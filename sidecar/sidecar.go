package sidecar

import (
	"context"
	"crypto/tls"
	"io"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	rootcerts "github.com/hashicorp/go-rootcerts"
	vault "github.com/hashicorp/vault/api"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	ctrl "sigs.k8s.io/controller-runtime"
)

var log = ctrl.Log.WithName("sidecar")

// Config configures the sidecar
type Config struct {
	ProviderConfig ProviderConfig
	KubeAuthPath   string
	KubeAuthRole   string
	ListenAddress  string
	OpsAddress     string
	TokenPath      string
}

// Sidecar provides the basic functionality for retrieving credentials using the
// provided ProviderConfig
type Sidecar struct {
	*Config
	backoff        *Backoff
	vaultClient    *vault.Client
	vaultConfig    *vault.Config
	vaultTLSConfig *tls.Config
}

// New returns a sidecar with the provided config
func New(config *Config) (*Sidecar, error) {
	vaultConfig := vault.DefaultConfig()

	// Capture the TLS config of the Transport before it's wrapped and
	// therefore unavailable. This is updated by reloadVaultCA.
	vaultTLSConfig := vaultConfig.HttpClient.Transport.(*http.Transport).TLSClientConfig

	vaultConfig.HttpClient.Transport = promhttp.InstrumentRoundTripperInFlight(promVaultRequestsInFlight,
		promhttp.InstrumentRoundTripperCounter(promVaultRequests,
			promhttp.InstrumentRoundTripperDuration(promVaultRequestsDuration, vaultConfig.HttpClient.Transport),
		),
	)

	vaultClient, err := vault.NewClient(vaultConfig)
	if err != nil {
		return nil, err
	}

	backoff := &Backoff{
		Jitter: true,
		Min:    2 * time.Second,
		Max:    1 * time.Minute,
	}

	return &Sidecar{
		Config:         config,
		backoff:        backoff,
		vaultConfig:    vaultConfig,
		vaultClient:    vaultClient,
		vaultTLSConfig: vaultTLSConfig,
	}, nil
}

// Run starts the sidecar. It retrieves credentials from vault and serves them
// for the configured cloud provider
func (s *Sidecar) Run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	loggedIn := make(chan bool, 1)

	go s.manageLoginToken(ctx, loggedIn)

	<-loggedIn

	// Random is used for the backoff and the interval between renewal attempts
	rnd := rand.New(rand.NewSource(int64(time.Now().Nanosecond())))

	ready := make(chan bool, 1)

	go func() {
		firstRun := true
		for {
			duration, err := s.renew(ctx)
			if err != nil {
				promErrors.Inc()
				d := s.backoff.Duration()
				log.Error(err, "error renewing credentials", "backoff", d)
				time.Sleep(d)
				continue
			}
			s.backoff.Reset()

			promRenewals.Inc()
			promExpiry.Set(float64(time.Now().Add(duration).Unix()))

			if firstRun {
				ready <- true
				firstRun = false
			}

			// Sleep until its time to renew the creds
			time.Sleep(sleepDuration(duration, rnd))
		}
	}()

	errors := make(chan error)

	// Serve operational endpoints
	sr := mux.NewRouter()
	sr.PathPrefix("/__/").Handler(statusHandler)

	go func() {
		log.Info("operational status server is listening", "address", s.OpsAddress)
		errors <- http.ListenAndServe(s.OpsAddress, sr)
	}()

	// Serve provider endpoints
	r := mux.NewRouter()
	s.ProviderConfig.setupEndpoints(r)

	// Instrument the handler with logging and metrics
	ir := instrumentHandlerLogging(
		promhttp.InstrumentHandlerInFlight(promRequestsInFlight,
			promhttp.InstrumentHandlerDuration(promRequestsDuration,
				promhttp.InstrumentHandlerCounter(promRequests,
					promhttp.InstrumentHandlerResponseSize(promResponseSize,
						promhttp.InstrumentHandlerRequestSize(promRequestSize, r),
					),
				),
			),
		),
	)

	go func() {
		// Block until the provider has retrieved the first set of
		// credentials
		<-ready
		log.Info("webserver is listening", "address", s.ListenAddress)
		errors <- http.ListenAndServe(s.ListenAddress, ir)
	}()

	err := <-errors

	return err
}

// renew the credentials
func (s *Sidecar) renew(ctx context.Context) (time.Duration, error) {
	// Reload vault CA from the environment
	if err := s.reloadVaultCA(); err != nil {
		return -1, err
	}

	// Renew credentials for the provider
	return s.ProviderConfig.renew(s.vaultClient)
}

// reloadVaultCA updates the tls.Config used by the vault client with the CA
// cert(s) pointed to by VAULT_CACERT or VAULT_CAPATH. This makes the sidecar
// tolerant of CA renewals.
func (s *Sidecar) reloadVaultCA() error {
	var envCACert string
	var envCAPath string
	var envCACertBytes []byte

	if v := os.Getenv(vault.EnvVaultCACert); v != "" {
		envCACert = v
	}

	if v := os.Getenv(vault.EnvVaultCAPath); v != "" {
		envCAPath = v
	}

	if v := os.Getenv("VAULT_CAURL"); v != "" {
		resp, err := http.Get(v)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		envCACertBytes, err = io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
	}

	if envCACert != "" || envCAPath != "" || len(envCACertBytes) != 0 {
		err := rootcerts.ConfigureTLS(s.vaultTLSConfig, &rootcerts.Config{
			CAPath:        envCAPath,
			CAFile:        envCACert,
			CACertificate: envCACertBytes,
		})

		if err != nil {
			return err
		}
	}

	return nil
}

// responseLogger wraps a http.ResponseWriter, recording elements of the
// response for the purpose of logging
type responseLogger struct {
	http.ResponseWriter
	code int
}

// WriteHeader records the status code so that it can be logged
func (rl *responseLogger) WriteHeader(code int) {
	rl.code = code
	rl.ResponseWriter.WriteHeader(code)
}

// instrumentHandlerLogging wraps a http.Handler with logging
func instrumentHandlerLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			rl := &responseLogger{ResponseWriter: w}
			start := time.Now()
			next.ServeHTTP(rl, r)
			log.Info("served request", "path", r.URL.EscapedPath(), "code", rl.code, "method", r.Method, "duration", time.Since(start))
		},
	)
}

// Sleep for 1/3 of the lease duration with a random jitter to discourage synchronised API calls from
// multiple instances of the application
func sleepDuration(leaseDuration time.Duration, rnd *rand.Rand) time.Duration {
	return time.Duration((float64(leaseDuration.Nanoseconds()) * 1 / 3) * (rnd.Float64() + 1.50) / 2)
}
