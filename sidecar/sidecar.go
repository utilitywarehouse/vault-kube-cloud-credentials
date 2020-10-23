package sidecar

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	vault "github.com/hashicorp/vault/api"
	"github.com/utilitywarehouse/go-operational/op"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	appName        = "vault-kube-cloud-credentials"
	appDescription = "Fetch cloud provider credentials from vault on behalf of a Kubernetes service account and serve them via HTTP."
)

var (
	log = ctrl.Log.WithName("sidecar")
)

// Config configures the sidecar
type Config struct {
	ProviderConfig ProviderConfig
	KubeAuthPath   string
	KubeAuthRole   string
	ListenAddress  string
	TokenPath      string
}

// Sidecar provides the basic functionality for retrieving credentials using the
// provided ProviderConfig
type Sidecar struct {
	*Config
	backoff     *Backoff
	vaultClient *vault.Client
	vaultConfig *vault.Config
}

// New returns a sidecar with the provided config
func New(config *Config) (*Sidecar, error) {
	vaultConfig := vault.DefaultConfig()
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
		Config:      config,
		backoff:     backoff,
		vaultConfig: vaultConfig,
		vaultClient: vaultClient,
	}, nil
}

// Run starts the sidecar. It retrieves credentials from vault and serves them
// for the configured cloud provider
func (s *Sidecar) Run() error {
	// Random is used for the backoff and the interval between renewal
	// attempts
	rand.Seed(int64(time.Now().Nanosecond()))

	go func() {
		for {
			duration, err := s.renew()
			if err != nil {
				d := s.backoff.Duration()
				log.Error(err, "error renewing credentials", "backoff", d)
				time.Sleep(d)
				continue
			}
			s.backoff.Reset()

			// Sleep until its time to renew the creds
			time.Sleep(sleepDuration(duration))
		}
	}()

	// Block until the provider is ready to serve credentials
	for {
		if s.ProviderConfig.ready() {
			break
		}
	}

	r := mux.NewRouter()

	// Add operational endpoints
	r.Handle("/__/", op.NewHandler(op.NewStatus(appName, appDescription).
		AddOwner("system", "#infra").
		AddLink("readme", fmt.Sprintf("https://github.com/utilitywarehouse/%s/blob/master/README.md", appName)).
		ReadyAlways()),
	)

	// Add provider-specific endpoints
	s.ProviderConfig.setupEndpoints(r)

	log.Info("webserver is listening", "address", s.ListenAddress)

	return http.ListenAndServe(s.ListenAddress, r)
}

// renew the credentials
func (s *Sidecar) renew() (time.Duration, error) {
	// Reload vault configuration from the environment
	if err := s.vaultConfig.ReadEnvironment(); err != nil {
		return -1, err
	}

	// Login to Vault via kube SA
	jwt, err := ioutil.ReadFile(s.TokenPath)
	if err != nil {
		return -1, err
	}
	loginPath := "auth/" + s.KubeAuthPath + "/login"
	secret, err := s.vaultClient.Logical().Write(loginPath, map[string]interface{}{
		"jwt":  string(jwt),
		"role": s.KubeAuthRole,
	})
	if err != nil {
		return -1, err
	}
	if secret == nil {
		return -1, fmt.Errorf("no secret returned by %s", loginPath)
	}
	if secret.Auth == nil {
		return -1, fmt.Errorf("no authentication information attached to the response from %s", loginPath)
	}
	s.vaultClient.SetToken(secret.Auth.ClientToken)

	// Retrieve credentials for the provider
	return s.ProviderConfig.renew(s.vaultClient)
}

// Sleep for 1/3 of the lease duration with a random jitter to discourage syncronised API calls from
// multiple instances of the application
func sleepDuration(leaseDuration time.Duration) time.Duration {
	return time.Duration((float64(leaseDuration.Nanoseconds()) * 1 / 3) * (rand.Float64() + 1.50) / 2)
}
