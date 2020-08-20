package sidecar

import (
	"io/ioutil"
	"log"
	"math/rand"
	"time"

	"github.com/cenkalti/backoff"
	vault "github.com/hashicorp/vault/api"
)

// credentialsRenewer renews the credentials
type credentialsRenewer struct {
	credentials    chan<- interface{}
	errors         chan<- error
	kubePath       string
	kubeRole       string
	providerConfig ProviderConfig
	tokenPath      string
	vaultConfig    *vault.Config
	vaultClient    *vault.Client
}

// start the renewer
func (cr *credentialsRenewer) start() {
	// Create Vault client
	client, err := vault.NewClient(cr.vaultConfig)
	if err != nil {
		cr.errors <- err
		return
	}
	cr.vaultClient = client

	b := backoff.NewExponentialBackOff()
	b.RandomizationFactor = 0.2
	b.Multiplier = 2
	b.InitialInterval = 2 * time.Second
	b.MaxElapsedTime = 0

	for {
		var (
			creds    interface{}
			duration time.Duration
			err      error
		)

		err = backoff.RetryNotify(
			func() error {
				creds, duration, err = cr.renew()

				return err
			},
			b,
			func(err error, t time.Duration) {
				log.Printf("error: %s, backoff: %v", err, t)
			},
		)
		if err != nil {
			cr.errors <- err
			return
		}

		// Feed the credentials through the channel
		cr.credentials <- creds

		// Used to generate random values for sleeping between renewals
		random := rand.New(rand.NewSource(int64(time.Now().Nanosecond())))

		// Sleep until its time to renew the creds
		time.Sleep(sleepDuration(duration, random))
	}
}

// renew the credentials
func (cr *credentialsRenewer) renew() (interface{}, time.Duration, error) {
	// Reload vault configuration from the environment
	if err := cr.vaultConfig.ReadEnvironment(); err != nil {
		return nil, -1, err
	}

	// Login to Vault via kube SA
	jwt, err := ioutil.ReadFile(cr.tokenPath)
	if err != nil {
		return nil, -1, err
	}
	secret, err := cr.vaultClient.Logical().Write("auth/"+cr.kubePath+"/login", map[string]interface{}{
		"jwt":  string(jwt),
		"role": cr.kubeRole,
	})
	if err != nil {
		return nil, -1, err
	}
	cr.vaultClient.SetToken(secret.Auth.ClientToken)

	// Retrieve credentials for the provider
	return cr.providerConfig.credentials(cr.vaultClient)
}
