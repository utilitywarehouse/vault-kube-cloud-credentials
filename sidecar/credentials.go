package sidecar

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"time"

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

	// Random is used for the backoff and the interval between renewal
	// attempts
	rand.Seed(int64(time.Now().Nanosecond()))

	b := &Backoff{
		Jitter: true,
		Min:    2 * time.Second,
		Max:    1 * time.Minute,
	}

	for {
		creds, duration, err := cr.renew()
		if err != nil {
			d := b.Duration()
			log.Error(err, "error renewing credentials", "backoff", d)
			time.Sleep(d)
			continue
		}
		b.Reset()

		// Feed the credentials through the channel
		cr.credentials <- creds

		// Sleep until its time to renew the creds
		time.Sleep(sleepDuration(duration))
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
	loginPath := "auth/" + cr.kubePath + "/login"
	secret, err := cr.vaultClient.Logical().Write(loginPath, map[string]interface{}{
		"jwt":  string(jwt),
		"role": cr.kubeRole,
	})
	if err != nil {
		return nil, -1, err
	}
	if secret.Auth == nil {
		return nil, -1, fmt.Errorf("no authentication information attached to the response from %s", loginPath)
	}
	cr.vaultClient.SetToken(secret.Auth.ClientToken)

	// Retrieve credentials for the provider
	return cr.providerConfig.credentials(cr.vaultClient)
}
