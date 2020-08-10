package sidecar

import (
	vault "github.com/hashicorp/vault/api"
	"io/ioutil"
	"math/rand"
	"time"
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
}

// start the renewer
func (cr *credentialsRenewer) start() {
	// Create Vault client
	client, err := vault.NewClient(cr.vaultConfig)
	if err != nil {
		cr.errors <- err
		return
	}

	for {
		// Reload vault configuration from the environment
		if err := cr.vaultConfig.ReadEnvironment(); err != nil {
			cr.errors <- err
			return
		}

		// Login into Vault via kube SA
		jwt, err := ioutil.ReadFile(cr.tokenPath)
		if err != nil {
			cr.errors <- err
			return
		}
		secret, err := client.Logical().Write("auth/"+cr.kubePath+"/login", map[string]interface{}{
			"jwt":  string(jwt),
			"role": cr.kubeRole,
		})
		if err != nil {
			cr.errors <- err
			return
		}
		client.SetToken(secret.Auth.ClientToken)

		creds, duration, err := cr.providerConfig.credentials(client)
		if err != nil {
			cr.errors <- err
			return
		}
		cr.credentials <- creds

		// Used to generate random values for sleeping between renewals
		random := rand.New(rand.NewSource(int64(time.Now().Nanosecond())))

		// Sleep until its time to renew the creds
		time.Sleep(sleepDuration(duration, random))
	}
}
