package sidecar

import (
	vault "github.com/hashicorp/vault/api"
	"io/ioutil"
	"math/rand"
	"time"
)

// CredentialsRenewer renews the credentials
type CredentialsRenewer struct {
	Credentials    chan<- interface{}
	Errors         chan<- error
	KubePath       string
	KubeRole       string
	ProviderConfig ProviderConfig
	TokenPath      string
	VaultConfig    *vault.Config
}

// Start the renewer
func (cr *CredentialsRenewer) Start() {
	// Create Vault client
	client, err := vault.NewClient(cr.VaultConfig)
	if err != nil {
		cr.Errors <- err
		return
	}

	for {
		// Reload vault configuration from the environment
		if err := cr.VaultConfig.ReadEnvironment(); err != nil {
			cr.Errors <- err
			return
		}

		// Login into Vault via kube SA
		jwt, err := ioutil.ReadFile(cr.TokenPath)
		if err != nil {
			cr.Errors <- err
			return
		}
		secret, err := client.Logical().Write("auth/"+cr.KubePath+"/login", map[string]interface{}{
			"jwt":  string(jwt),
			"role": cr.KubeRole,
		})
		if err != nil {
			cr.Errors <- err
			return
		}
		client.SetToken(secret.Auth.ClientToken)

		creds, duration, err := cr.ProviderConfig.GetCredentials(client)
		if err != nil {
			cr.Errors <- err
			return
		}
		cr.Credentials <- creds

		// Used to generate random values for sleeping between renewals
		random := rand.New(rand.NewSource(int64(time.Now().Nanosecond())))

		// Sleep until its time to renew the creds
		time.Sleep(sleepDuration(duration, random))
	}
}
