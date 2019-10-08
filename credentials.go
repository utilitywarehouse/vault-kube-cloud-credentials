package main

import (
	"encoding/json"
	"log"
	"math/rand"
	"time"

	vault "github.com/hashicorp/vault/api"
)

// AWSCredentials are the credentials served by the API
type AWSCredentials struct {
	AccessKeyID     string    `json:"AccessKeyId"`
	SecretAccessKey string    `json:"SecretAccessKey"`
	Token           string    `json:"Token"`
	Expiration      time.Time `json:"Expiration"`
}

// lease represents the part of the response from /v1/sys/leases/lookup we care about (the expire time)
type lease struct {
	Data struct {
		ExpireTime time.Time `json:"expire_time"`
	} `json:"data"`
}

// CredentialsRenewer renews the credentials
type CredentialsRenewer struct {
	Client         *vault.Client
	Credentials    chan<- *AWSCredentials
	Errors         chan<- error
	Rand           *rand.Rand
	Role           string
	SecretsBackend string
}

// Start the renewer
func (cr *CredentialsRenewer) Start() {
	for {
		// A token is required to authenticate, this should be set by the login renewer
		if len(cr.Client.Token()) > 0 {
			l := lease{}

			// Get a credentials secret from vault for the role
			secret, err := cr.Client.Logical().Read(cr.SecretsBackend + "/sts/" + cr.Role)
			if err != nil {
				cr.Errors <- err
				return
			}

			// Convert the secret's lease duration into a time.Duration
			leaseDuration := time.Duration(secret.LeaseDuration) * time.Second

			// Get the expiration date of the lease from vault
			req := cr.Client.NewRequest("PUT", "/v1/sys/leases/lookup")
			if err = req.SetJSONBody(map[string]interface{}{
				"lease_id": secret.LeaseID,
			}); err != nil {
				cr.Errors <- err
				return
			}
			resp, err := cr.Client.RawRequest(req)
			if err == nil {
				defer resp.Body.Close()
			} else {
				cr.Errors <- err
				return
			}
			err = json.NewDecoder(resp.Body).Decode(&l)
			if err != nil {
				cr.Errors <- err
				return
			}

			log.Printf("credentials: %v", secret.Data["access_key"].(string))

			// Send the new credentials down the channel
			cr.Credentials <- &AWSCredentials{
				AccessKeyID:     secret.Data["access_key"].(string),
				SecretAccessKey: secret.Data["secret_key"].(string),
				Token:           secret.Data["security_token"].(string),
				Expiration:      l.Data.ExpireTime,
			}

			// Sleep until its time to renew the creds
			time.Sleep(sleepDuration(leaseDuration, cr.Rand))
		}
	}
}
