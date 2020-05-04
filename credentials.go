package main

import (
	"encoding/json"
	"io"
	"io/ioutil"
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
	Credentials chan<- *AWSCredentials
	Errors      chan<- error
	AwsPath     string
	AwsRole     string
	KubePath    string
	KubeRole    string
	TokenPath   string
	VaultConfig *vault.Config
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

		// Get a credentials secret from vault for the role
		secret, err = client.Logical().Read(cr.AwsPath + "/sts/" + cr.AwsRole)
		if err != nil {
			cr.Errors <- err
			return
		}

		// Convert the secret's lease duration into a time.Duration
		leaseDuration := time.Duration(secret.LeaseDuration) * time.Second

		// Get the expiration date of the lease from vault
		l := lease{}
		req := client.NewRequest("PUT", "/v1/sys/leases/lookup")
		if err = req.SetJSONBody(map[string]interface{}{
			"lease_id": secret.LeaseID,
		}); err != nil {
			cr.Errors <- err
			return
		}
		resp, err := client.RawRequest(req)
		if err != nil {
			cr.Errors <- err
			return
		}
		err = json.NewDecoder(resp.Body).Decode(&l)
		io.Copy(ioutil.Discard, resp.Body)
		resp.Body.Close()
		if err != nil {
			cr.Errors <- err
			return
		}

		log.Printf("new aws credentials: %s, expiring %s", secret.Data["access_key"].(string), l.Data.ExpireTime.Format("2006-01-02 15:04:05"))

		// Send the new credentials down the channel
		cr.Credentials <- &AWSCredentials{
			AccessKeyID:     secret.Data["access_key"].(string),
			SecretAccessKey: secret.Data["secret_key"].(string),
			Token:           secret.Data["security_token"].(string),
			Expiration:      l.Data.ExpireTime,
		}
		// Used to generate random values for sleeping between renewals
		random := rand.New(rand.NewSource(int64(time.Now().Nanosecond())))

		// Sleep until its time to renew the creds
		time.Sleep(sleepDuration(leaseDuration, random))
	}
}
