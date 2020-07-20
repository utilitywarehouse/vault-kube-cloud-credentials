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

type ProviderConfig interface {
	CredentialsPath() string
	GetCredentials(client *vault.Client) (interface{}, time.Duration, error)
	SecretPath() string
}

// AWSCredentials are the credentials served by the API
type AWSCredentials struct {
	AccessKeyID     string    `json:"AccessKeyId"`
	SecretAccessKey string    `json:"SecretAccessKey"`
	Token           string    `json:"Token"`
	Expiration      time.Time `json:"Expiration"`
}

type AWSProviderConfig struct {
	AwsPath string
	AwsRole string
}

func (apc *AWSProviderConfig) CredentialsPath() string {
	return "/credentials"
}

func (apc *AWSProviderConfig) GetCredentials(client *vault.Client) (interface{}, time.Duration, error) {
	// Get a credentials secret from vault for the role
	secret, err := client.Logical().Read(apc.SecretPath())
	if err != nil {
		return nil, -1, err
	}

	// Convert the secret's lease duration into a time.Duration
	leaseDuration := time.Duration(secret.LeaseDuration) * time.Second

	// Get the expiration date of the lease from vault
	l := lease{}
	req := client.NewRequest("PUT", "/v1/sys/leases/lookup")
	if err = req.SetJSONBody(map[string]interface{}{
		"lease_id": secret.LeaseID,
	}); err != nil {
		return nil, -1, err
	}
	resp, err := client.RawRequest(req)
	if err != nil {
		return nil, -1, err
	}
	err = json.NewDecoder(resp.Body).Decode(&l)
	io.Copy(ioutil.Discard, resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, -1, err
	}

	log.Printf("new aws credentials: %s, expiring %s", secret.Data["access_key"].(string), l.Data.ExpireTime.Format("2006-01-02 15:04:05"))

	return &AWSCredentials{
		AccessKeyID:     secret.Data["access_key"].(string),
		SecretAccessKey: secret.Data["secret_key"].(string),
		Token:           secret.Data["security_token"].(string),
		Expiration:      l.Data.ExpireTime,
	}, leaseDuration, nil
}

func (apc *AWSProviderConfig) SecretPath() string {
	return apc.AwsPath + "/sts/" + apc.AwsRole
}

// GCPCredentials are the credentials served by the API
type GCPCredentials struct {
	AccessToken  string `json:"access_token"`
	ExpiresInSec int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

type GCPProviderConfig struct {
	GcpPath    string
	GcpRoleSet string
}

func (gpc *GCPProviderConfig) CredentialsPath() string {
	// https://github.com/googleapis/google-cloud-go/blob/master/compute/metadata/metadata.go#L299
	// https://github.com/golang/oauth2/blob/master/google/google.go#L175
	return "/computeMetadata/v1/instance/service-accounts/default/token"
}

func (gpc *GCPProviderConfig) GetCredentials(client *vault.Client) (interface{}, time.Duration, error) {
	// Get a credentials secret from vault for the role
	secret, err := client.Logical().Read(gpc.GcpPath + "/token/" + gpc.GcpRoleSet)
	if err != nil {
		return nil, -1, err
	}

	// Convert the secret's TTL into a time.Duration
	token_ttl, err := (secret.Data["token_ttl"].(json.Number)).Int64()
	if err != nil {
		return nil, -1, err
	}
	leaseDuration := time.Duration(token_ttl) * time.Second

	// Calculate expiry time
	expires_at_seconds, err := (secret.Data["expires_at_seconds"].(json.Number)).Int64()
	if err != nil {
		return nil, -1, err
	}
	log.Printf("new gcp credentials, expiring %s", time.Unix(expires_at_seconds, 0).Format("2006-01-02 15:04:05"))

	return &GCPCredentials{
		AccessToken:  secret.Data["token"].(string),
		ExpiresInSec: int(token_ttl),
		TokenType:    "Bearer",
	}, leaseDuration, nil
}

func (gpc *GCPProviderConfig) SecretPath() string {
	return gpc.GcpPath + "/token/" + gpc.GcpRoleSet
}

// lease represents the part of the response from /v1/sys/leases/lookup we care about (the expire time)
type lease struct {
	Data struct {
		ExpireTime time.Time `json:"expire_time"`
	} `json:"data"`
}

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
