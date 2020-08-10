package sidecar

import (
	"encoding/json"
	"github.com/gorilla/mux"
	vault "github.com/hashicorp/vault/api"
	"io"
	"io/ioutil"
	"log"
	"time"
)

// AWSCredentials are the credentials served by the API
type AWSCredentials struct {
	AccessKeyID     string    `json:"AccessKeyId"`
	SecretAccessKey string    `json:"SecretAccessKey"`
	Token           string    `json:"Token"`
	Expiration      time.Time `json:"Expiration"`
}

// AWSProviderConfig provides methods that allow the sidecar to retrieve and
// serve AWS credentials from vault for the given configuration
type AWSProviderConfig struct {
	AwsPath    string
	AwsRoleArn string
	AwsRole    string
}

// CredentialsPath returns the path to serve the credentials on
func (apc *AWSProviderConfig) CredentialsPath() string {
	return "/credentials"
}

// GetCredentials retrieves credentials from vault for the secret indicated in
// the configuration
func (apc *AWSProviderConfig) GetCredentials(client *vault.Client) (interface{}, time.Duration, error) {
	// Get a credentials secret from vault for the role
	secret, err := client.Logical().ReadWithData(apc.SecretPath(), apc.SecretData())
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

// SecretData returns the data to pass to vault when retrieving the AWS role secret
func (apc *AWSProviderConfig) SecretData() map[string][]string {
	if apc.AwsRoleArn != "" {
		return map[string][]string{
			"role_arn": []string{apc.AwsRoleArn},
		}
	}
	return nil
}

// SecretPath is the path in vault to retrieve the AWS role from
func (apc *AWSProviderConfig) SecretPath() string {
	return apc.AwsPath + "/sts/" + apc.AwsRole
}

// SetupAdditionalEndpoints does nothing because there are no additional paths
// necessary to override the AWS metadata services
func (apc *AWSProviderConfig) SetupAdditionalEndpoints(r *mux.Router) {}

// lease represents the part of the response from /v1/sys/leases/lookup we care about (the expire time)
type lease struct {
	Data struct {
		ExpireTime time.Time `json:"expire_time"`
	} `json:"data"`
}
