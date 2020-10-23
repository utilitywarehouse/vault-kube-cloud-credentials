package sidecar

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	vault "github.com/hashicorp/vault/api"
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

	creds *AWSCredentials
}

// renew retrieves credentials from vault for the secret indicated in
// the configuration
func (apc *AWSProviderConfig) renew(client *vault.Client) (time.Duration, error) {
	// Get a credentials secret from vault for the role
	var secretData map[string][]string
	if apc.AwsRoleArn != "" {
		secretData = map[string][]string{
			"role_arn": []string{apc.AwsRoleArn},
		}
	}
	secret, err := client.Logical().ReadWithData(apc.AwsPath+"/sts/"+apc.AwsRole, secretData)
	if err != nil {
		return -1, err
	}

	// Convert the secret's lease duration into a time.Duration
	leaseDuration := time.Duration(secret.LeaseDuration) * time.Second

	// Get the expiration date of the lease from vault
	l := lease{}
	req := client.NewRequest("PUT", "/v1/sys/leases/lookup")
	if err = req.SetJSONBody(map[string]interface{}{
		"lease_id": secret.LeaseID,
	}); err != nil {
		return -1, err
	}
	resp, err := client.RawRequest(req)
	if err != nil {
		return -1, err
	}
	err = json.NewDecoder(resp.Body).Decode(&l)
	io.Copy(ioutil.Discard, resp.Body)
	resp.Body.Close()
	if err != nil {
		return -1, err
	}

	log.Info("new aws credentials", "access_key", secret.Data["access_key"].(string), "expiration", l.Data.ExpireTime.Format("2006-01-02 15:04:05"))

	apc.creds = &AWSCredentials{
		AccessKeyID:     secret.Data["access_key"].(string),
		SecretAccessKey: secret.Data["secret_key"].(string),
		Token:           secret.Data["security_token"].(string),
		Expiration:      l.Data.ExpireTime,
	}

	return leaseDuration, nil
}

// setupEndpoints adds a handler that serves the credentials at /credentials
func (apc *AWSProviderConfig) setupEndpoints(r *mux.Router) {
	r.HandleFunc("/credentials", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.Encode(apc.creds)
	})
}

// ready indicates whether the provider is in a suitable state to serve
// credentials
func (apc *AWSProviderConfig) ready() bool {
	if apc.creds != nil {
		return true
	}

	return false
}

// lease represents the part of the response from /v1/sys/leases/lookup we care about (the expire time)
type lease struct {
	Data struct {
		ExpireTime time.Time `json:"expire_time"`
	} `json:"data"`
}
