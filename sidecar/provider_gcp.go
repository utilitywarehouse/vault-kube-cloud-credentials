package sidecar

import (
	"encoding/json"
	"github.com/gorilla/mux"
	vault "github.com/hashicorp/vault/api"
	"log"
	"net/http"
	"time"
)

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
	return "/computeMetadata/v1/instance/service-accounts/{service_account}/token"
}

func (gpc *GCPProviderConfig) GetCredentials(client *vault.Client) (interface{}, time.Duration, error) {
	// Get a credentials secret from vault for the role
	secret, err := client.Logical().ReadWithData(gpc.SecretPath(), gpc.SecretData())
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

func (gpc *GCPProviderConfig) SecretData() map[string][]string {
	return nil
}

func (gpc *GCPProviderConfig) SecretPath() string {
	return gpc.GcpPath + "/token/" + gpc.GcpRoleSet
}

func (apc *GCPProviderConfig) SetupAdditionalEndpoints(r *mux.Router) {
	r.HandleFunc("/computeMetadata/v1/instance/service-accounts/{service_account}/", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if v := r.Form["recursive"]; len(v) != 1 || v[0] != "true" {
			w.WriteHeader(http.StatusNotImplemented)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"aliases":["default"],"email":"default","scopes":[]}`))
	})
}
