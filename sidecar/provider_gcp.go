package sidecar

import (
	"encoding/json"
	"github.com/gorilla/mux"
	vault "github.com/hashicorp/vault/api"
	"net/http"
	"time"
)

// GCPCredentials are the credentials served by the API
type GCPCredentials struct {
	AccessToken  string `json:"access_token"`
	ExpiresInSec int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// GCPProviderConfig provides methods that allow the sidecar to retrieve and
// serve GCP credentials from vault for the given configuration
type GCPProviderConfig struct {
	GcpPath    string
	GcpRoleSet string
}

// credentialsPath returns the path to serve the credentials on
func (gpc *GCPProviderConfig) credentialsPath() string {
	// https://github.com/googleapis/google-cloud-go/blob/master/compute/metadata/metadata.go#L299
	// https://github.com/golang/oauth2/blob/master/google/google.go#L175
	return "/computeMetadata/v1/instance/service-accounts/{service_account}/token"
}

// credentials retrieves credentials from vault for the secret indicated in
// the configuration
func (gpc *GCPProviderConfig) credentials(client *vault.Client) (interface{}, time.Duration, error) {
	// Get a credentials secret from vault for the role
	secret, err := client.Logical().ReadWithData(gpc.secretPath(), gpc.secretData())
	if err != nil {
		return nil, -1, err
	}

	// Convert the secret's TTL into a time.Duration
	tokenTTL, err := (secret.Data["token_ttl"].(json.Number)).Int64()
	if err != nil {
		return nil, -1, err
	}
	leaseDuration := time.Duration(tokenTTL) * time.Second

	// Calculate expiry time
	expiresAtSeconds, err := (secret.Data["expires_at_seconds"].(json.Number)).Int64()
	if err != nil {
		return nil, -1, err
	}
	log.Info("new gcp credentials", "expiration", time.Unix(expiresAtSeconds, 0).Format("2006-01-02 15:04:05"))

	return &GCPCredentials{
		AccessToken:  secret.Data["token"].(string),
		ExpiresInSec: int(tokenTTL),
		TokenType:    "Bearer",
	}, leaseDuration, nil
}

// secretData returns data to pass to vault when retrieving the GCP roleset
// secret
func (gpc *GCPProviderConfig) secretData() map[string][]string {
	return nil
}

// secretPath is the path in vault to retrieve the GCP roleset from
func (gpc *GCPProviderConfig) secretPath() string {
	return gpc.GcpPath + "/token/" + gpc.GcpRoleSet
}

// setupAdditionalEndpoints adds an additional endpoint required to masuqerade
// as the GCE metdata service
func (gpc *GCPProviderConfig) setupAdditionalEndpoints(r *mux.Router) {
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
