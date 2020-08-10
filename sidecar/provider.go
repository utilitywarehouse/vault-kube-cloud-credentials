package sidecar

import (
	"github.com/gorilla/mux"
	vault "github.com/hashicorp/vault/api"
	"time"
)

// ProviderConfig provides generic methods for retrieving and serving
// credentials from vault for a cloud provider
type ProviderConfig interface {
	credentialsPath() string
	credentials(client *vault.Client) (interface{}, time.Duration, error)
	secretData() map[string][]string
	secretPath() string
	setupAdditionalEndpoints(r *mux.Router)
}
