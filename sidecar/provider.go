package sidecar

import (
	"github.com/gorilla/mux"
	vault "github.com/hashicorp/vault/api"
	"time"
)

// ProviderConfig provides generic methods for retrieving and serving
// credentials from vault for a cloud provider
type ProviderConfig interface {
	CredentialsPath() string
	GetCredentials(client *vault.Client) (interface{}, time.Duration, error)
	SecretData() map[string][]string
	SecretPath() string
	SetupAdditionalEndpoints(r *mux.Router)
}
