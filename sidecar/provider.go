package sidecar

import (
	"github.com/gorilla/mux"
	vault "github.com/hashicorp/vault/api"
	"time"
)

// ProviderConfig provides generic methods for retrieving and serving
// credentials from vault for a cloud provider
type ProviderConfig interface {
	ready() bool
	renew(client *vault.Client) (time.Duration, error)
	setupEndpoints(r *mux.Router)
}
