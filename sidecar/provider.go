package sidecar

import (
	"net/http"
	"time"

	"github.com/gorilla/mux"
	vault "github.com/hashicorp/vault/api"
)

// ProviderConfig provides generic methods for retrieving and serving
// credentials from vault for a cloud provider
type ProviderConfig interface {
	ready() bool
	renew(client *vault.Client) (time.Duration, error)
	setupEndpoints(r *mux.Router)
}

// providerError is an error that can be returned as a http response
type providerError interface {
	write(http.ResponseWriter, string, int) error
}

// httpError writes the given message and code to the response in the form of
// the providerError. It also logs the error.
func httpError(w http.ResponseWriter, r *http.Request, msg string, code int, e providerError) {
	log.Error(nil, msg, "url", r.URL)
	w.WriteHeader(code)
	if err := e.write(w, msg, code); err != nil {
		log.Error(err, "Error writing error to response")
	}
}

// httpErrorText wraps http.Error with logging
func httpErrorText(w http.ResponseWriter, r *http.Request, msg string, code int) {
	log.Error(nil, msg, "url", r.URL)
	http.Error(w, msg, code)
}
