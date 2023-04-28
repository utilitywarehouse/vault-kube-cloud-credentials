package sidecar

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	vault "github.com/hashicorp/vault/api"
)

// GCPCredentials are the credentials served by the API
type GCPCredentials struct {
	AccessToken  string `json:"access_token"`
	ExpiresInSec int    `json:"expires_in"`
	TokenType    string `json:"token_type"`

	// expiresAt is the time that the credentials expire. The duration until
	// this time is inserted into ExpiresInSec when marshalling into JSON.
	expiresAt time.Time
}

// gcpError is the format of errors returned by the GCE metadata endpoint when
// the response is expected to be JSON
type gcpError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// write populates the error fields and writes itself to the http response. The
// code is converted from the form returned by http.StatusText ("Not Found")
// into the form expected in the response ("not_found")
func (e *gcpError) write(w http.ResponseWriter, msg string, code int) error {
	e.Error = strings.ReplaceAll(strings.ToLower(http.StatusText(code)), " ", "_")
	e.ErrorDescription = msg

	w.Header().Set("Content-Type", "application/json")

	return json.NewEncoder(w).Encode(e)
}

// MarshalJSON overrides the value of ExpiresInSec with the duration until
// expiresAt
func (gc *GCPCredentials) MarshalJSON() ([]byte, error) {
	type Alias GCPCredentials
	return json.Marshal(&struct {
		ExpiresInSec int `json:"expires_in"`
		*Alias
	}{
		ExpiresInSec: int(time.Until(gc.expiresAt).Seconds()),
		Alias:        (*Alias)(gc),
	})
}

// gceMetadata is information that is used to masquerade as the GCE metadata server
type gceMetadata struct {
	project string
	email   string
	scopes  []string
}

// gceServiceAccountDetails are returned by calls to computeMetadata/v1/instance/service-accounts/
type gceServiceAccountDetails struct {
	Aliases []string `json:"aliases"`
	Email   string   `json:"email"`
	Scopes  []string `json:"scopes"`
}

// GCPProviderConfig provides methods that allow the sidecar to retrieve and
// serve GCP credentials from vault for the given configuration
type GCPProviderConfig struct {
	Path    string
	RoleSet string

	creds    *GCPCredentials
	metadata *gceMetadata
}

// renew retrieves credentials from vault for the secret indicated in
// the configuration
func (gpc *GCPProviderConfig) renew(client *vault.Client) (time.Duration, error) {
	// Get a credentials secret from vault for the role
	secret, err := client.Logical().Read(gpc.Path + "/roleset/" + gpc.RoleSet + "/token")
	if err != nil {
		return -1, err
	}

	// Convert the secret's TTL into a time.Duration
	tokenTTL, err := (secret.Data["token_ttl"].(json.Number)).Int64()
	if err != nil {
		return -1, err
	}
	leaseDuration := time.Duration(tokenTTL) * time.Second

	// Calculate expiry time
	expiresAtSeconds, err := (secret.Data["expires_at_seconds"].(json.Number)).Int64()
	if err != nil {
		return -1, err
	}

	if err := gpc.updateMetadata(client); err != nil {
		return -1, err
	}

	expiresAt := time.Unix(expiresAtSeconds, 0)

	log.Info("new gcp credentials",
		"expiration", expiresAt.Format("2006-01-02 15:04:05"),
		"project", gpc.metadata.project,
		"service_account_email", gpc.metadata.email,
		"scopes", gpc.metadata.scopes,
	)

	gpc.creds = &GCPCredentials{
		AccessToken: secret.Data["token"].(string),
		TokenType:   "Bearer",
		expiresAt:   expiresAt,
	}

	return leaseDuration, nil
}

// updateMetadata extracts metadata from the roleset in vault
func (gpc *GCPProviderConfig) updateMetadata(client *vault.Client) error {
	roleset, err := client.Logical().Read(gpc.Path + "/roleset/" + gpc.RoleSet)
	if err != nil {
		return err
	}

	var scopes []string
	tokenScopes, ok := roleset.Data["token_scopes"].([]interface{})
	if !ok {
		return fmt.Errorf("token_scopes is not a []interface{}")
	}
	for _, ts := range tokenScopes {
		scope, ok := ts.(string)
		if !ok {
			return fmt.Errorf("scope is not a string")
		}
		scopes = append(scopes, scope)
	}

	project, ok := roleset.Data["project"].(string)
	if !ok {
		return fmt.Errorf("project is not a string")
	}

	email, ok := roleset.Data["service_account_email"].(string)
	if !ok {
		return fmt.Errorf("service_account_email is not a string")
	}

	gpc.metadata = &gceMetadata{
		email:   email,
		project: project,
		scopes:  scopes,
	}

	return nil
}

// setupEndpoints adds the endpoints required to masquerade
// as the GCE metdata service
func (gpc *GCPProviderConfig) setupEndpoints(r *mux.Router) {
	r.HandleFunc("/computeMetadata/v1/instance/service-accounts/{service_account}/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if gpc.creds == nil {
			httpError(w, "Credentials not initialized", http.StatusNotFound, &gcpError{})
			return
		}
		if err := json.NewEncoder(w).Encode(gpc.creds); err != nil {
			httpError(w, "Error encoding credentials response as json", http.StatusInternalServerError, &gcpError{})
			return
		}
	})
	r.HandleFunc("/computeMetadata/v1/project/project-id", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/text")
		if gpc.metadata == nil {
			http.Error(w, "Metadata not initialized", http.StatusNotFound)
			return
		}
		w.Write([]byte(gpc.metadata.project))
	})
	r.HandleFunc("/computeMetadata/v1/project/numeric-project-id", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/text")
		if gpc.metadata == nil {
			http.Error(w, "Metadata not initialized", http.StatusNotFound)
			return
		}
		w.Write([]byte(`000000000000`))
	})
	r.HandleFunc("/computeMetadata/v1/instance/service-accounts", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+r.Host+r.URL.Path+"/", http.StatusMovedPermanently)
	})
	r.HandleFunc("/computeMetadata/v1/instance/service-accounts/", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Can't parse query arguments", http.StatusInternalServerError)
			return
		}
		if v := r.Form["recursive"]; len(v) != 1 || v[0] != "true" {
			w.Header().Set("Content-Type", "application/text")
			if gpc.metadata == nil {
				http.Error(w, "Metadata not initialized", http.StatusNotFound)
				return
			}
			w.Write([]byte("default/\n" + gpc.metadata.email + "/\n"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if gpc.metadata == nil {
			httpError(w, "Metadata not initialized", http.StatusNotFound, &gcpError{})
			return
		}
		if err := json.NewEncoder(w).Encode(map[string]*gceServiceAccountDetails{
			"default": &gceServiceAccountDetails{
				Aliases: []string{
					"default",
				},
				Email:  gpc.metadata.email,
				Scopes: gpc.metadata.scopes,
			},
			gpc.metadata.email: &gceServiceAccountDetails{
				Aliases: []string{
					"default",
				},
				Email:  gpc.metadata.email,
				Scopes: gpc.metadata.scopes,
			},
		}); err != nil {
			httpError(w, "Error encoding service accounts request as json", http.StatusNotFound, &gcpError{})
			return
		}
	})
	r.HandleFunc("/computeMetadata/v1/instance/service-accounts/{service_account}/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/text")
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Can't parse query arguments", http.StatusInternalServerError)
			return
		}
		if v := r.Form["recursive"]; len(v) != 1 || v[0] != "true" {
			w.Write([]byte("aliases\nemail\nidentity\nscopes\ntoken\n"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if gpc.metadata == nil {
			httpError(w, "Metadata not initialized", http.StatusNotFound, &gcpError{})
			return
		}
		if err := json.NewEncoder(w).Encode(&gceServiceAccountDetails{
			Aliases: []string{
				"default",
			},
			Email:  gpc.metadata.email,
			Scopes: gpc.metadata.scopes,
		}); err != nil {
			httpError(w, "Error encoding service account request as json", http.StatusNotFound, &gcpError{})
			return
		}
	})
	r.HandleFunc("/computeMetadata/v1/instance/service-accounts/{service_account}/aliases", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/text")
		w.Write([]byte(`default`))
	})
	r.HandleFunc("/computeMetadata/v1/instance/service-accounts/{service_account}/email", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/text")
		if gpc.metadata == nil {
			http.Error(w, "Metadata not initialized", http.StatusNotFound)
			return
		}
		w.Write([]byte(gpc.metadata.email))
	})
	r.HandleFunc("/computeMetadata/v1/instance/service-accounts/{service_account}/scopes", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/text")
		if gpc.metadata == nil {
			http.Error(w, "Metadata not initialized", http.StatusNotFound)
			return
		}
		w.Write([]byte(strings.Join(gpc.metadata.scopes, "\n")))
	})
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Metadata-Flavor", "Google")
		w.Header().Set("Content-Type", "application/text")
		w.Write([]byte(`ok`))
	})
}
