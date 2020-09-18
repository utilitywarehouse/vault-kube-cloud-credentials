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
}

// metadata is information that is used to masquerade as the GCE metadata server
type metadata struct {
	project string
	email   string
	scopes  []string
}

// serviceAccountDetails are returned by calls to computeMetadata/v1/instance/service-accounts/
type serviceAccountDetails struct {
	Aliases []string `json:"aliases"`
	Email   string   `json:"email"`
	Scopes  []string `json:"scopes"`
}

// GCPProviderConfig provides methods that allow the sidecar to retrieve and
// serve GCP credentials from vault for the given configuration
type GCPProviderConfig struct {
	GcpPath    string
	GcpRoleSet string

	metadata *metadata
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

	if err := gpc.updateMetadata(client); err != nil {
		return nil, -1, err
	}

	log.Info("new gcp credentials",
		"expiration", time.Unix(expiresAtSeconds, 0).Format("2006-01-02 15:04:05"),
		"project", gpc.metadata.project,
		"service_account_email", gpc.metadata.email,
		"scopes", gpc.metadata.scopes,
	)

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

// updateMetadata extracts metadata from the roleset in vault
func (gpc *GCPProviderConfig) updateMetadata(client *vault.Client) error {
	roleset, err := client.Logical().Read(gpc.GcpPath + "/roleset/" + gpc.GcpRoleSet)
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

	gpc.metadata = &metadata{
		email:   email,
		project: project,
		scopes:  scopes,
	}

	return nil
}

// setupAdditionalEndpoints adds the additional endpoints required to masquerade
// as the GCE metdata service
func (gpc *GCPProviderConfig) setupAdditionalEndpoints(r *mux.Router) {
	r.HandleFunc("/computeMetadata/v1/project/project-id", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/text")
		w.Write([]byte(gpc.metadata.project))
	})
	r.HandleFunc("/computeMetadata/v1/project/numeric-project-id", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/text")
		w.Write([]byte(`000000000000`))
	})
	r.HandleFunc("/computeMetadata/v1/instance/service-accounts", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+r.Host+r.URL.Path+"/", http.StatusMovedPermanently)
	})
	r.HandleFunc("/computeMetadata/v1/instance/service-accounts/", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if v := r.Form["recursive"]; len(v) != 1 || v[0] != "true" {
			w.Header().Set("Content-Type", "application/text")
			w.Write([]byte("default/\n" + gpc.metadata.email + "/\n"))
			return
		}
		data, err := json.Marshal(map[string]*serviceAccountDetails{
			"default": &serviceAccountDetails{
				Aliases: []string{
					"default",
				},
				Email:  gpc.metadata.email,
				Scopes: gpc.metadata.scopes,
			},
			gpc.metadata.email: &serviceAccountDetails{
				Aliases: []string{
					"default",
				},
				Email:  gpc.metadata.email,
				Scopes: gpc.metadata.scopes,
			},
		})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/text")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	})
	r.HandleFunc("/computeMetadata/v1/instance/service-accounts/{service_account}/", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if v := r.Form["recursive"]; len(v) != 1 || v[0] != "true" {
			w.Header().Set("Content-Type", "application/text")
			w.Write([]byte("aliases\nemail\nidentity\nscopes\ntoken\n"))
			return
		}
		data, err := json.Marshal(&serviceAccountDetails{
			Aliases: []string{
				"default",
			},
			Email:  gpc.metadata.email,
			Scopes: gpc.metadata.scopes,
		})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/text")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	})
	r.HandleFunc("/computeMetadata/v1/instance/service-accounts/{service_account}/aliases", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/text")
		w.Write([]byte(`default`))
	})
	r.HandleFunc("/computeMetadata/v1/instance/service-accounts/{service_account}/email", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/text")
		w.Write([]byte(gpc.metadata.email))
	})
	r.HandleFunc("/computeMetadata/v1/instance/service-accounts/{service_account}/scopes", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/text")
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
