package sidecar

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
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
	Path                   string
	StaticAccount          string
	SecretType             string
	KeyFileDestinationPath string

	creds    *GCPCredentials
	metadata *gceMetadata

	leaseID        string
	leaseDuration  time.Duration
	leaseExpiresAt time.Time
}

// renew retrieves credentials from vault for the secret indicated in
// the configuration
func (gpc *GCPProviderConfig) renew(client *vault.Client) (time.Duration, error) {
	switch gpc.SecretType {
	case "access_token":
		return gpc.renewToken(client)
	case "service_account_key":
		return gpc.renewKey(client)
	default:
		return -1, fmt.Errorf("wrong secret type")
	}
}

func (gpc *GCPProviderConfig) renewToken(client *vault.Client) (time.Duration, error) {
	// Get a credentials secret from vault for the static account
	secret, err := client.Logical().Read(gpc.Path + "/static-account/" + gpc.StaticAccount + "/token")
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

// GCP Key has some limitations https://developer.hashicorp.com/vault/docs/secrets/gcp#service-account-keys-quota-limits
// so instead of requesting new key when old key lease is expired we will keep
// renewing lease. so that only 1 key will be used for the lifecycle of the pod
// this also helps with the application which do not re-read keys.
func (gpc *GCPProviderConfig) renewKey(client *vault.Client) (time.Duration, error) {
	if gpc.leaseID == "" || time.Since(gpc.leaseExpiresAt) > 0 {
		return gpc.newKey(client)
	}

	secret, err := client.Sys().Renew(gpc.leaseID, int(gpc.leaseDuration.Seconds()))
	if err != nil {
		return -1, fmt.Errorf("unable to renew key lease err:%w", err)
	}

	gpc.leaseDuration = time.Duration(secret.LeaseDuration) * time.Second
	gpc.leaseExpiresAt = time.Now().Add(gpc.leaseDuration)

	log.Info("gcp key lease renewed",
		"lease_expiration", gpc.leaseExpiresAt.Format("2006-01-02 15:04:05"),
	)

	return gpc.leaseDuration, nil
}

func (gpc *GCPProviderConfig) newKey(client *vault.Client) (time.Duration, error) {
	// Get a credentials secret from vault for the static account
	secret, err := client.Logical().Read(gpc.Path + "/static-account/" + gpc.StaticAccount + "/key")
	if err != nil {
		return -1, err
	}

	// Extract privete key data from the secret returned by Vault
	privateKey := secret.Data["private_key_data"]
	privateKeyDecoded, err := base64.StdEncoding.DecodeString(privateKey.(string))
	if err != nil {
		log.Error(err, "Error decoding private key")
	}

	// Save the service account json key in a file
	err = os.WriteFile(gpc.KeyFileDestinationPath, []byte(privateKeyDecoded), 0600)
	if err != nil {
		log.Error(err, "Error saving google service account key file")
	}

	gpc.leaseDuration = time.Duration(secret.LeaseDuration) * time.Second
	gpc.leaseExpiresAt = time.Now().Add(gpc.leaseDuration)
	gpc.leaseID = secret.LeaseID

	var keyData map[string]interface{}
	err = json.Unmarshal(privateKeyDecoded, &keyData)
	if err != nil {
		return -1, err
	}

	log.Info("new gcp credentials",
		"lease_expiration", gpc.leaseExpiresAt.Format("2006-01-02 15:04:05"),
		"project", keyData["project_id"],
		"service_account_email", keyData["client_email"],
	)
	return gpc.leaseDuration, nil
}

// updateMetadata extracts metadata from the roleset in vault
func (gpc *GCPProviderConfig) updateMetadata(client *vault.Client) error {
	sa, err := client.Logical().Read(gpc.Path + "/static-account/" + gpc.StaticAccount)
	if err != nil {
		return err
	}

	project, ok := sa.Data["service_account_project"].(string)
	if !ok {
		return fmt.Errorf("project is not a string")
	}

	email, ok := sa.Data["service_account_email"].(string)
	if !ok {
		return fmt.Errorf("service_account_email is not a string")
	}

	gpc.metadata = &gceMetadata{
		email:   email,
		project: project,
	}

	return nil
}

// setupEndpoints adds the endpoints required to masquerade
// as the GCE metdata service
func (gpc *GCPProviderConfig) setupEndpoints(r *mux.Router) {
	if gpc.SecretType == "service_account_key" {
		return
	}

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
			"default": {
				Aliases: []string{
					"default",
				},
				Email:  gpc.metadata.email,
				Scopes: gpc.metadata.scopes,
			},
			gpc.metadata.email: {
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
