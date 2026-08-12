package sidecar

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	vault "github.com/hashicorp/vault/api"
)

// newVaultClient returns a vault API client pointed at the given test server.
func newVaultClient(t *testing.T, ts *httptest.Server) *vault.Client {
	t.Helper()
	cfg := vault.DefaultConfig()
	cfg.Address = ts.URL
	client, err := vault.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

// vaultHandler serves responses mimicking the real vault-plugin-secrets-gcp
// behaviors:
//   - a missing account on the plain read returns 404 (which vault/api maps to
//     nil, nil)
//   - a missing account on the token read returns 400 with an error (which
//     vault/api surfaces as an error)
func vaultHandler(t *testing.T, impersonatedExists bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/gcp/impersonated-account/test":
			if !impersonatedExists {
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprint(w, `{"errors":["impersonated account \"test\" does not exists"]}`)
				return
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"data":{"service_account_email":"imp@test.iam.gserviceaccount.com","service_account_project":"test","token_scopes":["https://www.googleapis.com/auth/cloud-platform"],"ttl":3600}}`)
		case "/v1/gcp/impersonated-account/test/token":
			if !impersonatedExists {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"errors":["impersonated account \"test\" does not exists"]}`)
				return
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"data":{"token":"impersonated-token","token_ttl":3600,"expires_at_seconds":0}}`)
		case "/v1/gcp/static-account/test":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"data":{"service_account_email":"static@test.iam.gserviceaccount.com","service_account_project":"test","token_scopes":["https://www.googleapis.com/auth/cloud-platform"]}}`)
		case "/v1/gcp/static-account/test/token":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"data":{"token":"static-token","token_ttl":3600,"expires_at_seconds":0}}`)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func TestReadAccountSecretPrefersImpersonatedWhenPresent(t *testing.T) {
	ts := httptest.NewServer(vaultHandler(t, true))
	defer ts.Close()
	client := newVaultClient(t, ts)

	gpc := &GCPProviderConfig{Path: "gcp", StaticAccount: "test"}

	secret, err := gpc.readAccountSecret(context.Background(), client, "/token")
	if err != nil {
		t.Fatalf("readAccountSecret: %v", err)
	}
	if got := secret.Data["token"]; got != "impersonated-token" {
		t.Errorf("token = %v, want impersonated-token", got)
	}
}

func TestReadAccountSecretFallsBackToStaticWhenImpersonatedMissing(t *testing.T) {
	ts := httptest.NewServer(vaultHandler(t, false))
	defer ts.Close()
	client := newVaultClient(t, ts)

	gpc := &GCPProviderConfig{Path: "gcp", StaticAccount: "test"}

	secret, err := gpc.readAccountSecret(context.Background(), client, "/token")
	if err != nil {
		t.Fatalf("readAccountSecret: %v", err)
	}
	if got := secret.Data["token"]; got != "static-token" {
		t.Errorf("token = %v, want static-token", got)
	}
}

func TestReadAccountSecretMetadataUsesCorrectPrefix(t *testing.T) {
	ts := httptest.NewServer(vaultHandler(t, true))
	defer ts.Close()
	client := newVaultClient(t, ts)

	gpc := &GCPProviderConfig{Path: "gcp", StaticAccount: "test"}

	secret, err := gpc.readAccountSecret(context.Background(), client, "")
	if err != nil {
		t.Fatalf("readAccountSecret: %v", err)
	}
	if got := secret.Data["service_account_email"]; got != "imp@test.iam.gserviceaccount.com" {
		t.Errorf("service_account_email = %v, want imp@test.iam.gserviceaccount.com", got)
	}
}
