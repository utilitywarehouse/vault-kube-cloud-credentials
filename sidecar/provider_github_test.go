package sidecar

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// githubVaultServer returns a test vault that answers a token read for the
// given permission set with the provided body.
func githubVaultServer(t *testing.T, permissionSet, body string) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if want := "/v1/github/token/" + permissionSet; r.URL.Path != want {
			t.Errorf("unexpected path: %s, want %s", r.URL.Path, want)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, body)
	}))
}

func newGitHubConfig(t *testing.T) (*GitHubProviderConfig, string) {
	t.Helper()

	tokenPath := filepath.Join(t.TempDir(), "token")

	return &GitHubProviderConfig{
		Path:                     "github",
		PermissionSet:            "uw_ro",
		TokenFileDestinationPath: tokenPath,
	}, tokenPath
}

func TestGitHubRenewWritesTokenFile(t *testing.T) {
	ts := githubVaultServer(t, "uw_ro", `{"data":{"token":"gh-token"},"lease_duration":3600}`)
	defer ts.Close()

	gh, tokenPath := newGitHubConfig(t)

	duration, err := gh.renew(context.Background(), newVaultClient(t, ts))
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if duration != time.Hour {
		t.Errorf("lease duration = %v, want %v", duration, time.Hour)
	}

	contents, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(contents) != "gh-token" {
		t.Errorf("token file = %q, want %q", contents, "gh-token")
	}

	info, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != tokenFileMode {
		t.Errorf("token file mode = %o, want %o", mode, tokenFileMode)
	}

	entries, err := os.ReadDir(filepath.Dir(tokenPath))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "token" {
		t.Errorf("directory contains %v, want only the token file", entries)
	}
}

func TestGitHubRenewReplacesExistingToken(t *testing.T) {
	gh, tokenPath := newGitHubConfig(t)

	if err := os.WriteFile(tokenPath, []byte("old-token"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ts := githubVaultServer(t, "uw_ro", `{"data":{"token":"new-token"},"lease_duration":3600}`)
	defer ts.Close()

	if _, err := gh.renew(context.Background(), newVaultClient(t, ts)); err != nil {
		t.Fatalf("renew: %v", err)
	}

	contents, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(contents) != "new-token" {
		t.Errorf("token file = %q, want %q", contents, "new-token")
	}
}

// A response without a usable token or lease must fail the renewal rather than
// leave the sidecar in a loop that creates a token per iteration.
func TestGitHubRenewRejectsUnusableResponse(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "no token data",
			body: `{"data":{}}`,
		},
		{
			name: "token is not a string",
			body: `{"data":{"token":123},"lease_duration":3600}`,
		},
		{
			name: "no lease duration",
			body: `{"data":{"token":"gh-token"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := githubVaultServer(t, "uw_ro", tt.body)
			defer ts.Close()

			gh, tokenPath := newGitHubConfig(t)

			if _, err := gh.renew(context.Background(), newVaultClient(t, ts)); err == nil {
				t.Error("renew did not return an error")
			}

			if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
				t.Errorf("token file written despite the error: %v", err)
			}
		})
	}
}

// A missing secrets engine or permission set is answered with a 404, which the
// vault client maps to a nil secret and no error.
func TestGitHubRenewRejectsMissingSecret(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"errors":[]}`)
	}))
	defer ts.Close()

	gh, tokenPath := newGitHubConfig(t)

	if _, err := gh.renew(context.Background(), newVaultClient(t, ts)); err == nil {
		t.Error("renew did not return an error for a nil secret")
	}

	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Errorf("token file written despite the error: %v", err)
	}
}

func TestWriteFileAtomicallyMissingDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "token")

	if err := writeFileAtomically(path, []byte("gh-token"), tokenFileMode); err == nil {
		t.Error("writeFileAtomically did not return an error for a missing directory")
	}
}
