package sidecar

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// TestReloginRenewsCredentials checks that replacing the login token renews the
// credentials immediately: vault revokes the leases created by the previous token,
// so the credentials they minted must not be served until the next scheduled
// renewal.
func TestReloginRenewsCredentials(t *testing.T) {
	var logins, tokenReads atomic.Int64

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/kubernetes/login":
			// Not renewable, so every iteration replaces the login token.
			logins.Add(1)
			fmt.Fprintf(w, `{"auth": {"client_token": "login-%d", "lease_duration": 1, "renewable": false}}`, logins.Load())
		case "/v1/github/token/uw_ro":
			reads := tokenReads.Add(1)
			// A long lease, so only a replaced login token can force a second read.
			fmt.Fprintf(w, `{"data": {"token": "ghs_%d"}, "lease_duration": 3600}`, reads)
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
			t.Errorf("unexpected request to %s", r.URL.Path)
		}
	}))
	defer ts.Close()

	t.Setenv("VAULT_ADDR", ts.URL)
	t.Setenv("VAULT_CACERT", "")
	t.Setenv("VAULT_CAPATH", "")
	t.Setenv("VAULT_CAURL", "")

	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	saTokenFile := filepath.Join(dir, "service-account-token")
	if err := os.WriteFile(saTokenFile, []byte("a-service-account-token"), 0o600); err != nil {
		t.Fatalf("writing %s: %v", saTokenFile, err)
	}

	s, err := New(&Config{
		ProviderConfig: &GitHubProviderConfig{
			Path:                     "github",
			PermissionSet:            "uw_ro",
			TokenFileDestinationPath: tokenFile,
		},
		KubeAuthPath:  "kubernetes",
		KubeAuthRole:  "k8s_github_uw_ro",
		ListenAddress: "127.0.0.1:0",
		OpsAddress:    "127.0.0.1:0",
		TokenPath:     saTokenFile,
	})
	if err != nil {
		t.Fatalf("New() = %v, want nil error", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	// The credentials only renew on the login token being replaced: the 1h lease
	// they were served with has not elapsed.
	if err := waitForContents(tokenFile, "ghs_2", 10*time.Second); err != nil {
		t.Error(err)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run() = %v, want nil error", err)
		}
	case <-time.After(10 * time.Second):
		t.Error("Run() did not return after its context was cancelled")
	}
}

// waitForContents polls path until it holds want, or timeout elapses.
func waitForContents(path, want string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if got, err := os.ReadFile(path); err == nil && string(got) == want {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}

	got, _ := os.ReadFile(path)
	return fmt.Errorf("token file = %q, want %q within %s", got, want, timeout)
}
