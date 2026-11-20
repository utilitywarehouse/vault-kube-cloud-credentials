package sidecar

import (
	"context"
	"fmt"
	"net"
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

func TestRunDisableHTTP(t *testing.T) {
	t.Cleanup(func() {
		credentialsReady.Store(false)
	})

	f := &awsFakeVault{
		roleArns: []string{primaryArn},
		ttl:      map[string]time.Duration{},
		fail:     map[string]bool{},
		stsCalls: map[string]int{},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/kubernetes/login" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"auth": {"client_token": "test-token", "lease_duration": 3600, "renewable": true}}`)
			return
		}

		f.handle(w, r)
	}))
	defer ts.Close()

	t.Setenv("VAULT_ADDR", ts.URL)
	t.Setenv("VAULT_CACERT", "")
	t.Setenv("VAULT_CAPATH", "")
	t.Setenv("VAULT_CAURL", "")

	dir := t.TempDir()
	saTokenFile := filepath.Join(dir, "service-account-token")
	if err := os.WriteFile(saTokenFile, []byte("a-service-account-token"), 0o600); err != nil {
		t.Fatalf("writing %s: %v", saTokenFile, err)
	}

	listenAddr := freeAddress(t)
	opsAddr := freeAddress(t)

	s, err := New(&Config{
		ProviderConfig: &AWSProviderConfig{
			Path:           "aws",
			Role:           "test-role",
			CredentialsDir: dir,
		},
		KubeAuthPath:  "kubernetes",
		KubeAuthRole:  "prod_aws_ns_sa",
		ListenAddress: listenAddr,
		OpsAddress:    opsAddr,
		TokenPath:     saTokenFile,
		DisableHTTP:   true,
	})
	if err != nil {
		t.Fatalf("New() = %v, want nil error", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := http.Get("http://" + opsAddr + "/__/ready")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}

		if time.Now().After(deadline) {
			t.Fatal("ops readiness did not become ready")
		}

		time.Sleep(50 * time.Millisecond)
	}

	if conn, err := net.DialTimeout("tcp", listenAddr, time.Second); err == nil {
		conn.Close()
		t.Errorf("something is listening on the provider address %s", listenAddr)
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

func freeAddress(t *testing.T) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding a free port: %v", err)
	}
	defer l.Close()

	return l.Addr().String()
}

func TestInvalidateProvider(t *testing.T) {
	apc := &AWSProviderConfig{
		roleStates: map[string]awsRoleState{
			primaryArn: {renewAt: time.Now().Add(time.Hour), retryPending: true},
		},
	}

	s := &Sidecar{Config: &Config{ProviderConfig: apc}}
	s.invalidateProvider()

	if state := apc.roleStates[primaryArn]; !state.renewAt.IsZero() || state.retryPending {
		t.Errorf("invalidateProvider did not invalidate the aws role state: %+v", state)
	}

	s = &Sidecar{Config: &Config{ProviderConfig: &GitHubProviderConfig{}}}
	s.invalidateProvider()
}

func TestNextRetry(t *testing.T) {
	apc := &AWSProviderConfig{
		roleStates: map[string]awsRoleState{
			primaryArn: {renewAt: time.Now().Add(time.Minute), retryPending: true},
		},
	}

	s := &Sidecar{Config: &Config{ProviderConfig: apc}}
	if d := s.nextRetry(); d < 59*time.Second || d > time.Minute {
		t.Errorf("nextRetry = %v, want about a minute", d)
	}

	s = &Sidecar{Config: &Config{ProviderConfig: &GitHubProviderConfig{}}}
	if d := s.nextRetry(); d != 0 {
		t.Errorf("nextRetry for a provider without retries = %v, want 0", d)
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
