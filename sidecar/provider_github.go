package sidecar

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gorilla/mux"
	vault "github.com/hashicorp/vault/api"
)

// GitHubProviderConfig provides methods that allow the sidecar to retrieve a
// GitHub token from vault-plugin-secrets-github for the configured permission
// set, and make it available to the workload as a file
type GitHubProviderConfig struct {
	Path                     string
	PermissionSet            string
	TokenFileDestinationPath string
}

// tokenPath is the vault path of the configured permission set's token.
func (gh *GitHubProviderConfig) tokenPath() string {
	return gh.Path + "/token/" + gh.PermissionSet
}

// renew retrieves a token from vault for the configured permission set and
// writes it to TokenFileDestinationPath
func (gh *GitHubProviderConfig) renew(ctx context.Context, client *vault.Client) (time.Duration, error) {
	secret, err := client.Logical().ReadWithContext(ctx, gh.tokenPath())
	if err != nil {
		return -1, fmt.Errorf("unable to read github token: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return -1, fmt.Errorf("no data returned for %s", gh.tokenPath())
	}

	token, ok := secret.Data["token"].(string)
	if !ok {
		return -1, fmt.Errorf("no string 'token' field returned for %s", gh.tokenPath())
	}

	// The plugin sets the lease duration from the token's expires_at. Without a
	// lease the sidecar would not sleep between renewals and would create a new
	// installation token on every iteration.
	leaseDuration := time.Duration(secret.LeaseDuration) * time.Second
	if leaseDuration <= 0 {
		return -1, fmt.Errorf("no lease duration returned for %s", gh.tokenPath())
	}

	if err := writeFileAtomically(gh.TokenFileDestinationPath, []byte(token)); err != nil {
		return -1, fmt.Errorf("unable to save github token file: %w", err)
	}

	log.Info("new github token",
		"permission_set", gh.PermissionSet,
		"expiration", time.Now().Add(leaseDuration).Format("2006-01-02 15:04:05"),
	)

	return leaseDuration, nil
}

// setupEndpoints is a no-op: unlike AWS/GCP, the github token is served to
// the workload as a file rather than over the loopback HTTP endpoint, since
// GitHub tooling (git, curl, gh) expects a token value/file, not an
// SDK-polled metadata endpoint.
func (gh *GitHubProviderConfig) setupEndpoints(r *mux.Router) {}

// writeFileAtomically writes data to a temporary file in the same directory
// as path and renames it into place, so a concurrent reader of path never
// observes a partially-written token. The destination is created with 0600
// permissions, which the caller relies on for a secret.
func writeFileAtomically(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once the rename below succeeds

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
