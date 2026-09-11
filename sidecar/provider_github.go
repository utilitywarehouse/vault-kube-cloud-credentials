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

// renew retrieves a token from vault for the configured permission set and
// writes it to TokenFileDestinationPath
func (gh *GitHubProviderConfig) renew(ctx context.Context, client *vault.Client) (time.Duration, error) {
	secret, err := client.Logical().ReadWithContext(ctx, gh.Path+"/token/"+gh.PermissionSet)
	if err != nil {
		return -1, fmt.Errorf("unable to read github token: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return -1, fmt.Errorf("no data returned for %s/token/%s", gh.Path, gh.PermissionSet)
	}

	token, ok := secret.Data["token"].(string)
	if !ok {
		return -1, fmt.Errorf("token is not a string")
	}

	if err := writeFileAtomically(gh.TokenFileDestinationPath, []byte(token), 0600); err != nil {
		return -1, fmt.Errorf("unable to save github token file: %w", err)
	}

	leaseDuration := time.Duration(secret.LeaseDuration) * time.Second

	log.Info("new github token",
		"permission_set", gh.PermissionSet,
		"lease_duration", leaseDuration,
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
// observes a partially-written token.
func writeFileAtomically(path string, data []byte, perm os.FileMode) error {
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
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
