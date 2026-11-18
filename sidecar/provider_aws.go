package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	vault "github.com/hashicorp/vault/api"
)

// AWSCredentials are the credentials served by the API
type AWSCredentials struct {
	AccessKeyID     string    `json:"AccessKeyId"`
	SecretAccessKey string    `json:"SecretAccessKey"`
	Token           string    `json:"Token"`
	Expiration      time.Time `json:"Expiration"`
}

// awsError is the expected format for errors returned by the credentials
// endpoint
type awsError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// write populates the error fields and writes itself to the http response. The
// code is converted from the form returned by http.StatusText ("Not Found")
// into the form expected in the response ("NotFound")
func (e *awsError) write(w http.ResponseWriter, msg string, code int) error {
	e.Code = strings.ReplaceAll(http.StatusText(code), " ", "")
	e.Message = msg

	w.Header().Set("Content-Type", "application/json")

	return json.NewEncoder(w).Encode(e)
}

const (
	failedRoleRetryInterval = 3 * time.Minute
	minRoleRenewInterval    = time.Second
)

var awsProfileNameInvalidChars = regexp.MustCompile(`[^a-zA-Z0-9_+=.@-]`)

// AWSProviderConfig provides methods that allow the sidecar to retrieve and
// serve AWS credentials from vault for the given configuration
type AWSProviderConfig struct {
	Path    string
	RoleArn string
	Role    string

	CredentialsDir string

	mu          sync.RWMutex
	creds       *AWSCredentials
	roleCreds   map[string]*AWSCredentials
	roleRenewAt map[string]time.Time
	knownArns   []string
	profiles    []string
}

type awsCredentialProcessFile struct {
	Version         int    `json:"Version"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration"`
}

// renew retrieves credentials from vault for the secret indicated in
// the configuration
func (apc *AWSProviderConfig) renew(ctx context.Context, client *vault.Client) (time.Duration, error) {
	roleArns, err := apc.roleArns(ctx, client)
	if err != nil {
		return -1, err
	}

	if len(roleArns) < 2 {
		creds, leaseDuration, err := apc.readCredentials(ctx, client, apc.RoleArn)
		if err != nil {
			return -1, err
		}

		var roleCreds map[string]*AWSCredentials
		if len(roleArns) == 1 {
			roleCreds = map[string]*AWSCredentials{roleArns[0]: creds}
		}

		apc.mu.Lock()
		apc.creds = creds
		apc.roleCreds = roleCreds
		apc.mu.Unlock()

		apc.publishCredentials(roleArns, roleCreds)

		return leaseDuration, nil
	}

	now := time.Now()

	apc.mu.RLock()
	previousCreds := apc.roleCreds
	previousRenewAt := apc.roleRenewAt
	apc.mu.RUnlock()

	creds := make(map[string]*AWSCredentials, len(roleArns))
	renewAt := make(map[string]time.Time, len(roleArns))

	var (
		firstErr      error
		leaseDuration time.Duration
		haveCreds     bool
	)

	for i, roleArn := range roleArns {
		if at := previousRenewAt[roleArn]; now.Before(at) {
			creds[roleArn] = previousCreds[roleArn]
			renewAt[roleArn] = at
		} else if c, d, err := apc.readCredentials(ctx, client, roleArn); err != nil {
			log.Error(err, "error renewing aws credentials for role arn", "role_arn", roleArn)
			promErrors.Inc()
			renewAt[roleArn] = now.Add(failedRoleRetryInterval)

			if previous := previousCreds[roleArn]; previous != nil && previous.Expiration.After(now) {
				creds[roleArn] = previous
			}

			if i == 0 {
				firstErr = err
			}
		} else {
			creds[roleArn] = c
			renewAt[roleArn] = now.Add(d / 4)
		}

		if c := creds[roleArn]; c != nil {
			if d := c.Expiration.Sub(now); !haveCreds || d < leaseDuration {
				leaseDuration, haveCreds = d, true
			}
		}
	}

	if leaseDuration < minRoleRenewInterval {
		leaseDuration = minRoleRenewInterval
	}

	apc.mu.Lock()
	apc.creds = creds[roleArns[0]]
	apc.roleCreds = creds
	apc.roleRenewAt = renewAt
	apc.mu.Unlock()

	apc.publishCredentials(roleArns, creds)

	return leaseDuration, firstErr
}

func (apc *AWSProviderConfig) invalidate() {
	apc.mu.Lock()
	apc.roleRenewAt = nil
	apc.mu.Unlock()
}

func (apc *AWSProviderConfig) publishCredentials(roleArns []string, creds map[string]*AWSCredentials) {
	if apc.CredentialsDir == "" || len(roleArns) == 0 {
		return
	}

	if err := apc.writeCredentialFiles(roleArns, creds); err != nil {
		log.Error(err, "error writing aws credential files", "dir", apc.CredentialsDir)
		promErrors.Inc()
	}
}

func (apc *AWSProviderConfig) writeCredentialFiles(roleArns []string, creds map[string]*AWSCredentials) error {
	names := awsProfileNames(roleArns)

	current := make([]string, 0, len(roleArns))
	defaultProfile := ""
	for i, roleArn := range roleArns {
		c := creds[roleArn]
		if c == nil {
			continue
		}

		name := names[roleArn]
		if err := writeCredentialFile(filepath.Join(apc.CredentialsDir, name+".json"), c); err != nil {
			return err
		}

		if i == 0 {
			defaultProfile = name
		}

		current = append(current, name)
	}

	sort.Strings(current)

	config := awsCredentialsConfig(apc.CredentialsDir, defaultProfile, current)
	if err := writeFileAtomically(filepath.Join(apc.CredentialsDir, "config"), config, tokenFileMode); err != nil {
		return err
	}

	apc.mu.RLock()
	previous := apc.profiles
	apc.mu.RUnlock()

	for _, name := range previous {
		if slices.Contains(current, name) {
			continue
		}

		if err := os.Remove(filepath.Join(apc.CredentialsDir, name+".json")); err != nil && !os.IsNotExist(err) {
			return err
		}
	}

	apc.mu.Lock()
	apc.profiles = current
	apc.mu.Unlock()

	return nil
}

func writeCredentialFile(path string, creds *AWSCredentials) error {
	data, err := json.Marshal(awsCredentialProcessFile{
		Version:         1,
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.Token,
		Expiration:      creds.Expiration.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}

	return writeFileAtomically(path, data, tokenFileMode)
}

func awsCredentialsConfig(dir, defaultProfile string, profiles []string) []byte {
	sections := make([]string, 0, len(profiles)+1)
	if defaultProfile != "" {
		sections = append(sections, fmt.Sprintf("[profile default]\ncredential_process = cat %s\n", filepath.Join(dir, defaultProfile+".json")))
	}
	for _, name := range profiles {
		sections = append(sections, fmt.Sprintf("[profile %s]\ncredential_process = cat %s\n", name, filepath.Join(dir, name+".json")))
	}

	return []byte(strings.Join(sections, "\n"))
}

func awsProfileNames(roleArns []string) map[string]string {
	counts := make(map[string]int, len(roleArns))
	for _, roleArn := range roleArns {
		name, _ := awsRoleProfile(roleArn)
		counts[name]++
	}

	names := make(map[string]string, len(roleArns))
	used := make(map[string]struct{}, len(roleArns))

	for i, roleArn := range roleArns {
		base, account := awsRoleProfile(roleArn)

		name := base
		if counts[base] > 1 || base == "default" {
			name = fmt.Sprintf("%d-%s", i, base)
			if account != "" {
				name = account + "-" + base
			}
		}

		for n := i; ; n++ {
			if _, ok := used[name]; !ok {
				break
			}
			name = fmt.Sprintf("%d-%s", n, base)
		}

		used[name] = struct{}{}
		names[roleArn] = name
	}

	return names
}

func awsRoleProfile(roleArn string) (name, account string) {
	parts := strings.Split(roleArn, ":")
	if len(parts) == 6 && parts[0] == "arn" && parts[2] == "iam" && strings.HasPrefix(parts[5], "role/") {
		name = strings.TrimPrefix(parts[5], "role/")
		if i := strings.LastIndex(name, "/"); i >= 0 {
			name = name[i+1:]
		}
		if name = sanitiseProfileName(name); name != "" {
			return name, parts[4]
		}
	}

	return sanitiseProfileName(roleArn), ""
}

func sanitiseProfileName(name string) string {
	return awsProfileNameInvalidChars.ReplaceAllString(name, "-")
}

func (apc *AWSProviderConfig) roleArns(ctx context.Context, client *vault.Client) ([]string, error) {
	if apc.RoleArn != "" {
		return []string{apc.RoleArn}, nil
	}

	roleArns, err := apc.readRoleArns(ctx, client)
	if err == nil && len(roleArns) > 0 {
		apc.mu.Lock()
		apc.knownArns = roleArns
		apc.mu.Unlock()

		return roleArns, nil
	}

	apc.mu.RLock()
	knownArns := apc.knownArns
	apc.mu.RUnlock()

	switch {
	case len(knownArns) > 0 && err != nil:
		log.Info("error reading role arns from vault, using the last role arns read successfully", "role", apc.Role, "error", err.Error())
	case len(knownArns) > 0:
		log.Info("no role arns found in vault, using the last role arns read successfully", "role", apc.Role)
	case err != nil && !vaultPermissionDenied(err):
		return nil, err
	case err != nil:
		log.Info("error reading role arns from vault, falling back to a single set of credentials", "role", apc.Role, "error", err.Error())
	default:
		log.Info("no role arns found in vault, falling back to a single set of credentials", "role", apc.Role)
	}

	return knownArns, nil
}

func vaultPermissionDenied(err error) bool {
	var responseErr *vault.ResponseError

	return errors.As(err, &responseErr) && responseErr.StatusCode == http.StatusForbidden
}

func (apc *AWSProviderConfig) readRoleArns(ctx context.Context, client *vault.Client) ([]string, error) {
	secret, err := client.Logical().ReadWithContext(ctx, apc.Path+"/roles/"+apc.Role)
	if err != nil || secret == nil {
		return nil, err
	}

	raw, ok := secret.Data["role_arns"].([]interface{})
	if !ok {
		if secret.Data["role_arns"] == nil {
			return nil, nil
		}

		return nil, fmt.Errorf("role_arns returned for %s/roles/%s is %T, not a list", apc.Path, apc.Role, secret.Data["role_arns"])
	}

	roleArns := make([]string, len(raw))
	for i, v := range raw {
		s, ok := v.(string)
		if !ok || s == "" {
			return nil, fmt.Errorf("role_arns entry %d returned for %s/roles/%s is not a non-empty string: %v", i, apc.Path, apc.Role, v)
		}

		roleArns[i] = s
	}

	return roleArns, nil
}

func (apc *AWSProviderConfig) readCredentials(ctx context.Context, client *vault.Client, roleArn string) (*AWSCredentials, time.Duration, error) {
	// Get a credentials secret from vault for the role
	var secretData map[string][]string
	if roleArn != "" {
		secretData = map[string][]string{
			"role_arn": []string{roleArn},
		}
	}
	secret, err := client.Logical().ReadWithDataWithContext(ctx, apc.Path+"/sts/"+apc.Role, secretData)
	if err != nil {
		return nil, -1, err
	}
	if secret == nil {
		return nil, -1, errors.New("secret returned by vault client is nil")
	}

	// Convert the secret's lease duration into a time.Duration
	leaseDuration := time.Duration(secret.LeaseDuration) * time.Second

	// Get the expiration date of the lease from vault. This uses the
	// parsed-secret call rather than a raw response: the raw helpers cancel the
	// request context before returning, so reading the body afterwards races
	// with that cancellation and intermittently fails with "context canceled".
	lookup, err := client.Logical().WriteWithContext(ctx, "sys/leases/lookup", map[string]interface{}{
		"lease_id": secret.LeaseID,
	})
	if err != nil {
		return nil, -1, err
	}
	if lookup == nil {
		return nil, -1, errors.New("lease lookup returned nil secret")
	}
	rawExpireTime, ok := lookup.Data["expire_time"].(string)
	if !ok {
		return nil, -1, errors.New("lease lookup response has no expire_time")
	}
	expireTime, err := time.Parse(time.RFC3339Nano, rawExpireTime)
	if err != nil {
		return nil, -1, err
	}

	log.Info("new aws credentials", "access_key", secret.Data["access_key"].(string), "expiration", expireTime.Format("2006-01-02 15:04:05"), "role_arn", roleArn)

	return &AWSCredentials{
		AccessKeyID:     secret.Data["access_key"].(string),
		SecretAccessKey: secret.Data["secret_key"].(string),
		Token:           secret.Data["security_token"].(string),
		Expiration:      expireTime,
	}, leaseDuration, nil
}

// setupEndpoints adds a handler that serves the credentials at /credentials
func (apc *AWSProviderConfig) setupEndpoints(r *mux.Router) {
	r.HandleFunc("/credentials", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)

		apc.mu.RLock()
		creds := apc.creds
		apc.mu.RUnlock()

		if creds == nil {
			httpError(w, "Credentials not initialized", http.StatusNotFound, &awsError{})
			return
		}
		if err := enc.Encode(creds); err != nil {
			httpError(w, "Error encoding credentials response as json", http.StatusInternalServerError, &awsError{})
			return
		}
	})
}
