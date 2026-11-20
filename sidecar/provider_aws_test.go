package sidecar

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	vault "github.com/hashicorp/vault/api"
)

// delayedLeaseLookupServer returns a fake vault that answers the STS read
// immediately and sends the lease lookup response headers before the body.
// Reading the lookup body after the call returns used to race with the client
// cancelling the request context, producing "context canceled" on renewal.
func delayedLeaseLookupServer(t *testing.T) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/v1/aws/roles/test-role":
			fmt.Fprint(w, `{"data":{}}`)
		case r.URL.Path == "/v1/aws/sts/test-role":
			fmt.Fprint(w, `{
				"lease_id": "aws/sts/test-role/lease-id",
				"lease_duration": 3600,
				"renewable": true,
				"data": {
					"access_key": "AKIATEST",
					"secret_key": "secret",
					"security_token": "token"
				}
			}`)
		case r.URL.Path == "/v1/sys/leases/lookup":
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			time.Sleep(25 * time.Millisecond)
			expire := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
			fmt.Fprintf(w, `{"data":{"expire_time":%q,"ttl":3599}}`, expire)
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestAWSRenewWithDelayedLeaseLookupBody(t *testing.T) {
	ts := delayedLeaseLookupServer(t)
	defer ts.Close()

	apc := &AWSProviderConfig{Path: "aws", Role: "test-role"}

	leaseDuration, err := apc.renew(context.Background(), awsTestClient(t, ts.URL))
	if err != nil {
		t.Fatalf("renew: %v", err)
	}

	if leaseDuration < 59*time.Minute || leaseDuration > time.Hour+time.Minute {
		t.Errorf("lease duration = %v, want about %v", leaseDuration, time.Hour)
	}

	if apc.creds == nil {
		t.Fatal("credentials were not stored")
	}
	if apc.creds.Expiration.Before(time.Now().Add(59 * time.Minute)) {
		t.Errorf("expiration = %v, want roughly an hour from now", apc.creds.Expiration)
	}
	if apc.creds.AccessKeyID != "AKIATEST" || apc.creds.SecretAccessKey != "secret" || apc.creds.Token != "token" {
		t.Errorf("unexpected credentials: %+v", apc.creds)
	}
}

const (
	primaryArn   = "arn:aws:iam::111111111111:role/primary"
	secondaryArn = "arn:aws:iam::111111111111:role/secondary"
)

func awsTestClient(t *testing.T, address string) *vault.Client {
	t.Helper()

	cfg := vault.DefaultConfig()
	cfg.Address = address
	cfg.MaxRetries = 0

	client, err := vault.NewClient(cfg)
	if err != nil {
		t.Fatalf("creating vault client: %v", err)
	}

	return client
}

type awsFakeVault struct {
	mu       sync.Mutex
	roleArns []string
	roleErr  int
	ttl      map[string]time.Duration
	fail     map[string]bool
	stsCalls map[string]int
}

func newAWSFakeVault(t *testing.T, roleArns ...string) (*awsFakeVault, *vault.Client) {
	t.Helper()

	f := &awsFakeVault{
		roleArns: roleArns,
		ttl:      map[string]time.Duration{},
		fail:     map[string]bool{},
		stsCalls: map[string]int{},
	}

	srv := httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(srv.Close)

	return f, awsTestClient(t, srv.URL)
}

func (f *awsFakeVault) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	roleArn := r.URL.Query().Get("role_arn")

	switch r.URL.Path {
	case "/v1/aws/roles/test-role":
		f.mu.Lock()
		defer f.mu.Unlock()

		if f.roleErr != 0 {
			w.WriteHeader(f.roleErr)
			fmt.Fprint(w, `{"errors":["boom"]}`)
			return
		}

		roleArns, err := json.Marshal(f.roleArns)
		if err != nil {
			panic(err)
		}

		fmt.Fprintf(w, `{"data":{"role_arns":%s}}`, roleArns)
	case "/v1/aws/sts/test-role":
		f.mu.Lock()
		f.stsCalls[roleArn]++
		failed := f.fail[roleArn]
		f.mu.Unlock()

		if failed {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"errors":["boom"]}`)
			return
		}

		fmt.Fprintf(w, `{"lease_id":%q,"lease_duration":3600,"data":{"access_key":"AK%s","secret_key":"secret","security_token":"token"}}`,
			roleArn, roleArn[strings.LastIndex(roleArn, "/")+1:])
	case "/v1/sys/leases/lookup":
		var req struct {
			LeaseID string `json:"lease_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			panic(err)
		}

		f.mu.Lock()
		ttl, ok := f.ttl[req.LeaseID]
		f.mu.Unlock()

		if !ok {
			ttl = time.Hour
		}

		fmt.Fprintf(w, `{"data":{"expire_time":%q}}`, time.Now().Add(ttl).UTC().Format(time.RFC3339Nano))
	default:
		http.NotFound(w, r)
	}
}

func (f *awsFakeVault) setRoleErr(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.roleErr = status
}

func (f *awsFakeVault) setTTL(roleArn string, ttl time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.ttl[roleArn] = ttl
}

func (f *awsFakeVault) setFailRole(roleArn string, fail bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.fail[roleArn] = fail
}

func (f *awsFakeVault) stsReads(roleArn string) int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.stsCalls[roleArn]
}

func (f *awsFakeVault) wantSTSCalls(t *testing.T, roleArn string, want int) {
	t.Helper()

	if got := f.stsReads(roleArn); got != want {
		t.Errorf("role %q read %d times, want %d", roleArn, got, want)
	}
}

func TestAWSReadRoleArns(t *testing.T) {
	tests := []struct {
		name    string
		data    map[string]interface{}
		want    []string
		wantErr bool
	}{
		{name: "no secret"},
		{name: "missing role_arns", data: map[string]interface{}{}},
		{name: "valid list", data: map[string]interface{}{"role_arns": []interface{}{primaryArn, secondaryArn}}, want: []string{primaryArn, secondaryArn}},
		{name: "not a list", data: map[string]interface{}{"role_arns": primaryArn}, wantErr: true},
		{name: "entry not a string", data: map[string]interface{}{"role_arns": []interface{}{primaryArn, 42}}, wantErr: true},
		{name: "entry is empty", data: map[string]interface{}{"role_arns": []interface{}{primaryArn, ""}}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")

				if tt.data == nil {
					w.WriteHeader(http.StatusNotFound)
				}

				_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": tt.data})
			}))
			defer srv.Close()

			apc := &AWSProviderConfig{Path: "aws", Role: "test-role"}

			got, err := apc.readRoleArns(context.Background(), awsTestClient(t, srv.URL))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got role arns %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("role arns = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAWSRenewRoleArnsReadOnFirstStart(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		wantErr   bool
		wantReads int
	}{
		{name: "failure", status: http.StatusInternalServerError, wantErr: true},
		{name: "denied", status: http.StatusForbidden, wantReads: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, client := newAWSFakeVault(t)
			f.setRoleErr(tt.status)

			apc := &AWSProviderConfig{Path: "aws", Role: "test-role"}

			duration, err := apc.renew(context.Background(), client)

			f.wantSTSCalls(t, "", tt.wantReads)

			apc.mu.RLock()
			creds, roleStates := apc.creds, apc.roleStates
			apc.mu.RUnlock()

			if tt.wantErr {
				if err == nil {
					t.Fatal("renew returned no error when the role arns read failed and none was ever read")
				}
				if duration != -1 {
					t.Errorf("renew duration = %v, want -1", duration)
				}
				if creds != nil || len(roleStates) != 0 {
					t.Errorf("credentials = %+v, role states = %+v, want none", creds, roleStates)
				}

				return
			}

			if err != nil {
				t.Fatalf("renew: %v", err)
			}
			if duration < 59*time.Minute || duration > time.Hour+time.Second {
				t.Errorf("renew duration = %v, want about %v", duration, time.Hour)
			}
			if creds == nil {
				t.Error("no credentials, want the single set read without a role_arn")
			}
			if len(roleStates) != 1 {
				t.Errorf("role states = %+v, want one default entry", roleStates)
			} else if state, ok := roleStates[""]; !ok || state.creds == nil {
				t.Errorf("role states = %+v, want credentials under the empty role arn", roleStates)
			}
		})
	}
}

func TestAWSRenewUsesKnownRoleArnsWhenReadFailsLater(t *testing.T) {
	f, client := newAWSFakeVault(t, primaryArn, secondaryArn)
	apc := &AWSProviderConfig{Path: "aws", Role: "test-role"}
	ctx := context.Background()

	if _, err := apc.renew(ctx, client); err != nil {
		t.Fatalf("first renew: %v", err)
	}

	f.setRoleErr(http.StatusInternalServerError)

	duration, err := apc.renew(ctx, client)
	if err != nil {
		t.Fatalf("renew while the role arns read fails after a successful read: %v", err)
	}
	if duration < 59*time.Minute || duration > time.Hour+time.Second {
		t.Errorf("renew duration = %v, want about an hour", duration)
	}

	f.wantSTSCalls(t, primaryArn, 1)
	f.wantSTSCalls(t, secondaryArn, 1)

	apc.mu.RLock()
	defer apc.mu.RUnlock()

	if apc.roleStates[primaryArn].creds == nil || apc.roleStates[secondaryArn].creds == nil {
		t.Errorf("role states = %v, want both known role arns served", apc.roleStates)
	}
}

func TestAWSRenewDefaultRoleFailureStillReadsSecondaries(t *testing.T) {
	f, client := newAWSFakeVault(t, primaryArn, secondaryArn)
	f.setFailRole(primaryArn, true)

	apc := &AWSProviderConfig{Path: "aws", Role: "test-role", CredentialsDir: t.TempDir()}

	duration, err := apc.renew(context.Background(), client)
	if err == nil {
		t.Fatal("renew succeeded, want the default role error")
	}
	if duration < 59*time.Minute || duration > time.Hour+time.Second {
		t.Errorf("renew duration = %v, want the secondary credential lifetime of about an hour", duration)
	}

	f.wantSTSCalls(t, primaryArn, 1)
	f.wantSTSCalls(t, secondaryArn, 1)

	apc.mu.RLock()
	primary, secondary := apc.roleStates[primaryArn].creds, apc.roleStates[secondaryArn].creds
	apc.mu.RUnlock()

	if apc.creds != nil {
		t.Errorf("default credentials = %+v, want nil", apc.creds)
	}
	if primary != nil {
		t.Errorf("credentials = %+v kept for a role that has never been read successfully", primary)
	}
	if secondary == nil || secondary.AccessKeyID != "AKsecondary" {
		t.Errorf("secondary role credentials = %+v, want the secondary role credentials", secondary)
	}

	config, err := os.ReadFile(filepath.Join(apc.CredentialsDir, "config"))
	if err != nil {
		t.Fatalf("reading published config: %v", err)
	}
	if !strings.Contains(string(config), "[profile secondary]") {
		t.Errorf("published config = %q, want a profile for the secondary role", config)
	}

	router := mux.NewRouter()
	apc.setupEndpoints(router)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/credentials", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("credentials endpoint status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestAWSRenewDefaultFailureDoesNotBecomeReady(t *testing.T) {
	f, client := newAWSFakeVault(t, primaryArn, secondaryArn)
	f.setFailRole(primaryArn, true)

	apc := &AWSProviderConfig{Path: "aws", Role: "test-role", CredentialsDir: t.TempDir()}
	ctx := context.Background()

	if _, err := apc.renew(ctx, client); err == nil {
		t.Fatal("first renew succeeded, want the default role error")
	}

	if _, err := apc.renew(ctx, client); err == nil {
		t.Fatal("second renew succeeded without default credentials")
	}
	f.wantSTSCalls(t, primaryArn, 2)

	apc.mu.RLock()
	if apc.creds != nil {
		t.Errorf("default credentials = %+v, want nil", apc.creds)
	}
	apc.mu.RUnlock()

	if retry := apc.nextRetry(); retry != 0 {
		t.Errorf("next retry = %v, want 0: the default role is paced by Run", retry)
	}

	f.setFailRole(primaryArn, false)

	if _, err := apc.renew(ctx, client); err != nil {
		t.Fatalf("renew after the default role recovered: %v", err)
	}

	apc.mu.RLock()
	creds := apc.creds
	apc.mu.RUnlock()

	if creds == nil {
		t.Fatal("no default credentials after the default role recovered")
	}
	if creds.AccessKeyID != "AKprimary" {
		t.Errorf("default access key = %q, want %q", creds.AccessKeyID, "AKprimary")
	}
	if retry := apc.nextRetry(); retry != 0 {
		t.Errorf("next retry = %v, want 0 after recovery", retry)
	}
}

func TestAWSRenewProfileFallbackWhenRoleArnsUnavailable(t *testing.T) {
	f, client := newAWSFakeVault(t)
	f.setRoleErr(http.StatusForbidden)

	dir := t.TempDir()
	apc := &AWSProviderConfig{Path: "aws", Role: "test-role", CredentialsDir: dir}

	leaseDuration, err := apc.renew(context.Background(), client)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if leaseDuration < 59*time.Minute || leaseDuration > time.Hour+time.Second {
		t.Errorf("renew duration = %v, want about an hour", leaseDuration)
	}

	wantConfig := fmt.Sprintf("[profile default]\ncredential_process = cat %s/default.json\n", dir)
	config, err := os.ReadFile(filepath.Join(dir, "config"))
	if err != nil {
		t.Fatalf("reading published config: %v", err)
	}
	if string(config) != wantConfig {
		t.Errorf("published config = %q, want %q", config, wantConfig)
	}

	data, err := os.ReadFile(filepath.Join(dir, "default.json"))
	if err != nil {
		t.Fatalf("reading default profile: %v", err)
	}
	var file awsCredentialProcessFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("decoding default profile: %v", err)
	}
	if file.Version != 1 || file.AccessKeyID != "AK" || file.SecretAccessKey != "secret" || file.SessionToken != "token" {
		t.Errorf("default profile = %+v", file)
	}
}

func TestAWSRenewProfileFallbackWriteFailure(t *testing.T) {
	f, client := newAWSFakeVault(t)
	f.setRoleErr(http.StatusForbidden)

	parent := t.TempDir()
	notDir := filepath.Join(parent, "not-a-dir")
	if err := os.WriteFile(notDir, []byte("file"), 0600); err != nil {
		t.Fatal(err)
	}

	apc := &AWSProviderConfig{Path: "aws", Role: "test-role", CredentialsDir: notDir}
	if _, err := apc.renew(context.Background(), client); err == nil {
		t.Fatal("renew succeeded, want a profile write error")
	}
}

func TestAWSRenewSingleRoleUsesRoleARN(t *testing.T) {
	f, client := newAWSFakeVault(t, primaryArn)
	apc := &AWSProviderConfig{Path: "aws", Role: "test-role"}

	if _, err := apc.renew(context.Background(), client); err != nil {
		t.Fatalf("renew: %v", err)
	}

	f.wantSTSCalls(t, primaryArn, 1)
	f.wantSTSCalls(t, "", 0)

	apc.mu.RLock()
	creds := apc.creds
	apc.mu.RUnlock()

	if creds == nil || creds.AccessKeyID != "AKprimary" {
		t.Errorf("credentials = %+v, want the primary role credentials", creds)
	}
}

func TestAWSRenewMultiRolePublishFailure(t *testing.T) {
	_, client := newAWSFakeVault(t, primaryArn, secondaryArn)

	parent := t.TempDir()
	notDir := filepath.Join(parent, "not-a-dir")
	if err := os.WriteFile(notDir, []byte("file"), 0600); err != nil {
		t.Fatal(err)
	}

	apc := &AWSProviderConfig{Path: "aws", Role: "test-role", CredentialsDir: notDir}
	if _, err := apc.renew(context.Background(), client); err == nil {
		t.Fatal("renew succeeded, want a profile write error")
	}
}

func TestAWSRenewSingleRolePublishFailure(t *testing.T) {
	f, client := newAWSFakeVault(t, primaryArn)

	parent := t.TempDir()
	notDir := filepath.Join(parent, "not-a-dir")
	if err := os.WriteFile(notDir, []byte("file"), 0600); err != nil {
		t.Fatal(err)
	}

	apc := &AWSProviderConfig{Path: "aws", Role: "test-role", CredentialsDir: notDir}
	if _, err := apc.renew(context.Background(), client); err == nil {
		t.Fatal("renew succeeded, want a profile write error")
	}
	f.wantSTSCalls(t, primaryArn, 1)
}

func TestAWSRenewSingleRoleClearsRetryState(t *testing.T) {
	f, client := newAWSFakeVault(t, primaryArn, secondaryArn)
	f.setFailRole(secondaryArn, true)

	apc := &AWSProviderConfig{Path: "aws", Role: "test-role"}
	if _, err := apc.renew(context.Background(), client); err != nil {
		t.Fatalf("renew with a failing secondary role: %v", err)
	}

	if retry := apc.nextRetry(); retry == 0 {
		t.Fatal("next retry = 0, want a retry for the failed secondary role")
	}

	// If vault later reports only one role, the retry timer for the removed
	// role must not keep waking the sidecar.
	f.mu.Lock()
	f.roleArns = []string{primaryArn}
	f.mu.Unlock()

	if _, err := apc.renew(context.Background(), client); err != nil {
		t.Fatalf("renew after switching to a single role: %v", err)
	}

	if retry := apc.nextRetry(); retry != 0 {
		t.Errorf("next retry after switching to a single role = %v, want 0", retry)
	}
}

func TestAWSRenewMultiRole(t *testing.T) {
	f, client := newAWSFakeVault(t, primaryArn, secondaryArn)
	apc := &AWSProviderConfig{Path: "aws", Role: "test-role"}
	ctx := context.Background()

	if _, err := apc.renew(ctx, client); err != nil {
		t.Fatalf("first renew: %v", err)
	}

	apc.mu.RLock()
	primaryRenewAt := apc.roleStates[primaryArn].renewAt
	apc.mu.RUnlock()

	if want := time.Now().Add(time.Hour / 4); primaryRenewAt.Before(want.Add(-time.Minute)) || primaryRenewAt.After(want.Add(time.Minute)) {
		t.Errorf("primary renew at = %v, want about a quarter of the lease ahead", primaryRenewAt)
	}

	if _, err := apc.renew(ctx, client); err != nil {
		t.Fatalf("second renew: %v", err)
	}
	f.wantSTSCalls(t, primaryArn, 1)
	f.wantSTSCalls(t, secondaryArn, 1)

	apc.invalidate()

	apc.mu.RLock()
	renewAt := 0
	for _, state := range apc.roleStates {
		if !state.renewAt.IsZero() || state.retryPending {
			renewAt++
		}
	}
	keptCreds := apc.roleStates[primaryArn].creds != nil && apc.roleStates[secondaryArn].creds != nil
	apc.mu.RUnlock()

	if renewAt != 0 {
		t.Errorf("role states with renewal timers after invalidate = %d, want 0", renewAt)
	}
	if !keptCreds {
		t.Error("invalidate dropped the cached role credentials")
	}

	f.setFailRole(secondaryArn, true)

	duration, err := apc.renew(ctx, client)
	if err != nil {
		t.Fatalf("renew with a failing secondary role: %v", err)
	}
	if duration < 59*time.Minute || duration > time.Hour+time.Second {
		t.Errorf("renew duration = %v, want the secondary credential lifetime of about an hour", duration)
	}
	f.wantSTSCalls(t, primaryArn, 2)
	f.wantSTSCalls(t, secondaryArn, 2)

	apc.mu.RLock()
	secondaryState := apc.roleStates[secondaryArn]
	apc.mu.RUnlock()

	if secondaryState.creds == nil || secondaryState.creds.AccessKeyID != "AKsecondary" {
		t.Errorf("secondary credentials = %+v, want the previous unexpired credentials", secondaryState.creds)
	}
	if !secondaryState.retryPending {
		t.Error("secondary role is not marked as failed")
	}
	if want := time.Now().Add(failedRoleRetryInterval); secondaryState.renewAt.Before(want.Add(-time.Second)) || secondaryState.renewAt.After(want.Add(time.Second)) {
		t.Errorf("secondary renew at = %v, want about %v ahead", secondaryState.renewAt, failedRoleRetryInterval)
	}

	if retry := apc.nextRetry(); retry < failedRoleRetryInterval-5*time.Second || retry > failedRoleRetryInterval {
		t.Errorf("next retry = %v, want about %v", retry, failedRoleRetryInterval)
	}

	if _, err := apc.renew(ctx, client); err != nil {
		t.Fatalf("renew before the secondary retry time: %v", err)
	}
	f.wantSTSCalls(t, secondaryArn, 2)

	apc.mu.RLock()
	secondaryAfterCache := apc.roleStates[secondaryArn]
	primaryAfterCache := apc.roleStates[primaryArn]
	apc.mu.RUnlock()

	if !secondaryAfterCache.renewAt.Equal(secondaryState.renewAt) {
		t.Error("the failed secondary role's retry time was not carried over")
	}
	if !secondaryAfterCache.retryPending {
		t.Error("the failed secondary role was not kept in the failed state")
	}
	if primaryAfterCache.retryPending {
		t.Error("the healthy primary role was marked as failed")
	}

	apc.mu.Lock()
	state := apc.roleStates[primaryArn]
	state.renewAt = time.Now().Add(-time.Second)
	apc.roleStates[primaryArn] = state
	apc.mu.Unlock()

	if _, err := apc.renew(ctx, client); err != nil {
		t.Fatalf("renew with only the primary role due: %v", err)
	}
	f.wantSTSCalls(t, primaryArn, 3)
	f.wantSTSCalls(t, secondaryArn, 2)

	apc.mu.Lock()
	state = apc.roleStates[secondaryArn]
	state.creds.Expiration = time.Now().Add(-time.Minute)
	state.renewAt = time.Now().Add(-time.Second)
	state.retryPending = true
	apc.roleStates[secondaryArn] = state
	apc.mu.Unlock()

	if _, err := apc.renew(ctx, client); err != nil {
		t.Fatalf("renew with an expired credential for the failing secondary role: %v", err)
	}

	apc.mu.RLock()
	expired := apc.roleStates[secondaryArn].creds
	apc.mu.RUnlock()

	if expired != nil {
		t.Errorf("expired credentials = %+v kept for the failing secondary role", expired)
	}
}

func TestAWSRenewDuration(t *testing.T) {
	tests := []struct {
		name         string
		primaryTTL   time.Duration
		wantDuration time.Duration
	}{
		{name: "shortest lifetime of the roles with credentials", primaryTTL: 10 * time.Minute, wantDuration: 10 * time.Minute},
		{name: "floored at the minimum renew interval", primaryTTL: 0, wantDuration: minRoleRenewInterval},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, client := newAWSFakeVault(t, primaryArn, secondaryArn)
			f.setTTL(primaryArn, tt.primaryTTL)
			f.setTTL(secondaryArn, 30*time.Minute)

			duration, err := (&AWSProviderConfig{Path: "aws", Role: "test-role"}).renew(context.Background(), client)
			if err != nil {
				t.Fatalf("renew: %v", err)
			}
			if duration < tt.wantDuration-time.Second || duration > tt.wantDuration+time.Second {
				t.Errorf("renew duration = %v, want about %v", duration, tt.wantDuration)
			}
		})
	}
}

func TestAWSPublishCredentialFiles(t *testing.T) {
	dir := t.TempDir()
	apc := &AWSProviderConfig{Path: "aws", Role: "test-role", CredentialsDir: dir}

	creds := map[string]awsRoleState{
		primaryArn:   {creds: &AWSCredentials{AccessKeyID: "AKPRIMARY", SecretAccessKey: "secret", Token: "token", Expiration: time.Now().Add(time.Hour)}},
		secondaryArn: {creds: &AWSCredentials{AccessKeyID: "AKSECONDARY", SecretAccessKey: "secret", Token: "token", Expiration: time.Now().Add(time.Hour)}},
	}

	unmanaged := filepath.Join(dir, "hand-written.json")
	if err := os.WriteFile(unmanaged, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}

	apc.writeCredentialFiles([]string{secondaryArn, primaryArn}, creds)

	wantConfig := fmt.Sprintf("[profile default]\ncredential_process = cat %[1]s/secondary.json\n\n[profile primary]\ncredential_process = cat %[1]s/primary.json\n\n[profile secondary]\ncredential_process = cat %[1]s/secondary.json\n", dir)
	config, err := os.ReadFile(filepath.Join(dir, "config"))
	if err != nil {
		t.Fatalf("reading published config: %v", err)
	}
	if string(config) != wantConfig {
		t.Errorf("published config = %q, want %q", config, wantConfig)
	}

	for _, name := range []string{"primary", "secondary"} {
		path := filepath.Join(dir, name+".json")
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("published %s credentials: %v", name, err)
		}
		if info.Mode().Perm() != tokenFileMode {
			t.Errorf("%s.json mode = %o, want %o", name, info.Mode().Perm(), tokenFileMode)
		}
	}

	data, err := os.ReadFile(filepath.Join(dir, "primary.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file awsCredentialProcessFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("decoding primary.json: %v", err)
	}
	if file.Version != 1 || file.AccessKeyID != "AKPRIMARY" || file.SecretAccessKey != "secret" || file.SessionToken != "token" {
		t.Errorf("primary.json = %+v", file)
	}

	apc.writeCredentialFiles([]string{primaryArn}, creds)

	if _, err := os.Stat(filepath.Join(dir, "secondary.json")); !os.IsNotExist(err) {
		t.Errorf("secondary.json was not removed: %v", err)
	}
	if _, err := os.Stat(unmanaged); err != nil {
		t.Errorf("unmanaged file was removed: %v", err)
	}

	dir = t.TempDir()
	apc = &AWSProviderConfig{Path: "aws", Role: "test-role", CredentialsDir: dir}

	apc.writeCredentialFiles([]string{primaryArn, secondaryArn}, map[string]awsRoleState{
		secondaryArn: {creds: &AWSCredentials{AccessKeyID: "AKSECONDARY", SecretAccessKey: "secret", Token: "token", Expiration: time.Now().Add(time.Hour)}},
	})

	wantNoDefault := fmt.Sprintf("[profile secondary]\ncredential_process = cat %s/secondary.json\n", dir)
	config, err = os.ReadFile(filepath.Join(dir, "config"))
	if err != nil {
		t.Fatalf("reading published config: %v", err)
	}
	if string(config) != wantNoDefault {
		t.Errorf("published config = %q, want %q", config, wantNoDefault)
	}
}

func TestAWSProfileNames(t *testing.T) {
	tests := []struct {
		name     string
		roleArns []string
		want     []string
	}{
		{
			name:     "single role",
			roleArns: []string{"arn:aws:iam::111111111111:role/name"},
			want:     []string{"name"},
		},
		{
			name:     "role path",
			roleArns: []string{"arn:aws:iam::111111111111:role/path/to/name"},
			want:     []string{"name"},
		},
		{
			name:     "comma in role name",
			roleArns: []string{"arn:aws:iam::123456789012:role/a,b"},
			want:     []string{"a-b"},
		},
		{
			name:     "characters outside the allowed set",
			roleArns: []string{"arn:aws:iam::111111111111:role/a[b] c"},
			want:     []string{"a-b--c"},
		},
		{
			name: "collision after sanitising in the same account",
			roleArns: []string{
				"arn:aws:iam::123456789012:role/a,b",
				"arn:aws:iam::123456789012:role/a-b",
			},
			want: []string{"123456789012-a-b", "1-a-b"},
		},
		{
			name: "collision across accounts",
			roleArns: []string{
				"arn:aws:iam::111111111111:role/a,b",
				"arn:aws:iam::222222222222:role/a-b",
			},
			want: []string{"111111111111-a-b", "222222222222-a-b"},
		},
		{
			name:     "role named default",
			roleArns: []string{"arn:aws:iam::123456789012:role/default"},
			want:     []string{"123456789012-default"},
		},
		{
			name:     "empty role name",
			roleArns: []string{"arn:aws:iam::111111111111:role/"},
			want:     []string{"arn-aws-iam--111111111111-role-"},
		},
		{
			name:     "not an iam role arn",
			roleArns: []string{"arn:aws:iam::111111111111:saml-provider/a,b"},
			want:     []string{"arn-aws-iam--111111111111-saml-provider-a-b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := make(map[string]string, len(tt.roleArns))
			for i, roleArn := range tt.roleArns {
				want[roleArn] = tt.want[i]
			}

			if got := awsProfileNames(tt.roleArns); !reflect.DeepEqual(got, want) {
				t.Errorf("awsProfileNames(%v) = %v, want %v", tt.roleArns, got, want)
			}
		})
	}
}
