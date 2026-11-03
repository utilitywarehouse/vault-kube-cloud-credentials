package sidecar

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
			fmt.Fprint(w, `{"data":{"expire_time":"2026-11-03T12:52:22.5Z","ttl":3599}}`)
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestAWSRenewWithDelayedLeaseLookupBody(t *testing.T) {
	ts := delayedLeaseLookupServer(t)
	defer ts.Close()

	cfg := vault.DefaultConfig()
	cfg.Address = ts.URL
	cfg.MaxRetries = 0

	client, err := vault.NewClient(cfg)
	if err != nil {
		t.Fatalf("creating vault client: %v", err)
	}

	apc := &AWSProviderConfig{Path: "aws", Role: "test-role"}

	leaseDuration, err := apc.renew(context.Background(), client)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}

	if leaseDuration != time.Hour {
		t.Errorf("lease duration = %v, want %v", leaseDuration, time.Hour)
	}

	want := time.Date(2026, 11, 3, 12, 52, 22, 500000000, time.UTC)
	if apc.creds == nil {
		t.Fatal("credentials were not stored")
	}
	if !apc.creds.Expiration.Equal(want) {
		t.Errorf("expiration = %v, want %v", apc.creds.Expiration, want)
	}
	if apc.creds.AccessKeyID != "AKIATEST" || apc.creds.SecretAccessKey != "secret" || apc.creds.Token != "token" {
		t.Errorf("unexpected credentials: %+v", apc.creds)
	}
}
