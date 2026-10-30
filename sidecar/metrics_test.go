package sidecar

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReadiness(t *testing.T) {
	t.Cleanup(func() {
		credentialsReady.Store(false)
	})

	tests := []struct {
		name        string
		credentials bool
		want        int
	}{
		{
			name: "not ready before the first credentials",
			want: http.StatusServiceUnavailable,
		},
		{
			name:        "ready after the first credentials",
			credentials: true,
			want:        http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credentialsReady.Store(tt.credentials)

			rec := httptest.NewRecorder()
			statusHandler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/__/ready", nil))

			if rec.Code != tt.want {
				t.Errorf("readiness returned %d, want %d", rec.Code, tt.want)
			}
		})
	}
}
