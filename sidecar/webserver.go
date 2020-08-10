package sidecar

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/mux"
	"github.com/utilitywarehouse/go-operational/op"
)

const (
	appName        = "vault-kube-cloud-credentials"
	appDescription = "Fetch cloud provider credentials from vault on behalf of a Kubernetes service account and serve them via HTTP."
)

// Webserver serves the credentials
type Webserver struct {
	Credentials    <-chan interface{}
	ProviderConfig ProviderConfig
	Errors         chan<- error
	ListenAddress  string
}

// Start the webserver
func (w *Webserver) Start() {
	lock := &sync.RWMutex{}

	// Block until the first credentials are delivered
	latestCredentials := <-w.Credentials

	// Updated credentials when delivered by the w.Credentials channel
	go func() {
		for {
			select {
			case c := <-w.Credentials:
				log.Printf("webserver: received credentials")
				latestCredentials = c
			}
		}
	}()

	r := mux.NewRouter()

	// Add operational endpoints
	r.Handle("/__/", op.NewHandler(op.NewStatus(appName, appDescription).
		AddOwner("system", "#infra").
		AddLink("readme", fmt.Sprintf("https://github.com/utilitywarehouse/%s/blob/master/README.md", appName)).
		ReadyAlways()),
	)

	// Serve credentials at the appropriate path for the provider
	r.HandleFunc(w.ProviderConfig.CredentialsPath(), func(w http.ResponseWriter, r *http.Request) {
		lock.RLock()
		defer lock.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.Encode(latestCredentials)
	})

	w.ProviderConfig.SetupAdditionalEndpoints(r)

	log.Printf("Listening on %s", w.ListenAddress)
	w.Errors <- http.ListenAndServe(w.ListenAddress, r)
}
