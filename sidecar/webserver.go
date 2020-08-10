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

// webserver serves the credentials
type webserver struct {
	credentials    <-chan interface{}
	providerConfig ProviderConfig
	errors         chan<- error
	listenAddress  string
}

// start the webserver
func (w *webserver) start() {
	lock := &sync.RWMutex{}

	// Block until the first credentials are delivered
	latestCredentials := <-w.credentials

	// Updated credentials when delivered by the w.Credentials channel
	go func() {
		for {
			select {
			case c := <-w.credentials:
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
	r.HandleFunc(w.providerConfig.credentialsPath(), func(w http.ResponseWriter, r *http.Request) {
		lock.RLock()
		defer lock.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.Encode(latestCredentials)
	})

	w.providerConfig.setupAdditionalEndpoints(r)

	log.Printf("Listening on %s", w.listenAddress)
	w.errors <- http.ListenAndServe(w.listenAddress, r)
}
