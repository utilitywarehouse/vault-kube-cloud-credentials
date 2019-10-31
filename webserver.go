package main

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
)

// Webserver serves the credentials
type Webserver struct {
	Credentials   <-chan *AWSCredentials
	Errors        chan<- error
	ListenAddress string
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
				log.Printf("webserver: received credentials: %s", c.AccessKeyID)
				latestCredentials = c
			}
		}
	}()

	// Serve credentials at /credentials
	http.HandleFunc("/credentials", func(w http.ResponseWriter, r *http.Request) {
		lock.RLock()
		defer lock.RUnlock()
		enc := json.NewEncoder(w)
		enc.Encode(latestCredentials)
	})

	log.Printf("Listening on %s", w.ListenAddress)
	w.Errors <- http.ListenAndServe(w.ListenAddress, nil)
}
