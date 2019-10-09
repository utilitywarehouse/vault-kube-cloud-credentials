package main

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
)

// Webserver serves the credentials
type Webserver struct {
	Credentials <-chan *AWSCredentials
	Errors      chan<- error
}

// Start the webserver
func (w *Webserver) Start() {
	received := make(chan bool)
	lock := &sync.RWMutex{}
	latestCredentials := &AWSCredentials{}

	// Updated credentials are delivered by the w.Credentials channel
	go func() {
		for {
			select {
			case c := <-w.Credentials:
				log.Printf("webserver: received credentials: %s", c.AccessKeyID)
				latestCredentials = c
				received <- true
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

	// Wait to receive the first set of credentials before starting the webserver
	<-received

	log.Printf("Listening on %s", listenAddress)
	w.Errors <- http.ListenAndServe(listenAddress, nil)
}
