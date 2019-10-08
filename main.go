package main

import (
	"log"
	"math/rand"
	"os"
	"time"

	vault "github.com/hashicorp/vault/api"
)

var (
	listenAddress    = os.Getenv("VKAC_LISTEN_ADDRESS")
	awsSecretBackend = os.Getenv("VKAC_AWS_SECRET_BACKEND")
	awsSecretRole    = os.Getenv("VKAC_AWS_SECRET_ROLE")
	kubeAuthBackend  = os.Getenv("VKAC_KUBE_AUTH_BACKEND")
	kubeAuthRole     = os.Getenv("VKAC_KUBE_AUTH_ROLE")
	kubeTokenPath    = os.Getenv("VKAC_KUBE_SA_TOKEN_PATH")

	latestCredentials = &AWSCredentials{}
)

func validate() {
	if len(awsSecretBackend) == 0 {
		awsSecretBackend = "aws"
	}

	if len(awsSecretRole) == 0 {
		log.Fatalf("error: must set VKAC_AWS_SECRET_ROLE")
	}

	if len(kubeAuthRole) == 0 {
		log.Fatalf("error: must set VKAC_KUBE_AUTH_ROLE")
	}

	if len(kubeAuthBackend) == 0 {
		kubeAuthBackend = "kubernetes"
	}

	if len(kubeTokenPath) == 0 {
		kubeTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	}

	if len(listenAddress) == 0 {
		listenAddress = "127.0.0.1:8000"
	}
}

func main() {
	validate()

	// Vault client
	client, err := vault.NewClient(vault.DefaultConfig())
	if err != nil {
		log.Fatalf("error creating vault client: %v", err)
	}

	// Used to generate random values for sleeping between renewals
	random := rand.New(rand.NewSource(int64(time.Now().Nanosecond())))

	// Channel for goroutines to send errors to
	errors := make(chan error)

	// This channel communicates changes in credentials between the credentials renewer and the webserver
	creds := make(chan *AWSCredentials)

	// Login, and stay logged in
	loginRenewer := &LoginRenewer{
		AuthBackend: kubeAuthBackend,
		Client:      client,
		Errors:      errors,
		Role:        kubeAuthRole,
		Rand:        random,
		TokenPath:   kubeTokenPath,
	}

	// Keep credentials up to date
	credentialsRenewer := &CredentialsRenewer{
		Client:         client,
		Credentials:    creds,
		Errors:         errors,
		Role:           awsSecretRole,
		Rand:           random,
		SecretsBackend: awsSecretBackend,
	}

	// Serve the credentials
	webserver := &Webserver{
		Credentials: creds,
		Errors:      errors,
	}

	go loginRenewer.Start()
	go credentialsRenewer.Start()
	go webserver.Start()

	e := <-errors
	log.Fatalf("error: %v", e)
}
