package main

import (
	"log"
	"os"
)

var (
	awsPath    = os.Getenv("VKAC_AWS_SECRET_BACKEND_PATH")
	awsRole    = os.Getenv("VKAC_AWS_SECRET_ROLE")
	kubePath   = os.Getenv("VKAC_KUBE_AUTH_BACKEND_PATH")
	kubeRole   = os.Getenv("VKAC_KUBE_AUTH_ROLE")
	tokenPath  = os.Getenv("VKAC_KUBE_SA_TOKEN_PATH")
	listenHost = os.Getenv("VKAC_LISTEN_HOST")
	listenPort = os.Getenv("VKAC_LISTEN_PORT")
)

func validate() {
	if len(awsRole) == 0 {
		log.Fatalf("error: must set VKAC_AWS_SECRET_ROLE")
	}

	if len(kubeRole) == 0 {
		log.Fatalf("error: must set VKAC_KUBE_AUTH_ROLE")
	}

	if len(awsPath) == 0 {
		awsPath = "aws"
	}

	if len(kubePath) == 0 {
		kubePath = "kubernetes"
	}

	if len(tokenPath) == 0 {
		tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	}

	if len(listenHost) == 0 {
		listenHost = "127.0.0.1"
	}

	if len(listenPort) == 0 {
		listenPort = "8000"
	}
}

func main() {
	validate()

	// Channel for goroutines to send errors to
	errors := make(chan error)

	// This channel communicates changes in credentials between the credentials renewer and the webserver
	creds := make(chan *AWSCredentials)

	listenAddress := listenHost + ":" + listenPort

	// Keep credentials up to date
	credentialsRenewer := &CredentialsRenewer{
		Credentials: creds,
		Errors:      errors,
		AwsPath:     awsPath,
		AwsRole:     awsRole,
		KubePath:    kubePath,
		KubeRole:    kubeRole,
		TokenPath:   tokenPath,
	}

	// Serve the credentials
	webserver := &Webserver{
		Credentials:   creds,
		Errors:        errors,
		ListenAddress: listenAddress,
	}

	go credentialsRenewer.Start()
	go webserver.Start()

	e := <-errors
	log.Fatalf("error: %v", e)
}
