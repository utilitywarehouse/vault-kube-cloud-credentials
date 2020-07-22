package main

import (
	"log"
	"os"

	vault "github.com/hashicorp/vault/api"
)

var (
	awsPath    = os.Getenv("VKAC_AWS_SECRET_BACKEND_PATH")
	awsRole    = os.Getenv("VKAC_AWS_SECRET_ROLE")
	gcpPath    = os.Getenv("VKAC_GCP_SECRET_BACKEND_PATH")
	gcpRoleSet = os.Getenv("VKAC_GCP_SECRET_ROLESET")
	kubePath   = os.Getenv("VKAC_KUBE_AUTH_BACKEND_PATH")
	kubeRole   = os.Getenv("VKAC_KUBE_AUTH_ROLE")
	tokenPath  = os.Getenv("VKAC_KUBE_SA_TOKEN_PATH")
	listenHost = os.Getenv("VKAC_LISTEN_HOST")
	listenPort = os.Getenv("VKAC_LISTEN_PORT")
)

func validate() {
	if (len(awsRole) == 0 && len(gcpRoleSet) == 0) ||
		(len(awsRole) > 0 && len(gcpRoleSet) > 0) {
		log.Fatalf("error: must set either VKAC_AWS_SECRET_ROLE or VKAC_GCP_SECRET_ROLESET")
	}

	if len(kubeRole) == 0 {
		log.Fatalf("error: must set VKAC_KUBE_AUTH_ROLE")
	}

	if len(awsPath) == 0 {
		awsPath = "aws"
	}

	if len(gcpPath) == 0 {
		gcpPath = "gcp"
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
	creds := make(chan interface{})

	listenAddress := listenHost + ":" + listenPort

	var providerConfig ProviderConfig
	if len(awsRole) > 0 {
		providerConfig = &AWSProviderConfig{
			AwsPath: awsPath,
			AwsRole: awsRole,
		}
		log.Printf("using AWS secrets engine")
	} else if len(gcpRoleSet) > 0 {
		providerConfig = &GCPProviderConfig{
			GcpPath:    gcpPath,
			GcpRoleSet: gcpRoleSet,
		}
		log.Printf("using GCP secrets engine")
	} else {
		log.Fatalf("could not determine cloud provider")
	}

	// Keep credentials up to date
	credentialsRenewer := &CredentialsRenewer{
		Credentials:    creds,
		Errors:         errors,
		KubePath:       kubePath,
		KubeRole:       kubeRole,
		ProviderConfig: providerConfig,
		TokenPath:      tokenPath,
		VaultConfig:    vault.DefaultConfig(),
	}

	// Serve the credentials
	webserver := &Webserver{
		Credentials:     creds,
		CredentialsPath: providerConfig.CredentialsPath(),
		Errors:          errors,
		ListenAddress:   listenAddress,
	}

	go credentialsRenewer.Start()
	go webserver.Start()

	e := <-errors
	log.Fatalf("error: %v", e)
}
