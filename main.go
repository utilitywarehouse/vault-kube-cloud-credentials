package main

import (
	"log"
	"os"
)

var (
	appNamespace     = os.Getenv("VKAC_APP_NAMESPACE")
	appSA            = os.Getenv("VKAC_APP_SA")
	awsSecretsEngine = os.Getenv("VKAC_AWS_SECRETS_ENGINE")
	kubeAuthMethod   = os.Getenv("VKAC_KUBE_AUTH_METHOD")
	kubeSATokenPath  = os.Getenv("VKAC_KUBE_SA_TOKEN_PATH")
	listenAddress    = os.Getenv("VKAC_LISTEN_ADDRESS")
)

func validate() {
	if len(appNamespace) == 0 {
		log.Fatalf("error: must set VKAC_APP_NAMESPACE")
	}

	if len(appSA) == 0 {
		log.Fatalf("error: must set VKAC_APP_SA")
	}

	if len(awsSecretsEngine) == 0 {
		awsSecretsEngine = "aws"
	}

	if len(kubeAuthMethod) == 0 {
		kubeAuthMethod = "kubernetes"
	}

	if len(kubeSATokenPath) == 0 {
		kubeSATokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	}

	if len(listenAddress) == 0 {
		listenAddress = "127.0.0.1:8000"
	}
}

func main() {
	validate()

	// Channel for goroutines to send errors to
	errors := make(chan error)

	// This channel communicates changes in credentials between the credentials renewer and the webserver
	creds := make(chan *AWSCredentials)

	// Identifier used in vault roles
	vaultRolesName := appNamespace + "-" + appSA

	// Keep credentials up to date
	credentialsRenewer := &CredentialsRenewer{
		Credentials:   creds,
		Errors:        errors,
		Role:          vaultRolesName,
		SecretsEngine: awsSecretsEngine,
		AuthMethod:    kubeAuthMethod,
		TokenPath:     kubeSATokenPath,
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
