package sidecar

import (
	vault "github.com/hashicorp/vault/api"
)

// Config configures the sidecar
type Config struct {
	ProviderConfig ProviderConfig
	KubeAuthPath   string
	KubeAuthRole   string
	ListenAddress  string
	TokenPath      string
}

// Sidecar provides the basic functionality for retrieving credentials using the
// provided ProviderConfig
type Sidecar struct {
	*Config
}

// New returns a sidecar with the provided config
func New(config *Config) *Sidecar {
	return &Sidecar{config}
}

// Run starts the sidecar. It retrieves credentials from vault and serves them
// for the configured cloud provider
func (s *Sidecar) Run() error {
	// Channel for goroutines to send errors to
	errors := make(chan error)

	// This channel communicates changes in credentials between the credentials renewer and the webserver
	creds := make(chan interface{})

	// Keep credentials up to date
	cr := &credentialsRenewer{
		credentials:    creds,
		errors:         errors,
		kubePath:       s.KubeAuthPath,
		kubeRole:       s.KubeAuthRole,
		providerConfig: s.ProviderConfig,
		tokenPath:      s.TokenPath,
		vaultConfig:    vault.DefaultConfig(),
	}

	// Serve the credentials
	ws := &webserver{
		credentials:    creds,
		providerConfig: s.ProviderConfig,
		errors:         errors,
		listenAddress:  s.ListenAddress,
	}

	go cr.start()
	go ws.start()

	err := <-errors

	return err
}
