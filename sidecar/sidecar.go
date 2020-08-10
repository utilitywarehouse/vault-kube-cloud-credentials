package sidecar

import (
	vault "github.com/hashicorp/vault/api"
)

type Config struct {
	ProviderConfig ProviderConfig
	KubeAuthPath   string
	KubeAuthRole   string
	ListenAddress  string
	TokenPath      string
}

type Sidecar struct {
	*Config
}

func New(config *Config) *Sidecar {
	return &Sidecar{config}
}

func (s *Sidecar) Run() error {
	// Channel for goroutines to send errors to
	errors := make(chan error)

	// This channel communicates changes in credentials between the credentials renewer and the webserver
	creds := make(chan interface{})

	// Keep credentials up to date
	credentialsRenewer := &CredentialsRenewer{
		Credentials:    creds,
		Errors:         errors,
		KubePath:       s.KubeAuthPath,
		KubeRole:       s.KubeAuthRole,
		ProviderConfig: s.ProviderConfig,
		TokenPath:      s.TokenPath,
		VaultConfig:    vault.DefaultConfig(),
	}

	// Serve the credentials
	webserver := &Webserver{
		Credentials:    creds,
		ProviderConfig: s.ProviderConfig,
		Errors:         errors,
		ListenAddress:  s.ListenAddress,
	}

	go credentialsRenewer.Start()
	go webserver.Start()

	err := <-errors

	return err
}
