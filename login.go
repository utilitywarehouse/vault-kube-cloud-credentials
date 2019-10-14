package main

import (
	"io/ioutil"
	"log"
	"math/rand"
	"time"

	vault "github.com/hashicorp/vault/api"
)

type LoginRenewer struct {
	AuthBackend string
	Client      *vault.Client
	Errors      chan<- error
	Rand        *rand.Rand
	Role        string
	TokenPath   string
}

func (lr *LoginRenewer) Start() {
	log.Print("login: starting login renewer")

	for {
		// Login
		leaseDuration, err := lr.login()
		if err != nil {
			lr.Errors <- err
			return
		}

		// Sleep
		time.Sleep(sleepDuration(leaseDuration, lr.Rand))
	}
}

func (lr *LoginRenewer) login() (time.Duration, error) {
	jwt, err := ioutil.ReadFile(lr.TokenPath)
	if err != nil {
		return time.Duration(0), err
	}

	secret, err := lr.Client.Logical().Write("auth/"+lr.AuthBackend+"/login", map[string]interface{}{
		"jwt":  string(jwt),
		"role": lr.Role,
	})
	if err != nil {
		log.Printf("error: %v", err)
		return time.Duration(0), err
	}

	lr.Client.SetToken(secret.Auth.ClientToken)

	log.Printf("new vault login: lease duration: %vs", secret.Auth.LeaseDuration)
	return time.Duration(secret.Auth.LeaseDuration) * time.Second, nil
}
