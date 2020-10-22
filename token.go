package main

import (
	"fmt"
	"io/ioutil"

	"github.com/dgrijalva/jwt-go"
)

type kubeTokenClaims struct {
	Namespace          string `json:"kubernetes.io/serviceaccount/namespace"`
	ServiceAccountName string `json:"kubernetes.io/serviceaccount/service-account.name"`
}

// Valid implements jwt.Claims. It's never called because we're only running
// ParseUnverified.
func (c *kubeTokenClaims) Valid() error {
	return nil
}

func newKubeTokenClaimsFromFile(tokenFile string) (*kubeTokenClaims, error) {
	token, err := ioutil.ReadFile(tokenFile)
	if err != nil {
		return nil, err
	}

	jwtParser := &jwt.Parser{}

	claims := &kubeTokenClaims{}
	if _, _, err := jwtParser.ParseUnverified(string(token), claims); err != nil {
		return nil, err
	}

	if claims.Namespace == "" {
		return claims, fmt.Errorf("missing claim for kubernetes.io/serviceaccount/namespace")
	}

	if claims.ServiceAccountName == "" {
		return claims, fmt.Errorf("missing claim for kubernetes.io/serviceaccount/service-account.name")
	}

	return claims, nil
}
