package main

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
)

func TestNewKubeTokenClaimsFromFile(t *testing.T) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":                                    "kubernetes/serviceaccount",
		"kubernetes.io/serviceaccount/namespace": "foo",
		"kubernetes.io/serviceaccount/secret.name":          "bar-token-8mjcw",
		"kubernetes.io/serviceaccount/service-account.name": "bar",
		"kubernetes.io/serviceaccount/service-account.uid":  "d8f5785e-1477-11eb-adc1-0242ac120002",
		"sub": "system:serviceaccount:foo:bar",
	})

	ss, err := token.SignedString([]byte("SuperDuperSecure"))
	if err != nil {
		t.Fatal(err)
	}

	tmpFile, err := ioutil.TempFile("", "jwt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	if _, err := tmpFile.Write([]byte(ss)); err != nil {
		t.Fatal(err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatal(err)
	}

	claims, err := newKubeTokenClaimsFromFile(tmpFile.Name())
	assert.NoError(t, err)
	assert.Equal(t, "foo", claims.Namespace)
	assert.Equal(t, "bar", claims.ServiceAccountName)
}

func TestNewKubeTokenClaimsFromFileInvalidClaims(t *testing.T) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "kubernetes/serviceaccount",
		"kubernetes.io/serviceaccount/secret.name":         "bar-token-8mjcw",
		"kubernetes.io/serviceaccount/service-account.uid": "d8f5785e-1477-11eb-adc1-0242ac120002",
		"sub": "system:serviceaccount:foo:bar",
	})

	ss, err := token.SignedString([]byte("SuperDuperSecure"))
	if err != nil {
		t.Fatal(err)
	}

	tmpFile, err := ioutil.TempFile("", "jwt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	if _, err := tmpFile.Write([]byte(ss)); err != nil {
		t.Fatal(err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = newKubeTokenClaimsFromFile(tmpFile.Name())
	assert.Error(t, err)
}
