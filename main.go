package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"sync"
	"time"

	vault "github.com/hashicorp/vault/api"
)

// AWSCredentials are the credentials served by the API
type AWSCredentials struct {
	AccessKeyID     string    `json:"AccessKeyId"`
	SecretAccessKey string    `json:"SecretAccessKey"`
	Token           string    `json:"Token"`
	Expiration      time.Time `json:"Expiration"`
}

type lease struct {
	Data struct {
		ExpireTime time.Time `json:"expire_time"`
	} `json:"data"`
}

// NewAWSCredentials fetches a new set of credentials from vault with a role
func NewAWSCredentials(client *vault.Client, backend, role string) (credentials *AWSCredentials, leaseDuration time.Duration, err error) {
	var l lease

	secret, err := client.Logical().Read(backend + "/sts/" + role)
	if err != nil {
		return
	}

	// Get the expiration date of the lease
	r := client.NewRequest("PUT", "/v1/sys/leases/lookup")
	if err = r.SetJSONBody(map[string]interface{}{
		"lease_id": secret.LeaseID,
	}); err != nil {
		return
	}
	resp, err := client.RawRequest(r)
	if err == nil {
		defer resp.Body.Close()
	} else {
		return
	}
	err = json.NewDecoder(resp.Body).Decode(&l)
	if err != nil {
		return
	}

	return &AWSCredentials{
		AccessKeyID:     secret.Data["access_key"].(string),
		SecretAccessKey: secret.Data["secret_key"].(string),
		Token:           secret.Data["security_token"].(string),
		Expiration:      l.Data.ExpireTime,
	}, time.Duration(secret.LeaseDuration) * time.Second, nil
}

// leaseExpireTime retrieves the expiration date of a lease
func leaseExpireTime(client *vault.Client, leaseID string) (expire time.Time, err error) {
	var l lease

	r := client.NewRequest("PUT", "/v1/sys/leases/lookup")
	if err = r.SetJSONBody(map[string]interface{}{
		"lease_id": leaseID,
	}); err != nil {
		return
	}
	resp, err := client.RawRequest(r)
	if err == nil {
		defer resp.Body.Close()
	} else {
		return
	}
	json.NewDecoder(resp.Body).Decode(&l)

	return l.Data.ExpireTime, nil
}

var (
	listenAddress        = os.Getenv("VKAC_LISTEN_ADDRESS")
	kubeAuthBackendPath  = os.Getenv("VKAC_KUBE_AUTH_BACKEND_PATH")
	kubeAuthRole         = os.Getenv("VKAC_KUBE_AUTH_ROLE")
	awsSecretBackendPath = os.Getenv("VKAC_AWS_SECRET_BACKEND_PATH")
	awsSecretRole        = os.Getenv("VKAC_AWS_SECRET_ROLE")

	syncMutex = &sync.RWMutex{}
)

func validate() {
	if kubeAuthRole == "" {
		log.Fatalf("error: %s", "VKAC_KUBE_AUTH_ROLE must be set")
	}
	if kubeAuthBackendPath == "" {
		kubeAuthBackendPath = "kubernetes"
	}
	if awsSecretRole == "" {
		log.Fatalf("error: %s", "VKAC_AWS_SECRET_ROLE must be set")
	}
	if awsSecretBackendPath == "" {
		awsSecretBackendPath = "aws"
	}
	if listenAddress == "" {
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

	// Login with the SA token
	jwt, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		log.Fatalf("error reading serviceaccount token: %v", err)
	}
	loginSecret, err := client.Logical().Write("auth/"+kubeAuthBackendPath+"/login", map[string]interface{}{
		"jwt":  string(jwt),
		"role": kubeAuthRole,
	})
	if err != nil {
		log.Fatalf("error logging in: %v", err)
	}
	client.SetToken(loginSecret.Auth.ClientToken)

	// Keep the login renewed
	renewer, err := client.NewRenewer(&vault.RenewerInput{
		Secret: loginSecret,
	})
	if err != nil {
		log.Fatalf("error creating login renewer: %v", err)
	}
	go renewer.Renew()
	defer renewer.Stop()
	go func() {
		for {
			select {
			case err := <-renewer.DoneCh():
				if err != nil {
					log.Fatalf("error during login renewal: %v", err)
				}
				return
			case renewal := <-renewer.RenewCh():
				client.SetToken(renewal.Secret.Auth.ClientToken)
			}
		}
	}()

	// Credentials
	credentials, leaseDuration, err := NewAWSCredentials(client, awsSecretBackendPath, awsSecretRole)
	if err != nil {
		log.Fatalf("error retrieving credentials: %v", err)
	}
	go func() {
		random := rand.New(rand.NewSource(int64(time.Now().Nanosecond())))
		for {
			// Wait for 2/3 of the lease duration with a small random jitter ([0.75, 1.25]) which prevents multiple clients
			// fetching credentials simultaneously.
			sleep := time.Duration((float64(leaseDuration.Nanoseconds()) * 2 / 3) * (random.Float64() + 1.50) / 2)
			time.Sleep(sleep)

			syncMutex.Lock()
			credentials, leaseDuration, err = NewAWSCredentials(client, awsSecretBackendPath, awsSecretRole)
			if err != nil {
				log.Fatalf("error retrieving credentials: %v", err)
			}
			syncMutex.Unlock()
		}
	}()

	// Serve the credentials over HTTP
	http.HandleFunc("/credentials", func(w http.ResponseWriter, r *http.Request) {
		syncMutex.RLock()
		defer syncMutex.RUnlock()
		enc := json.NewEncoder(w)
		enc.Encode(credentials)
	})

	log.Printf("Listening on: %s", listenAddress)
	log.Fatal(http.ListenAndServe(listenAddress, nil))
}
