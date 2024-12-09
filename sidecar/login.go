package sidecar

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/hashicorp/vault/api"
)

func (s *Sidecar) manageLoginToken(ctx context.Context, loggedIn chan bool) {
	// Random is used for the backoff and the interval between renewal attempts
	rnd := rand.New(rand.NewSource(int64(time.Now().Nanosecond())))
	backoff := &Backoff{
		Jitter: true,
		Min:    5 * time.Second,
		Max:    1 * time.Minute,
	}

	var secret *api.Secret
	var expiresAt time.Time

	go func() {
		firstRun := true
		for {
			newSec, err := s.renewLoginToken(ctx, secret, expiresAt)
			if err != nil {
				if firstRun {
					log.Error(err, "error renewing login token")
					os.Exit(1)
				}

				promErrors.Inc()
				d := backoff.Duration()
				log.Error(err, "error renewing login token", "backoff", d)
				time.Sleep(d)
				continue
			}
			secret = newSec
			backoff.Reset()

			duration := time.Duration(secret.Auth.LeaseDuration) * time.Second
			expiresAt = time.Now().Add(duration)

			promRenewals.Inc()
			promExpiry.Set(float64(time.Now().Add(duration).Unix()))

			if firstRun {
				loggedIn <- true
				firstRun = false
			}

			// Sleep until its time to renew the creds
			time.Sleep(sleepDuration(duration, rnd))
		}
	}()
}

func (s *Sidecar) renewLoginToken(ctx context.Context, secret *api.Secret, expiresAt time.Time) (*api.Secret, error) {
	var err error

	// Reload vault CA from the environment
	if err := s.reloadVaultCA(); err != nil {
		return nil, fmt.Errorf("unable to reload vault CA err:%w", err)
	}

	// check if login token can be renewed
	if secret == nil || secret.Auth == nil ||
		!secret.Auth.Renewable || time.Since(expiresAt) > 0 {
		secret, err = s.login(ctx)
		if err != nil {
			return nil, err
		}

		// Calculate expiry time
		expiresAt = time.Now().Add(time.Duration(secret.Auth.LeaseDuration) * time.Second)
		log.Info("new login token created", "lease_expiration", expiresAt.Format("2006-01-02 15:04:05"))
		return secret, nil
	}

	secret, err = s.vaultClient.Auth().Token().RenewTokenAsSelfWithContext(ctx, secret.Auth.ClientToken, secret.Auth.LeaseDuration)
	if err != nil {
		return nil, fmt.Errorf("unable to renew login token err:%w", err)
	}

	// Calculate expiry time
	expiresAt = time.Now().Add(time.Duration(secret.Auth.LeaseDuration) * time.Second)
	log.Info("login token lease renewed", "lease_expiration", expiresAt.Format("2006-01-02 15:04:05"))

	return secret, nil
}

func (s *Sidecar) login(ctx context.Context) (*api.Secret, error) {
	// Login to Vault via kube SA
	jwt, err := os.ReadFile(s.TokenPath)
	if err != nil {
		return nil, err
	}

	loginPath := "auth/" + s.KubeAuthPath + "/login"
	secret, err := s.vaultClient.Logical().WriteWithContext(ctx, loginPath, map[string]interface{}{
		"jwt":  string(jwt),
		"role": s.KubeAuthRole,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to login err:%w", err)
	}
	if secret == nil {
		return nil, fmt.Errorf("no secret returned by %s", loginPath)
	}
	if secret.Auth == nil {
		return nil, fmt.Errorf("no authentication information attached to the response from %s", loginPath)
	}

	// set new token on client
	s.vaultClient.SetToken(secret.Auth.ClientToken)

	return secret, nil
}
