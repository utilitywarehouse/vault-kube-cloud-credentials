package sidecar

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/hashicorp/vault/api"
)

func (s *Sidecar) login(ctx context.Context) error {
	if s.vaultClient.Token() != "" && !s.reAuthRequired {
		return nil
	}

	var secret *api.Secret

	// Login to Vault via kube SA
	jwt, err := os.ReadFile(s.TokenPath)
	if err != nil {
		return err
	}
	loginPath := "auth/" + s.KubeAuthPath + "/login"
	secret, err = s.vaultClient.Logical().Write(loginPath, map[string]interface{}{
		"jwt":  string(jwt),
		"role": s.KubeAuthRole,
	})
	if err != nil {
		return err
	}
	if secret == nil {
		return fmt.Errorf("no secret returned by %s", loginPath)
	}
	if secret.Auth == nil {
		return fmt.Errorf("no authentication information attached to the response from %s", loginPath)
	}

	log.Info("new login token", "renewable", secret.Auth.Renewable, "lease", secret.Auth.LeaseDuration)

	s.vaultClient.SetToken(secret.Auth.ClientToken)

	// setup loop to renew login token
	rnd := rand.New(rand.NewSource(int64(time.Now().Nanosecond())))
	go func() {
		for {
			// validate auth token again as in loop
			if secret == nil || secret.Auth == nil || !secret.Auth.Renewable {
				break
			}

			// Sleep until its time to renew the creds
			time.Sleep(sleepDuration(time.Duration(secret.Auth.LeaseDuration)*time.Second, rnd))

			// Reload vault CA from the environment
			if err := s.reloadVaultCA(); err != nil {
				log.Error(err, "unable to reload vault CA")
				break
			}

			secret, err = s.vaultClient.Auth().Token().RenewTokenAsSelfWithContext(ctx, secret.Auth.ClientToken, secret.Auth.LeaseDuration)
			if err != nil {
				log.Error(err, "unable to renew login token")
				break
			}

			// Calculate expiry time
			expiresAt := time.Now().Add(time.Duration(secret.Auth.LeaseDuration) * time.Second)
			log.Info("login token lease renewed", "lease_expiration", expiresAt.Format("2006-01-02 15:04:05"))
		}
		// unable to renew login token or its not renewable
		s.reAuthRequired = true

	}()

	return nil
}
