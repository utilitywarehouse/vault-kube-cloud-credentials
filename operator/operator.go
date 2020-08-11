package operator

import (
	vault "github.com/hashicorp/vault/api"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Config is the base configuration for an operator
type Config struct {
	KubeClient            client.Client
	KubernetesAuthBackend string
	Prefix                string
	VaultClient           *vault.Client
	VaultConfig           *vault.Config
}

// Operator is responsible for providing access to cloud IAM roles for
// Kubernetes serviceaccounts based on annotations
type Operator interface {
	// Reconcile implements reconcile.Reconciler
	Reconcile(ctrl.Request) (ctrl.Result, error)
	// SetupWithManager adds the operator to a controller-runtime manager as
	// a Runnable and a Reconiler
	SetupWithManager(ctrl.Manager) error
	// Start implements manager.Runnable
	Start(<-chan struct{}) error
}
