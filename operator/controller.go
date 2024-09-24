package operator

import (
	"fmt"

	vault "github.com/hashicorp/vault/api"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var log = ctrl.Log.WithName("operator")

// Config is the base configuration for an operator
type Config struct {
	KubeClient            client.Client
	KubernetesAuthBackend string
	Prefix                string
	VaultClient           *vault.Client
	VaultConfig           *vault.Config
}

// Controller is responsible for providing access to cloud IAM roles for
// Kubernetes serviceaccounts based on annotations
type Controller struct {
	mgr ctrl.Manager
}

// New creates a new operator from the configuration in the provided file
func New(configFile, provider string) (*Controller, error) {
	fc, err := loadConfigFromFile(configFile)
	if err != nil {
		return nil, err
	}

	scheme := runtime.NewScheme()

	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:         scheme,
		Metrics:        metricsserver.Options{BindAddress: fc.MetricsAddress},
		LeaderElection: false,
	})
	if err != nil {
		return nil, err
	}

	vaultConfig := vault.DefaultConfig()
	vaultClient, err := vault.NewClient(vaultConfig)
	if err != nil {
		return nil, err
	}

	config := &Config{
		KubeClient:            mgr.GetClient(),
		KubernetesAuthBackend: fc.KubernetesAuthBackend,
		Prefix:                fc.Prefix,
		VaultClient:           vaultClient,
		VaultConfig:           vaultConfig,
	}

	log.Info("Starting " + provider + " operator...")
	switch provider {
	case "aws":
		aws, err := NewAWSProvider(fc.AWS)
		if err != nil {
			return nil, err
		}

		ao, err := NewOperator(config, aws)
		if err != nil {
			return nil, err
		}

		if err := ao.SetupWithManager(mgr); err != nil {
			return nil, err
		}
	case "gcp":
		gcp, err := NewGCPProvider(fc.GCP)
		if err != nil {
			return nil, err
		}

		gco, err := NewOperator(config, gcp)
		if err != nil {
			return nil, err
		}

		if err := gco.SetupWithManager(mgr); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("wrong operator provider. must be one of 'aws' or 'gcp'")
	}

	return &Controller{mgr: mgr}, nil
}

// Start runs the operator
func (o *Controller) Start() error {
	return o.mgr.Start(ctrl.SetupSignalHandler())
}
