package operator

import (
	"path/filepath"
	"strings"

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

// Operator is responsible for providing access to cloud IAM roles for
// Kubernetes serviceaccounts based on annotations
type Operator struct {
	mgr ctrl.Manager
}

// New creates a new operator from the configuration in the provided file
func New(configFile, provider string) (*Operator, error) {
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

	if provider == "aws" {
		log.Info("Starting AWS operator...")
		ao, err := NewAWSOperator(&AWSOperatorConfig{
			Config:     config,
			DefaultTTL: fc.AWS.DefaultTTL,
			MinTTL:     fc.AWS.MinTTL,
			AWSPath:    fc.AWS.Path,
			Rules:      fc.AWS.Rules,
		})
		if err != nil {
			return nil, err
		}

		if err := ao.SetupWithManager(mgr); err != nil {
			return nil, err
		}
	}

	if provider == "gcp" {
		log.Info("Starting GCP operator...")
		gco, err := NewGCPOperator(&GCPOperatorConfig{
			Config:  config,
			GCPPath: fc.GCP.Path,
			Rules:   fc.GCP.Rules,
		})
		if err != nil {
			return nil, err
		}

		if err := gco.SetupWithManager(mgr); err != nil {
			return nil, err
		}

	}

	return &Operator{mgr: mgr}, nil
}

// Start runs the operator
func (o *Operator) Start() error {
	return o.mgr.Start(ctrl.SetupSignalHandler())
}

// matchesNamespace returns true if the rule allows the given namespace
func matchesNamespace(namespace string, namespacePatterns []string) (bool, error) {
	for _, np := range namespacePatterns {
		match, err := filepath.Match(np, namespace)
		if err != nil {
			return false, err
		}
		if match {
			return true, nil
		}
	}

	return false, nil
}

// name returns a unique name for the key in vault, derived from the namespace and name of the
// serviceaccount
func name(prefix, provider, namespace, serviceAccount string) string {
	return prefix + provider + namespace + "_" + serviceAccount
}

// parseKey parses a key from vault into its namespace and name. Also returns a
// bool that indicates whether parsing was successful
func parseKey(key, prefix, provider string) (namespace, name string, yes bool) {
	keyParts := strings.Split(key, "_")
	if len(keyParts) == 4 && keyParts[0] == prefix && keyParts[1] == provider {
		return keyParts[2], keyParts[3], true
	}

	return "", "", false
}
