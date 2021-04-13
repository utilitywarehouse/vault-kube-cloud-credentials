package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	vault "github.com/hashicorp/vault/api"
	"github.com/utilitywarehouse/vault-kube-cloud-credentials/operator"
	"github.com/utilitywarehouse/vault-kube-cloud-credentials/sidecar"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var (
	operatorCommand             = flag.NewFlagSet("operator", flag.ExitOnError)
	flagOperatorPrefix          = operatorCommand.String("prefix", "vkcc", "This prefix is prepended to all the roles and policies created in vault")
	flagOperatorAWSBackend      = operatorCommand.String("aws-backend", "aws", "AWS secret backend path")
	flagOperatorKubeAuthBackend = operatorCommand.String("kube-auth-backend", "kubernetes", "Kubernetes auth backend")
	flagOperatorMetricsAddr     = operatorCommand.String("metrics-address", ":8080", "Metrics address")
	flagOperatorConfigFile      = operatorCommand.String("config-file", "", "Path to a configuration file")
	flagOperatorDefaultTTL      = operatorCommand.Duration("default-sts-ttl", 900*time.Second, "Default ttl for AWS credentials")

	sidecarCommand           = flag.NewFlagSet("sidecar", flag.ExitOnError)
	flagSidecarKubeTokenPath = sidecarCommand.String("kube-token-path", "/var/run/secrets/kubernetes.io/serviceaccount/token", "Path to the kubernetes serviceaccount token")
	flagSidecarListenAddr    = sidecarCommand.String("listen-address", "127.0.0.1:8098", "Listen address")
	flagSidecarOpsAddr       = sidecarCommand.String("operational-address", ":8099", "Listen address for operational status endpoints")
	flagSidecarVaultRole     = sidecarCommand.String("vault-role", "", "Must be in the format: `<prefix>_<provider>_<namespace>_<service-account>`")

	log = ctrl.Log.WithName("main")

	// example: exp-1_aws_sys-prom_thanos-compact
	//
	// 0: exp-1_aws_sys-prom_thanos-compact
	// 1: prefix (Vault instance) example values: "exp-1", "dev", "prod"
	// 2: provider (AWS|GCP)
	// 3: kubernetes_namespace
	// 4: kubernetes_service_account
	vaultRoleRegex = regexp.MustCompile(`([-\w]+)_([-\w]+)_([-\w]+)_([-\w]+)`)
)

func usage() {
	fmt.Printf(
		`Usage:
  %s [command]

Commands:
  operator      Run the operator
  sidecar       Sidecar for provider credentials
`, os.Args[0])
}

func main() {
	flag.Usage = usage

	if len(os.Args) < 2 {
		usage()
		return
	}

	logOpts := zap.Options{}

	switch os.Args[1] {
	case "operator":
		logOpts.BindFlags(operatorCommand)
		operatorCommand.Parse(os.Args[2:])
	case "sidecar":
		logOpts.BindFlags(sidecarCommand)
		sidecarCommand.Parse(os.Args[2:])
	default:
		usage()
		return
	}

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&logOpts)))

	if operatorCommand.Parsed() {
		if len(operatorCommand.Args()) > 0 {
			operatorCommand.PrintDefaults()
			os.Exit(1)
		}

		if strings.Contains(*flagOperatorPrefix, "_") {
			fmt.Printf("prefix must not contain a '_': %s\n", *flagOperatorPrefix)
			os.Exit(1)
		}

		scheme := runtime.NewScheme()

		_ = clientgoscheme.AddToScheme(scheme)
		_ = corev1.AddToScheme(scheme)

		mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
			Scheme:             scheme,
			MetricsBindAddress: *flagOperatorMetricsAddr,
			LeaderElection:     false,
		})
		if err != nil {
			log.Error(err, "error creating manager")
			os.Exit(1)
		}

		vaultConfig := vault.DefaultConfig()
		vaultClient, err := vault.NewClient(vaultConfig)
		if err != nil {
			log.Error(err, "error creating vault client")
			os.Exit(1)
		}
		o, err := operator.NewAWSOperator(&operator.AWSOperatorConfig{
			Config: &operator.Config{
				KubeClient:            mgr.GetClient(),
				KubernetesAuthBackend: *flagOperatorKubeAuthBackend,
				Prefix:                *flagOperatorPrefix,
				VaultClient:           vaultClient,
				VaultConfig:           vaultConfig,
			},
			AWSPath:    *flagOperatorAWSBackend,
			DefaultTTL: *flagOperatorDefaultTTL,
		})
		if err != nil {
			log.Error(err, "error creating operator")
			os.Exit(1)
		}

		if *flagOperatorConfigFile != "" {
			if err := o.LoadConfig(*flagOperatorConfigFile); err != nil {
				log.Error(err, "error loading configuration file")
				os.Exit(1)
			}
		}

		if err = o.SetupWithManager(mgr); err != nil {
			log.Error(err, "error creating controller")
			os.Exit(1)
		}

		if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
			log.Error(err, "error running manager")
			os.Exit(1)
		}

		return
	}

	if sidecarCommand.Parsed() {
		if len(sidecarCommand.Args()) > 0 {
			sidecarCommand.PrintDefaults()
			os.Exit(1)
		}

		var pc sidecar.ProviderConfig
		provider := vaultRoleRegex.FindStringSubmatch(*flagSidecarVaultRole)[2]

		switch provider {
		case "aws":
			pc = &sidecar.AWSProviderConfig{
				Path:    "aws",
				RoleArn: "",
				Role:    *flagSidecarVaultRole,
			}
		case "gcp":
			pc = &sidecar.GCPProviderConfig{
				Path:    "gcp",
				RoleSet: *flagSidecarVaultRole,
			}
		default:
			usage()
			return
		}
		sidecarConfig := &sidecar.Config{
			KubeAuthPath:   "kubernetes",
			KubeAuthRole:   *flagSidecarVaultRole,
			ListenAddress:  *flagSidecarListenAddr,
			OpsAddress:     *flagSidecarOpsAddr,
			ProviderConfig: pc,
			TokenPath:      *flagSidecarKubeTokenPath,
		}

		s, err := sidecar.New(sidecarConfig)
		if err != nil {
			log.Error(err, "error creating sidecar")
			os.Exit(1)
		}

		if err := s.Run(); err != nil {
			log.Error(err, "error running sidecar")
			os.Exit(1)
		}

		return
	}

	usage()
	return
}
