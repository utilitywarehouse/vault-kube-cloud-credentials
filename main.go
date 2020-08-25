package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

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

	awsSidecarCommand    = flag.NewFlagSet("aws-sidecar", flag.ExitOnError)
	flagAWSBackend       = awsSidecarCommand.String("backend", "aws", "AWS secret backend path")
	flagAWSRoleArn       = awsSidecarCommand.String("role-arn", "", "AWS role arn to assume")
	flagAWSRole          = awsSidecarCommand.String("role", "", "AWS secret role (required)")
	flagAWSKubeAuthRole  = awsSidecarCommand.String("kube-auth-role", "", "Kubernetes auth role (required)")
	flagAWSKubeBackend   = awsSidecarCommand.String("kube-auth-backend", "kubernetes", "Kubernetes auth backend")
	flagAWSKubeTokenPath = awsSidecarCommand.String("kube-token-path", "/var/run/secrets/kubernetes.io/serviceaccount/token", "Path to the kubernetes serviceaccount token")
	flagAWSListenAddr    = awsSidecarCommand.String("listen-address", "127.0.0.1:8000", "Listen address")

	gcpSidecarCommand    = flag.NewFlagSet("gcp-sidecar", flag.ExitOnError)
	flagGCPBackend       = gcpSidecarCommand.String("backend", "gcp", "GCP secret backend path")
	flagGCPRoleSet       = gcpSidecarCommand.String("roleset", "", "GCP secret roleset (required)")
	flagGCPKubeAuthRole  = gcpSidecarCommand.String("kube-auth-role", "", "Kubernetes auth role (required)")
	flagGCPKubeBackend   = gcpSidecarCommand.String("kube-auth-backend", "kubernetes", "Kubernetes auth backend")
	flagGCPKubeTokenPath = gcpSidecarCommand.String("kube-token-path", "/var/run/secrets/kubernetes.io/serviceaccount/token", "Path to the kubernetes serviceaccount token")
	flagGCPListenAddr    = gcpSidecarCommand.String("listen-address", "127.0.0.1:8000", "Listen address")

	log = ctrl.Log.WithName("main")
)

func usage() {
	fmt.Printf(
		`Usage:
  %s [command]

Commands:
  operator      Run the operator
  aws-sidecar   Sidecar for AWS credentials
  gcp-sidecar   Sidecar for GCP credentials
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
	case "aws-sidecar":
		logOpts.BindFlags(awsSidecarCommand)
		awsSidecarCommand.Parse(os.Args[2:])
	case "gcp-sidecar":
		logOpts.BindFlags(gcpSidecarCommand)
		gcpSidecarCommand.Parse(os.Args[2:])
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
				VaultConfig:           vault.DefaultConfig(),
			},
			AWSPath: *flagOperatorAWSBackend,
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

	if awsSidecarCommand.Parsed() {
		if len(awsSidecarCommand.Args()) > 0 {
			awsSidecarCommand.PrintDefaults()
			os.Exit(1)
		}

		if *flagAWSKubeAuthRole == "" {
			fmt.Print("error: must set -kube-auth-role\n")
			os.Exit(1)
		}

		if *flagAWSRole == "" {
			fmt.Print("error: must set -role\n")
			os.Exit(1)
		}

		sidecarConfig := &sidecar.Config{
			KubeAuthPath:  *flagAWSKubeBackend,
			KubeAuthRole:  *flagAWSKubeAuthRole,
			ListenAddress: *flagAWSListenAddr,
			ProviderConfig: &sidecar.AWSProviderConfig{
				AwsPath:    *flagAWSBackend,
				AwsRoleArn: *flagAWSRoleArn,
				AwsRole:    *flagAWSRole,
			},
			TokenPath: *flagAWSKubeTokenPath,
		}

		if err := sidecar.New(sidecarConfig).Run(); err != nil {
			log.Error(err, "error running sidecar")
			os.Exit(1)
		}

		return
	}

	if gcpSidecarCommand.Parsed() {
		if len(gcpSidecarCommand.Args()) > 0 {
			gcpSidecarCommand.PrintDefaults()
			os.Exit(1)
		}

		if *flagGCPKubeAuthRole == "" {
			fmt.Print("error: must set -kube-auth-role\n")
			os.Exit(1)
		}

		if *flagGCPRoleSet == "" {
			fmt.Print("error: must set -roleset\n")
			os.Exit(1)
		}

		sidecarConfig := &sidecar.Config{
			KubeAuthPath:  *flagGCPKubeBackend,
			KubeAuthRole:  *flagGCPKubeAuthRole,
			ListenAddress: *flagGCPListenAddr,
			ProviderConfig: &sidecar.GCPProviderConfig{
				GcpPath:    *flagGCPBackend,
				GcpRoleSet: *flagGCPRoleSet,
			},
			TokenPath: *flagGCPKubeTokenPath,
		}

		if err := sidecar.New(sidecarConfig).Run(); err != nil {
			log.Error(err, "error running sidecar")
			os.Exit(1)
		}

		return
	}

	usage()
	return
}
