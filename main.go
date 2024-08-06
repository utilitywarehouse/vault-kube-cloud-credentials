package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"

	"github.com/utilitywarehouse/vault-kube-cloud-credentials/operator"
	"github.com/utilitywarehouse/vault-kube-cloud-credentials/sidecar"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var (
	operatorCommand        = flag.NewFlagSet("operator", flag.ExitOnError)
	flagOperatorConfigFile = operatorCommand.String("config-file", "", "Path to a configuration file")
	flagOperatorProvider   = operatorCommand.String("provider", "aws", "Cloud provider (one of 'aws' or 'gcp')")

	sidecarCommand                = flag.NewFlagSet("sidecar", flag.ExitOnError)
	flagSidecarKubeTokenPath      = sidecarCommand.String("kube-token-path", "/var/run/secrets/kubernetes.io/serviceaccount/token", "Path to the kubernetes serviceaccount token")
	flagSidecarListenAddr         = sidecarCommand.String("listen-address", "127.0.0.1:8098", "Listen address")
	flagSidecarOpsAddr            = sidecarCommand.String("operational-address", ":8099", "Listen address for operational status endpoints")
	flagSidecarVaultRole          = sidecarCommand.String("vault-role", "", "Must be in the format: `<prefix>_<provider>_<namespace>_<service-account>`")
	flagSidecarVaultStaticAccount = sidecarCommand.String("vault-static-account", "", "Must be in the format: `<prefix>_<provider>_<namespace>_<service-account>`")
	flagSidecarSecretType         = sidecarCommand.String("secret-type", "access_token", "Secret type (one of 'service_account_key' or 'access_token')")

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

		if *flagOperatorProvider == "" {
			operatorCommand.PrintDefaults()
			os.Exit(1)
		}

		o, err := operator.New(*flagOperatorConfigFile, *flagOperatorProvider)
		if err != nil {
			log.Error(err, "error creating operator")
			os.Exit(1)
		}

		if err := o.Start(); err != nil {
			log.Error(err, "error running operator")
			os.Exit(1)
		}

		return
	}

	if sidecarCommand.Parsed() {
		if len(sidecarCommand.Args()) > 0 {
			sidecarCommand.PrintDefaults()
			os.Exit(1)
		}

		var provider string
		if *flagSidecarVaultStaticAccount != "" && *flagSidecarVaultRole != "" {
			log.Error(nil, "Only one of 'vault-role' or 'vault-static-account' can be specified.")
			os.Exit(1)
		}

		if *flagSidecarVaultStaticAccount != "" {
			provider = vaultRoleRegex.FindStringSubmatch(*flagSidecarVaultStaticAccount)[2]
		}
		if *flagSidecarVaultRole != "" {
			provider = vaultRoleRegex.FindStringSubmatch(*flagSidecarVaultRole)[2]
		}

		var pc sidecar.ProviderConfig
		switch provider {
		case "aws":
			pc = &sidecar.AWSProviderConfig{
				Path:    "aws",
				RoleArn: "",
				Role:    *flagSidecarVaultRole,
			}
		case "gcp":
			keyFilePath := os.Getenv("GCP_CREDENTIALS_FILE")
			if keyFilePath == "" {
				keyFilePath = "/gcp/sa.json"
			}

			pc = &sidecar.GCPProviderConfig{
				Path:                   "gcp",
				StaticAccount:          *flagSidecarVaultStaticAccount,
				SecretType:             *flagSidecarSecretType,
				KeyFileDestinationPath: keyFilePath,
			}
		default:
			usage()
			return
		}

		sidecarConfig := &sidecar.Config{
			KubeAuthPath:   "kubernetes",
			KubeAuthRole:   *flagSidecarVaultStaticAccount,
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
