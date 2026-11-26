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

	sidecarCommand                 = flag.NewFlagSet("sidecar", flag.ExitOnError)
	flagSidecarKubeTokenPath       = sidecarCommand.String("kube-token-path", envOr("VKCC_KUBE_TOKEN_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/token"), "Path to the kubernetes serviceaccount token")
	flagSidecarListenAddr          = sidecarCommand.String("listen-address", envOr("VKCC_LISTEN_ADDRESS", "127.0.0.1:8098"), "Listen address")
	flagSidecarOpsAddr             = sidecarCommand.String("operational-address", envOr("VKCC_OPERATIONAL_ADDRESS", ":8099"), "Listen address for operational status endpoints")
	flagSidecarDisableHTTP         = sidecarCommand.Bool("disable-http", envBool("VKCC_DISABLE_HTTP"), "Do not serve credentials over HTTP (aws provider with VKCC_AWS_CREDENTIALS_DIR only)")
	flagSidecarVaultRole           = sidecarCommand.String("vault-role", os.Getenv("VKCC_VAULT_ROLE"), "Must be in the format: `<prefix>_<provider>_<namespace>_<service-account>` (github: `<prefix>_github_<permission-set>`)")
	flagSidecarVaultStaticAccount  = sidecarCommand.String("vault-static-account", os.Getenv("VKCC_VAULT_STATIC_ACCOUNT"), "Must be in the format: `<prefix>_<provider>_<namespace>_<service-account>`")
	flagSidecarSecretType          = sidecarCommand.String("secret-type", envOr("VKCC_SECRET_TYPE", "access_token"), "Secret type (one of 'service_account_key' or 'access_token')")
	flagSidecarGitHubPermissionSet = sidecarCommand.String("github-permission-set", os.Getenv("VKCC_GITHUB_PERMISSION_SET"), "Name of the vault-plugin-secrets-github permission set to fetch a token for (github provider only)")

	log = ctrl.Log.WithName("main")

	// example: exp-1_aws_sys-prom_thanos-compact
	//
	// 1: prefix (Vault instance) example values: "exp-1", "dev", "prod"
	// 2: provider (aws|gcp|github)
	// 3: `<namespace>_<service-account>` for aws/gcp, the permission set for
	//    github; these may contain underscores (for example uw_ro_k8s)
	//
	// The provider is pinned as the second segment so a name with extra
	// underscores cannot parse into a plausible but wrong provider.
	vaultRoleRegex = regexp.MustCompile(`^([a-zA-Z0-9-]+)_(aws|gcp|github)_([a-zA-Z0-9_-]+)$`)
)

// accountProvider returns the provider named in an account of the form
// `<prefix>_<provider>_<namespace>_<service-account>`; the namespace and
// service account may contain underscores (a GitHub permission set such as
// uw_ro_k8s arrives in the same shape).
func accountProvider(account string) (string, bool) {
	match := vaultRoleRegex.FindStringSubmatch(account)
	if match == nil {
		return "", false
	}

	return match[2], true
}

// envOr returns the environment variable named key when it is set, and
// fallback otherwise, so the sidecar can be configured without flags.
func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}

	return fallback
}

func envBool(key string) bool {
	return envOr(key, "false") == "true"
}

// mustBeSet exits when the flag a provider needs to derive its kubernetes auth
// role or credentials from was not set.
func mustBeSet(name, value, provider string) {
	if value != "" {
		return
	}

	log.Error(nil, "'"+name+"' must be set for the "+provider+" provider.")
	os.Exit(1)
}

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
	ctx := ctrl.SetupSignalHandler()
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

		o, err := operator.New(*flagOperatorConfigFile, *flagOperatorProvider)
		if err != nil {
			log.Error(err, "error creating operator")
			os.Exit(1)
		}

		if err := o.Start(ctx); err != nil {
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

		var sidecarProvider string
		if *flagSidecarVaultStaticAccount != "" && *flagSidecarVaultRole != "" {
			log.Error(nil, "Only one of 'vault-role' or 'vault-static-account' can be specified.")
			os.Exit(1)
		}

		account := *flagSidecarVaultRole
		if account == "" {
			account = *flagSidecarVaultStaticAccount
		}

		if account != "" {
			provider, ok := accountProvider(account)
			if !ok {
				log.Error(nil, "'vault-role' or 'vault-static-account' must be in the format `<prefix>_<provider>_<namespace>_<service-account>` (github: `<prefix>_github_<permission-set>`).")
				os.Exit(1)
			}
			sidecarProvider = provider
		}

		// Each provider takes its kubernetes auth role from one of these flags,
		// so each case checks the flag it uses before building anything from it.
		var pc sidecar.ProviderConfig
		var kubeAuthRole string
		switch sidecarProvider {
		case "aws":
			mustBeSet("vault-role", *flagSidecarVaultRole, sidecarProvider)

			pc = &sidecar.AWSProviderConfig{
				Path:           "aws",
				RoleArn:        "",
				Role:           *flagSidecarVaultRole,
				CredentialsDir: os.Getenv("VKCC_AWS_CREDENTIALS_DIR"),
			}
			kubeAuthRole = *flagSidecarVaultRole
		case "gcp":
			mustBeSet("vault-static-account", *flagSidecarVaultStaticAccount, sidecarProvider)

			keyFilePath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
			if keyFilePath == "" {
				keyFilePath = "/gcp/sa.json"
			}

			pc = &sidecar.GCPProviderConfig{
				Path:                   "gcp",
				StaticAccount:          *flagSidecarVaultStaticAccount,
				SecretType:             *flagSidecarSecretType,
				KeyFileDestinationPath: keyFilePath,
			}
			kubeAuthRole = *flagSidecarVaultStaticAccount
		case "github":
			mustBeSet("vault-role", *flagSidecarVaultRole, sidecarProvider)
			mustBeSet("github-permission-set", *flagSidecarGitHubPermissionSet, sidecarProvider)

			tokenFilePath := os.Getenv("GITHUB_TOKEN_FILE")
			if tokenFilePath == "" {
				tokenFilePath = "/var/run/secrets/github/token"
			}

			pc = &sidecar.GitHubProviderConfig{
				Path:                     "github",
				PermissionSet:            *flagSidecarGitHubPermissionSet,
				TokenFileDestinationPath: tokenFilePath,
			}
			kubeAuthRole = *flagSidecarVaultRole
		default:
			// Reached with no account at all, where usage is the answer, or with
			// a well formed account naming a provider this binary does not have.
			if sidecarProvider != "" {
				log.Error(nil, "Unsupported provider: "+sidecarProvider)
				os.Exit(1)
			}

			usage()
			return
		}

		if *flagSidecarDisableHTTP {
			if sidecarProvider != "aws" {
				log.Error(nil, "'disable-http' requires the aws provider.")
				os.Exit(1)
			}
			if os.Getenv("VKCC_AWS_CREDENTIALS_DIR") == "" {
				log.Error(nil, "'disable-http' requires 'VKCC_AWS_CREDENTIALS_DIR'.")
				os.Exit(1)
			}
		}

		sidecarConfig := &sidecar.Config{
			KubeAuthPath:   "kubernetes",
			KubeAuthRole:   kubeAuthRole,
			ListenAddress:  *flagSidecarListenAddr,
			OpsAddress:     *flagSidecarOpsAddr,
			ProviderConfig: pc,
			TokenPath:      *flagSidecarKubeTokenPath,
			DisableHTTP:    *flagSidecarDisableHTTP,
		}

		s, err := sidecar.New(sidecarConfig)
		if err != nil {
			log.Error(err, "error creating sidecar")
			os.Exit(1)
		}

		if err := s.Run(ctx); err != nil {
			log.Error(err, "error running sidecar")
			os.Exit(1)
		}

		return
	}

	usage()
	return
}
