package main

import (
	"flag"
	"github.com/utilitywarehouse/vault-kube-cloud-credentials/sidecar"
	"log"
	"os"
)

var (
	awsSidecar = flag.Bool("aws-sidecar", false, "Run the AWS sidecar")
	awsPath    = flag.String("aws-secret-backend", "aws", "AWS secret backend path")
	awsRoleArn = flag.String("aws-role-arn", "", "AWS role arn to assume")
	awsRole    = flag.String("aws-role", "", "AWS secret role (required when -aws-sidecar is set)")

	gcpSidecar = flag.Bool("gcp-sidecar", false, "Run the GCP sidecar")
	gcpPath    = flag.String("gcp-secret-backend", "gcp", "GCP secret backend path")
	gcpRoleSet = flag.String("gcp-roleset", "", "GCP roleset (required when -gcp-sidecar is set)")

	kubeAuthBackend = flag.String("kube-auth-backend", "kubernetes", "Kubernetes auth backend path")
	kubeAuthRole    = flag.String("kube-auth-role", "", "Kubernetes auth role (required when -aws-sidecar or -gcp-sidecar are set)")
	kubeTokenPath   = flag.String("kube-token-path", "/var/run/secrets/kubernetes.io/serviceaccount/token", "Path to the kubernetes serviceaccount token")

	listenHost = flag.String("listen-host", "127.0.0.1", "Host to listen on")
	listenPort = flag.String("listen-port", "8000", "Port to listen on")
)

func main() {
	flag.Parse()

	if len(os.Args) < 2 {
		flag.PrintDefaults()
		return
	}

	if *awsSidecar && *gcpSidecar {
		log.Fatal("Must only set -aws-sidecar or -gcp-sidecar, not both")
	}

	if *kubeAuthRole == "" {
		log.Fatal("Must set -kube-auth-role")
	}

	sidecarConfig := &sidecar.Config{
		KubeAuthPath:  *kubeAuthBackend,
		KubeAuthRole:  *kubeAuthRole,
		ListenAddress: *listenHost + ":" + *listenPort,
		TokenPath:     *kubeTokenPath,
	}

	if *awsSidecar {
		if *awsRole == "" {
			log.Fatal("Must set -aws-role with -aws-sidecar")
			return

		}
		sidecarConfig.ProviderConfig = &sidecar.AWSProviderConfig{
			AwsPath:    *awsPath,
			AwsRoleArn: *awsRoleArn,
			AwsRole:    *awsRole,
		}
	} else if *gcpSidecar {
		if *gcpRoleSet == "" {
			log.Fatal("Must set -gcp-roleset with -gcp-sidecar")
			return

		}
		sidecarConfig.ProviderConfig = &sidecar.GCPProviderConfig{
			GcpPath:    *gcpPath,
			GcpRoleSet: *gcpRoleSet,
		}
	} else {
		flag.PrintDefaults()
		return
	}

	if err := sidecar.New(sidecarConfig).Run(); err != nil {
		log.Fatal(err)
	}
}
