module github.com/utilitywarehouse/vault-kube-cloud-credentials

go 1.16

require (
	github.com/aws/aws-sdk-go v1.40.10
	github.com/go-logr/logr v0.4.0
	github.com/gorilla/mux v1.8.0
	github.com/hashicorp/go-rootcerts v1.0.2
	github.com/hashicorp/vault v1.8.0
	github.com/hashicorp/vault-plugin-auth-kubernetes v0.10.1
	github.com/hashicorp/vault/api v1.1.2-0.20210713235431-1fc8af4c041f
	github.com/hashicorp/vault/sdk v0.2.2-0.20210713235431-1fc8af4c041f
	github.com/prometheus/client_golang v1.11.0
	github.com/stretchr/testify v1.7.0
	github.com/utilitywarehouse/go-operational v0.0.0-20190722153447-b0f3f6284543
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/api v0.21.3
	k8s.io/apimachinery v0.21.3
	k8s.io/client-go v0.21.3
	sigs.k8s.io/controller-runtime v0.9.0-alpha.1
)
