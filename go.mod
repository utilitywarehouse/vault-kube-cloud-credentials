module github.com/utilitywarehouse/vault-kube-cloud-credentials

go 1.14

require (
	github.com/gorilla/mux v1.7.4
	github.com/hashicorp/vault v1.5.0
	github.com/hashicorp/vault-plugin-auth-kubernetes v0.7.0
	github.com/hashicorp/vault/api v1.0.5-0.20200630205458-1a16f3c699c6
	github.com/hashicorp/vault/sdk v0.1.14-0.20200718021857-871b5365aa35
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/prometheus/client_golang v1.6.0 // indirect
	github.com/stretchr/testify v1.5.1
	github.com/utilitywarehouse/go-operational v0.0.0-20190722153447-b0f3f6284543
	gotest.tools/v3 v3.0.2 // indirect
	k8s.io/api v0.18.6
	k8s.io/apimachinery v0.18.6
	k8s.io/client-go v0.18.6
	sigs.k8s.io/controller-runtime v0.6.2
)

replace github.com/hashicorp/vault/api => github.com/hashicorp/vault/api v0.0.0-20200718022110-340cc2fa263f
