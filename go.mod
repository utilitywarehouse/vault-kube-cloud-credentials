module github.com/utilitywarehouse/vault-kube-cloud-credentials

go 1.15

require (
	cloud.google.com/go v0.66.0 // indirect
	github.com/Azure/go-autorest/autorest v0.11.6 // indirect
	github.com/aws/aws-sdk-go v1.34.29
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/go-logr/logr v0.2.1
	github.com/go-logr/zapr v0.2.0 // indirect
	github.com/golang/snappy v0.0.2 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/uuid v1.1.2 // indirect
	github.com/gophercloud/gophercloud v0.12.0 // indirect
	github.com/gorilla/mux v1.8.0
	github.com/hashicorp/go-retryablehttp v0.6.7 // indirect
	github.com/hashicorp/vault v1.5.0
	github.com/hashicorp/vault-plugin-auth-kubernetes v0.7.0
	github.com/hashicorp/vault/api v1.0.5-0.20200630205458-1a16f3c699c6
	github.com/hashicorp/vault/sdk v0.1.14-0.20200718021857-871b5365aa35
	github.com/imdario/mergo v0.3.11 // indirect
	github.com/mitchellh/mapstructure v1.3.3 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/prometheus/common v0.13.0 // indirect
	github.com/stretchr/testify v1.5.1
	github.com/utilitywarehouse/go-operational v0.0.0-20190722153447-b0f3f6284543
	go.uber.org/multierr v1.6.0 // indirect
	go.uber.org/zap v1.16.0 // indirect
	golang.org/x/crypto v0.0.0-20200820211705-5c72a883971a // indirect
	golang.org/x/sys v0.0.0-20200922070232-aee5d888a860 // indirect
	golang.org/x/time v0.0.0-20200630173020-3af7569d3a1e // indirect
	gomodules.xyz/jsonpatch/v2 v2.1.0 // indirect
	gopkg.in/yaml.v2 v2.3.0
	gotest.tools/v3 v3.0.2 // indirect
	k8s.io/api v0.18.8
	k8s.io/apiextensions-apiserver v0.18.8 // indirect
	k8s.io/apimachinery v0.18.8
	k8s.io/client-go v0.18.8
	k8s.io/klog/v2 v2.3.0 // indirect
	k8s.io/utils v0.0.0-20200912215256-4140de9c8800 // indirect
	sigs.k8s.io/controller-runtime v0.6.3
)

replace github.com/hashicorp/vault/api => github.com/hashicorp/vault/api v0.0.0-20200718022110-340cc2fa263f
