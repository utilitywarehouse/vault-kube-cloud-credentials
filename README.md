# vault-kube-cloud-credentials

This is a specialised sidecar for Kubernetes pods that fetches credentials for a
cloud provider from [Vault](https://www.vaultproject.io) and serves them via
http to be consumed by the cloud-provider's SDK.

It is intended to be used with a Vault setup like [this](https://github.com/utilitywarehouse/vault-manifests).
The sidecar logs with Vault using its Kubernetes Service Account, requests
credentials from a secrets engine and serves the acquired credentials via http.
The sidecar detects the lease expiration and keeps the served credentials
updated and valid.

## Usage

Refer to the [example](example/) for a reference Kubernetes deployment.

Supported providers (secret engines):

- `aws`
- `gcp`

## Environment variables

Configuration is provided to the sidecar via the environment.

Required:

- `VKAC_KUBE_AUTH_ROLE`: kubernetes auth backend role used to login

and one of the following:

- `VKAC_AWS_SECRET_ROLE`: aws secret backend role to retrieve credentials with
- `VKAC_GCP_SECRET_ROLESET`: gcp secret backend roleset to retrieve credentials with

These variables determine which secret engine is used and the format of the
credentials which are served over http.

Optional:

- `VKAC_AWS_SECRET_BACKEND_PATH`: path of the aws secret backend (default: `aws`)
- `VKAC_AWS_SECRET_ROLE_ARN`: the ARN of the role to assume. This is required
  when there is more than one `role_arn` configured against the backend role
  (not set by default)
- `VKAC_GCP_SECRET_BACKEND_PATH`: path of the gcp secret backend (default: `gcp`)
- `VKAC_KUBE_AUTH_BACKEND_PATH`: path of the kubernetes auth backend (default: `kubernetes`)
- `VKAC_KUBE_SA_TOKEN_PATH`: path to a file containing the Kubernetes service account token (default: `/var/run/secrets/kubernetes.io/serviceaccount/token`)
- `VKAC_LISTEN_HOST`: host to bind to (default: `127.0.0.1`)
- `VKAC_LISTEN_PORT`: port to bind to (default: `8000`)

Additionally, you can use any of the [environment variables supported by the Vault
client](https://www.vaultproject.io/docs/commands/#environment-variables), most
applicably:

- `VAULT_ADDR`: the address of the Vault server (default: `https://127.0.0.1:8200`)
- `VAULT_CACERT`: path to a CA certificate file used to verify the Vault server's certificate
