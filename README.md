# vault-kube-aws-credentials

This is a specialised sidecar for Kubernetes pods that fetches AWS credentials from [Vault](https://www.vaultproject.io) and serves them via http to be consumed by the AWS SDK.

It is intended to be used with a Vault setup like [this](https://github.com/utilitywarehouse/vault-manifests). The sidecar logs with Vault using its Kubernetes Service Account, requests credentials from an AWS secrets engine and serves the acquired credentials via http. The sidecar detects the lease expiration and keeps the served credentials updated and valid.

## Usage

Refer to [example/aws-probe.yaml](example/aws-probe.yaml) for a reference Kubernetes deployment.

## Environment variables

Configuration is provided to the sidecar via the environment.

Required:

- `VKAC_AWS_SECRET_ROLE`: aws secret backend role to retrieve credentials with
- `VKAC_KUBE_AUTH_ROLE`: kubernetes auth backend role used to login

Optional:

- `VKAC_AWS_SECRET_BACKEND_PATH`: path of the aws secret backend (default: `aws`)
- `VKAC_KUBE_AUTH_BACKEND_PATH`: path of the kubernetes auth backend (default: `kubernetes`)
- `VKAC_KUBE_SA_TOKEN_PATH`: path to a file containing the Kubernetes service account token (default: `/var/run/secrets/kubernetes.io/serviceaccount/token`)
- `VKAC_LISTEN_HOST`: host to bind to (default: `127.0.0.1`)
- `VKAC_LISTEN_PORT`: port to bind to (default: `8000`)

Additionally, you can use any of the [environment variables supported by the Vault
client](https://www.vaultproject.io/docs/commands/#environment-variables), most applicably:

- `VAULT_ADDR`: the address of the Vault server (default: `https://127.0.0.1:8200`)
- `VAULT_CACERT`: path to a CA certificate file used to verify the Vault server's certificate
