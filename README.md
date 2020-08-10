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

For `aws`:

```
./vault-kube-cloud-credentials \
  -aws-sidecar \
  -kube-auth-role=<kubernetes auth role> \
  -aws-role=<aws secret role>
```

And `gcp`:

```
./vault-kube-cloud-credentials \
  -gcp-sidecar \
  -kube-auth-role=<kubernetes auth role> \
  -gcp-roleset=<gcp secret roleset>
```

Refer to the usage for more options:

```
./vault-kube-cloud-credentials -h
```

Additionally, you can use any of the [environment variables supported by the Vault
client](https://www.vaultproject.io/docs/commands/#environment-variables), most
applicably:

- `VAULT_ADDR`: the address of the Vault server (default: `https://127.0.0.1:8200`)
- `VAULT_CACERT`: path to a CA certificate file used to verify the Vault server's certificate
