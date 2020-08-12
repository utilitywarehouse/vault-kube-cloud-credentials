# vault-kube-cloud-credentials

This is a system for retrieving cloud IAM credentials from Vault for use in
Kubernetes.

It's comprised of two parts:

- An operator which will create a login role and a secret in Vault based on
  service account annotations
- A sidecar which retrieves the credentials from vault and serves them over
  http, acting as a metadata endpoint for the given cloud provider

## Operator

### Requirements

- A Vault server with:
  - Kubernetes auth method, enabled and configured
  - AWS secrets engine, enabled and configured

### Usage

Refer to the [example](manifests/operator/) for a reference Kubernetes deployment.

Annotate your service accounts and the operator will create the corresponding
login role and aws secret role in Vault at
`auth/kubernetes/roles/<prefix>_aws_<namespace>_<name>` and
`aws/role/<prefix>_aws_<namespace>_<name>` respectively, where `<prefix>` is the
string supplied with the `-prefix` flag (default: `vkcc`)

```
apiVersion: v1
kind: ServiceAccount
metadata:
  name: foobar
  annotations:
    uw.systems/aws-role: "arn:aws:iam::000000000000:role/some-role-name"
```

### Config file

You can control which service accounts can assume which roles based on their
namespace by passing a yaml file to the operator with the flag `-config-file`.

For example, the following configuration allows service accounts in `kube-system` 
and namespaces prefixed with `system-` to assume roles under the `sysadmin/*` path,
roles that begin with `sysadmin-` or a specific `org/s3-admin` role in the accounts
`000000000000` and `111111111111`.

```
aws:
  rules:
    - namespacePatterns:
        - kube-system
        - system-*
      roleNamePatterns:
       - sysadmin-*
       - sysadmin/*
       - org/s3-admin
      accountIDs:
        - 000000000000
        - 111111111111
```

If `accountIDs` is omitted or empty then any account is permitted. The other two
parameters are required.

The pattern matching supports [shell file name
patterns](https://golang.org/pkg/path/filepath/#Match).

## Sidecars

### Usage

Refer to the [examples](manifests/examples/) for reference Kubernetes deployments.

Supported providers (secret engines):

- `aws`
- `gcp`

For `aws`:

```
./vault-kube-cloud-credentials aws-sidecar \
  -kube-auth-role=<kubernetes auth role> \
  -aws-role=<aws secret role>
```

And `gcp`:

```
./vault-kube-cloud-credentials gcp-sidecar \
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
