# vault-kube-cloud-credentials

[![Build Status](https://drone.prod.merit.uw.systems/api/badges/utilitywarehouse/vault-kube-cloud-credentials/status.svg)](https://drone.prod.merit.uw.systems/utilitywarehouse/vault-kube-cloud-credentials)

<!-- vim-markdown-toc GFM -->

* [Operator](#operator)
	* [Requirements](#requirements)
	* [Usage](#usage)
	* [Config file](#config-file)
	* [Role names](#role-names)
* [Sidecars](#sidecars)
	* [Usage](#usage-1)
	* [Renewal](#renewal)

<!-- vim-markdown-toc -->

Vault Kube Cloud Credentials (lovingly VKCC - shorthand) - is an application
that runs in two modes - **operator** and **sidecar**.

As an **operator** - it watches for Kubernetes annotations in ServiceAccounts
and creates Vault objects - mapping that SA to the Cloud provider role value
inside the annotation.

It uses a config file to define which namespaces are allowed to map to which
cloud provider roles.

Cloud providers supported:
  - AWS

GCP - needs to be configured manually via a Terraform module:
[terraform/terraform-vault-gcp-binding](terraform/terraform-vault-gcp-binding)

As a **sidecar** - it runs next to you application container and exposes HTTP
endpoint that contains cloud provider credentials. Libraries such as AWS SDK
can consume such HTTP endpoint to always have up-to-date credentials.

Cloud providers supported:
  - AWS
  - GCP

## Operator

### Requirements

- A Vault server with:
  * Kubernetes auth method, enabled and configured
  * AWS secrets engine, enabled and configured

### Usage

Refer to the [example](manifests/operator/) for a reference Kubernetes
deployment.

Annotate your ServiceAccounts and the operator will create the corresponding
login role and AWS secret role in Vault at
`auth/kubernetes/roles/<prefix>_aws_<namespace>_<name>` and
`aws/role/<prefix>_aws_<namespace>_<name>` respectively, where `<prefix>` is the
string supplied with the `-prefix` flag (default: `vkcc`)

`-prefix` - is used to distinguish between multiple Vault deployments that
create roles in the same Provider account.

```
apiVersion: v1
kind: ServiceAccount
metadata:
  name: foobar
  annotations:
    uw.systems/aws-role: "arn:aws:iam::000000000000:role/some-role-name"
```

### Config file

You control which ServiceAccounts can assume which roles based on their
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

### Role names

The operator creates objects in Vault with the following name structure:

```
<prefix>_<provider>_<namespace>_<serviceaccount>
```

The `<prefix>` portion is defined by the `-prefix` flag (default: `vkcc`) and
serves as an identifier that can be useful when you have multiple Vault instances
creating resources in the same cloud provider account. The prefix used here may be
included in the name of the resources, allowing you to identify which Vault instance
they belong to.

Including `<provider>` avoids the potential for clashes in the situation where a
service account requires credentials from multiple providers.

The `<namespace>` and `<serviceaccount>` parts are self-explanatory.

## Sidecars

### Usage

Refer to the [examples](manifests/examples/) for reference Kubernetes deployments.

Or manifests to use with
https://github.com/utilitywarehouse/k8s-sidecar-injector at
[manifests/sidecar-injector](manifests/sidecar-injector)

Supported providers (secret engines):

- `aws`
- `gcp`

```
./vault-kube-cloud-credentials sidecar -vault-role=<prefix>_<provider>_<namespace>_<serviceaccount>
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

### Renewal

The sidecar will retrieve new credentials after 1/3 of the current TTL has
elapsed. So, if the credentials are valid for an hour then the sidecar will
attempt to fetch a new set after about 20 minutes. A random jitter is applied
to the refresh period to avoid tight synchronisation between multiple sidecar
instances.

If the refresh fails then the sidecar will continue to make attempts at renewal,
with an exponential backoff.
