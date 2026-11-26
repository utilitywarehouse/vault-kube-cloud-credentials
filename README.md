# vault-kube-cloud-credentials

Vault Kube Cloud Credentials (lovingly VKCC - shorthand) - is an application
that runs in two modes - **operator** and **sidecar**.

As an **operator** - it watches for Kubernetes annotations in ServiceAccounts
and creates Vault objects - mapping that SA to the Cloud provider role or
service account value inside the annotation.

It uses a config file to define which namespaces are allowed to map to which
cloud provider roles/service accounts.

Cloud providers supported:

- AWS
- GCP

As a **sidecar** - it runs next to you application container and exposes HTTP
endpoint that contains cloud provider credentials. Libraries such as AWS SDK
can consume such HTTP endpoint to always have up-to-date credentials.
In case if you would like to get GCP service account key file instead, the
sidecar will fetch the key and make the file available to your application
container.

Cloud providers supported:

- AWS
- GCP

The sidecar also supports a **github** provider. It fetches a token from
`vault-plugin-secrets-github` for a configured permission set and writes it to
a file (path from `GITHUB_TOKEN_FILE`, default `/var/run/secrets/github/token`).

## Operator

### Requirements

- A Vault server with:
  - Kubernetes auth method, enabled and configured
  - AWS or GCP secrets engine, enabled and configured

### Usage

```
./vault-kube-cloud-credentials operator -provider={aws|gcp} [-config-file=PATH_TO_CONFIG_FILE]
```

Refer to the [example](manifests/operator/) for a reference Kubernetes
deployment.

Annotate your ServiceAccounts and the operator will create the corresponding
login role and AWS secret role at
`auth/kubernetes/roles/<prefix>_aws_<namespace>_<name>` and
`aws/role/<prefix>_aws_<namespace>_<name>`  
or, in case with GCP, will create a GCP static account at
`gcp/static-account/<prefix>_gcp_<namespace>_<name>` respectively, where
`<prefix>` is the value of `prefix` in the configuration file (default: `vkcc`).

AWS kube serviceAccount example:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: foobar
  annotations:
    vault.uw.systems/aws-role: "arn:aws:iam::000000000000:role/some-role-name"
    vault.uw.systems/default-sts-ttl: "6h"
```

optional `default-sts-ttl` annotation, can be used to set custom ttl on aws token and lease time.
Valid Range for this value is [Minimum value of 900s, Maximum value of 43200s](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html).
this value should be lower then `maxLeaseTTL` of vault or `max_lease_ttl` on AWS backend config otherwise it will be capped at maxTTL.

_if custom TTL is set then make sure `max_session_duration` is updated in assume Role policy for the role if required, as it defaults to `1h`._

The annotation accepts a comma separated list of ARNs, so one ServiceAccount
can map to several IAM roles:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: foobar
  annotations:
    vault.uw.systems/aws-role: "arn:aws:iam::000000000000:role/some-role-name,arn:aws:iam::000000000000:role/some-other-role-name"
```

The order matters. By default, the sidecar serves the first ARN on
`GET /credentials`. When `VKCC_AWS_CREDENTIALS_DIR` is set, it also writes that
role as `[profile default]`. The operator rejects empty, invalid, and duplicate
ARNs. It also checks every ARN against `aws.rules` for the namespace. If one
isn't allowed, the operator doesn't admit the ServiceAccount and writes nothing
to Vault.

_GCP service account keys and access tokens have a default TTL of 1 hour._

GCP kube serviceAccount example:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: foobar
  annotations:
    vault.uw.systems/gcp-service-account: "foo@bar.iam.gserviceaccount.com"
    vault.uw.systems/gcp-token-scopes: "https://www.googleapis.com/auth/cloud-platform"
```

If you specify `vault.uw.systems/gcp-token-scopes` annotation you will receive
GCP credentials in a form of access tokens. You can specify multiple scopes
separated by comma.
If that annotation is omitted the sidecar will fetch service account key in a
form of JSON file and save that to the path specified in `GOOGLE_APPLICATION_CREDENTIALS`
env var (`/gcp/sa.json` by default).
`vault.uw.systems/default-gcp-key-ttl` annotation can be used to set initial lease
ttl for the key. if this key is not renewed and expired then vault will delete key from GCP.

### Config file

The operator can be configured by a yaml file passed to the operator with the flag
`-config-file`.

If no file is provided then the defaults are used. Any omitted values revert to
their defaults.

Refer to the `defaultFileConfig` in [operator/config.go](operator/config.go).

#### Rules

You can control which service accounts can assume/use which roles based on their
namespace by setting rules under `aws.rules` and `gcp.rules`.

For example, the following configuration allows service accounts in `kube-system`
and namespaces prefixed with `system-` to assume roles under the `sysadmin/*` path,
roles that begin with `sysadmin-` or a specific `org/s3-admin` role in the accounts
`000000000000` and `111111111111`.

```yaml
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

The following GCP configuration allows service accounts in `kube-system` get
access to `foo@bar.iam.gserviceaccount.com` GCP service account and all accounts
that start with `baz` in `bar` project.

```yaml
gcp:
  rules:
    - namespacePatterns:
        - kube-system
      serviceAccountEmailPatterns:
        - foo@bar.iam.gserviceaccount.com
        - baz-*@bar.iam.gserviceaccount.com
```

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
- `github`

```
# AWS
./vault-kube-cloud-credentials sidecar \
    -vault-role=<prefix>_<provider>_<namespace>_<serviceaccount>
# GCP
./vault-kube-cloud-credentials sidecar \
    -vault-static-account=<prefix>_<provider>_<namespace>_<serviceaccount> \
    -secret-type=access_token
# GitHub
./vault-kube-cloud-credentials sidecar \
    -vault-role=<prefix>_github_<permission-set> \
    -github-permission-set=<permission-set>
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

### AWS

By default, the sidecar serves credentials on `GET /credentials` at its listen
address (`127.0.0.1:8098` by default), in the JSON shape the [AWS container
credentials provider](https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html)
expects. Point `AWS_CONTAINER_CREDENTIALS_FULL_URI` at
`http://127.0.0.1:8098/credentials` to use it.

Set `VKCC_AWS_CREDENTIALS_DIR` to a writable directory and the sidecar also
writes one JSON file per role, plus a shared `config` file with one AWS profile
per role. Point the workload at `<dir>/config` with `AWS_CONFIG_FILE`, then
choose a profile with `AWS_PROFILE`. Set `-disable-http` (or
`VKCC_DISABLE_HTTP=true`) to serve profiles only; this needs
`VKCC_AWS_CREDENTIALS_DIR`.

- **Several roles:** list more than one ARN in the ServiceAccount annotation.
  Put a comma between ARNs. A comma starts a new ARN only when the next part
  begins with `arn:`, so commas inside a role name still work. The first ARN is
  the default role: when HTTP is enabled, `GET /credentials` serves only that
  role, and when profiles are enabled, they include every role that has
  credentials. If a secondary role fails, the sidecar keeps serving the default
  role and the other profiles. It retries the failed role within 3 minutes, or
  sooner if its credentials expire, and keeps serving any previous credentials
  until they expire.
  Roll the operator out before the sidecar. Until its policy can read
  `aws/roles/<name>`, the sidecar can't discover the ARNs. A role with one ARN
  still works: the sidecar falls back to Vault's default credentials. A role
  with several ARNs won't get credentials.
- **Profiles:** when profiles are enabled, the first role has two profiles:
  `default` and a profile named after the role. If the sidecar can't read the
  role list, it creates only `default`. Each other role gets a profile named
  after the last segment of its ARN. If two roles have the same name, the
  sidecar adds the account ID or the role's position in the list to keep the
  names unique.
- **Setup:** the sidecar needs write access to `VKCC_AWS_CREDENTIALS_DIR`; the
  workload needs read access. The files are mode `0640`, so set `fsGroup` on the
  workload. `AWS_CONFIG_FILE` overrides any config file the workload already
  has. The workload image needs `sh` and `cat` to run `credential_process`. If
  you use boto3, set `AWS_DEFAULT_REGION`. Keep the Vault TTL above 25 minutes.

### GitHub

The `github` provider reads a token from `vault-plugin-secrets-github` and writes it to
the file named by `GITHUB_TOKEN_FILE`, rather than serving an HTTP endpoint, because
the tooling that consumes it expects a token value.

**The pod must set `securityContext.fsGroup` for the workload to read the token file; any
value works.**

The operator creates no Vault objects for this provider, so the following have to be in
place before the sidecar starts:

- A Kubernetes auth role at
  `auth/kubernetes/role/<prefix>_github_<namespace>_<serviceaccount>`, bound to that
  namespace and service account, carrying the `github_<permission-set>` policy that
  [sys-vault-repo-permission-sets](https://github.com/utilitywarehouse/terraform/tree/master/github/sys-vault-repo-permission-sets)
  creates
- A writable directory at the token path, normally an `emptyDir` mounted at
  `/var/run/secrets/github`. The directory does not exist in the image, so the sidecar
  cannot write the token without it. It has to be mounted into the workload container as
  well
- The workload re-reading the token file. Installation tokens expire after an hour, so a
  workload that reads the token once at startup stops working after the first expiry

One sidecar serves one permission set. A workload that needs two has to run a second
sidecar with its own `GITHUB_TOKEN_FILE`, `-listen-address` and `-operational-address`,
as containers in a pod share a network namespace.

### Renewal

The sidecar will retrieve new credentials after 1/3 of the current TTL has
elapsed. So, if the credentials are valid for an hour then the sidecar will
attempt to fetch a new set after about 20 minutes. A random jitter is applied
to the refresh period to avoid tight synchronisation between multiple sidecar
instances.

Credentials are also renewed as soon as a replacement login token is issued,
since vault revokes the leases created by the old token: without it the
credentials it minted would be unusable until the next refresh.

If the refresh fails then the sidecar will continue to make attempts at renewal,
with an exponential backoff.

### CA Reload

Both `operator` and `sidecar` support hot reload of vault CA cert for secure communication.
CA is updated before making vault API Calls. Following envs are supported.

- `VAULT_CACERT`: value should be path to a PEM-encoded certificate file or bundle.
  Takes precedence over CACertificate and CAPath.
- `VAULT_CAPATH`: value should be path to a directory populated with PEM-encoded certificates.
- `VAULT_CAURL`: value should be URL which returns a PEM-encoded certificate or bundle as body.
  Takes precedence over CAPath.

