## Usage

```hcl
module "vault_gcp_binding" {
  source = "github.com/utilitywarehouse/vault-kube-cloud-credentials/terraform/terraform-vault-gcp-binding"

  kube_namespace = "example-namespace"
  kube_sa_name   = "example"
  gcp_project    = "example-project"

  gcp_bindings = [
    {
      resource = "example-resource"
      roles = ["example-role"]
    }
  ]
}
```

Check `variables.tf` for detailed descriptions and optional variables.
