locals {
  name = "${var.environment}_gcp_${var.kube_namespace}_${var.kube_sa_name}"
}

resource "vault_kubernetes_auth_backend_role" "app" {
  role_name                        = local.name
  backend                          = var.kubernetes_auth_backend
  bound_service_account_names      = [var.kube_sa_name]
  bound_service_account_namespaces = [var.kube_namespace]
  token_ttl                        = var.token_ttl
  token_policies                   = ["default", local.name]
}

data "vault_policy_document" "app" {
  rule {
    path         = "${var.gcp_secret_backend}/roleset/${local.name}"
    capabilities = ["read"]
  }
  rule {
    path         = "${var.gcp_secret_backend}/token/${local.name}"
    capabilities = ["create", "read", "update", "delete", "list"]
  }
  rule {
    path         = "${var.gcp_secret_backend}/roleset/${local.name}/token"
    capabilities = ["create", "read", "update", "delete", "list"]
  }
  # We do not use access keys directly but still allow the call, even though
  # the roleset will not be able to produce an access key, since the roleset
  # is a different type.
  rule {
    path         = "${var.gcp_secret_backend}/key/${local.name}"
    capabilities = ["create", "read", "update", "delete", "list"]
  }
}

resource "vault_policy" "app" {
  name   = local.name
  policy = data.vault_policy_document.app.hcl
}

resource "vault_gcp_secret_roleset" "app" {
  backend      = var.gcp_secret_backend
  roleset      = local.name
  secret_type  = "access_token"
  project      = var.gcp_project
  token_scopes = ["https://www.googleapis.com/auth/cloud-platform"]

  dynamic "binding" {
    for_each = var.gcp_bindings
    content {
      resource = binding.value.resource
      roles    = binding.value.roles
    }
  }
}
