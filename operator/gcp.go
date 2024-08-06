package operator

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"text/template"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const (
	gcpSAAnnotation    = "vault.uw.systems/gcp-service-account"
	gcpScopeAnnotation = "vault.uw.systems/gcp-token-scopes"
)

var gcpPolicyTemplate = `
path "{{ .GCPPath }}/static-account/{{ .Name }}" {
  capabilities = ["read"]
}
path "{{ .GCPPath }}/static-account/{{ .Name }}/token" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "{{ .GCPPath }}/static-account/{{ .Name }}/key" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "{{ .GCPPath }}/token/{{ .Name }}" {
capabilities = ["create", "read", "update", "delete", "list"]
}
path "{{ .GCPPath }}/key/{{ .Name }}" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
`

// GCPRules are a collection of rules.
type GCPRules []GCPRule

// allow returns true if there is a rule in the list of rules which allows
// a service account in the given namespace to use the given gcp service account
// Rules are evaluated in order and allow returns true for the first matching
// rule in the list
func (gcr GCPRules) allow(namespace, serviceAccount string) (bool, error) {
	err := validateServiceAccEmail(serviceAccount)
	if err != nil {
		return false, err
	}

	for _, r := range gcr {
		allowed, err := r.allows(namespace, serviceAccount)
		if err != nil {
			return false, err
		}
		if allowed {
			return true, nil
		}
	}

	return len(gcr) == 0, nil
}

// GCPRule
type GCPRule struct {
	NamespacePatterns       []string `yaml:"namespacePatterns"`
	ServiceAccEmailPatterns []string `yaml:"serviceAccountEmailPatterns"`
}

func validateServiceAccEmail(email string) error {
	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.gserviceaccount\.com$`

	re := regexp.MustCompile(pattern)

	if !re.MatchString(email) {
		return fmt.Errorf("invalid service account email format")
	}

	return nil
}

// allows checks whether this rule allows a namespace to use the given gcp
// service account
func (gcr *GCPRule) allows(namespace, serviceAccount string) (bool, error) {
	namespaceAllowed, err := matchesNamespace(namespace, gcr.NamespacePatterns)
	if err != nil {
		return false, err
	}

	serviceAccountAllowed, err := gcr.matchesSAEmail(serviceAccount)
	if err != nil {
		return false, err
	}

	return namespaceAllowed && serviceAccountAllowed, nil
}

// matchesSAEmail returns true if the rule allows the given service account
func (gcr *GCPRule) matchesSAEmail(roleName string) (bool, error) {
	for _, rp := range gcr.ServiceAccEmailPatterns {
		match, err := filepath.Match(rp, roleName)
		if err != nil {
			return false, err
		}
		if match {
			return true, nil
		}
	}

	return false, nil
}

// GCPOperatorConfig provides configuration when creating a new Operator
type GCPOperatorConfig struct {
	*Config
	GCPPath string
	Rules   GCPRules
}

// GCPOperator is responsible for creating Kubernetes auth roles and GCP static
// accounts based on ServiceAccount annotations
type GCPOperator struct {
	*GCPOperatorConfig
	log  logr.Logger
	tmpl *template.Template
}

// NewGCPOperator returns a configured GCPOperator
func NewGCPOperator(config *GCPOperatorConfig) (*GCPOperator, error) {
	tmpl, err := template.New("policy").Parse(gcpPolicyTemplate)
	if err != nil {
		return nil, err
	}

	gcr := &GCPOperator{
		GCPOperatorConfig: config,
		log:               log.WithName("gcp"),
		tmpl:              tmpl,
	}

	return gcr, nil
}

// Start is ran when the manager starts up. We're using it to clear up orphaned
// serviceaccounts that could have been missed while the operator was down
func (o *GCPOperator) Start(ctx context.Context) error {
	o.log.Info("garbage collection started")

	// GCP static accounts
	gcpStaticAccountsList, err := o.VaultClient.Logical().List(o.GCPPath + "/static-account/")
	if err != nil {
		return err
	}
	if gcpStaticAccountsList != nil {
		if keys, ok := gcpStaticAccountsList.Data["keys"].([]interface{}); ok {
			err = o.garbageCollect(keys)
			if err != nil {
				return err
			}
		}
	}

	// Kubernetes auth roles
	kubeAuthRoleList, err := o.VaultClient.Logical().List("auth/" + o.KubernetesAuthBackend + "/role/")
	if err != nil {
		return err
	}
	if kubeAuthRoleList != nil {
		if keys, ok := kubeAuthRoleList.Data["keys"].([]interface{}); ok {
			err = o.garbageCollect(keys)
			if err != nil {
				return err
			}
		}
	}

	// Policies
	policies, err := o.VaultClient.Logical().List("sys/policy")
	if err != nil {
		return err
	}
	if policies != nil {
		if keys, ok := policies.Data["keys"].([]interface{}); ok {
			err = o.garbageCollect(keys)
			if err != nil {
				return err
			}
		}
	}

	o.log.Info("garbage collection finished")

	return nil
}

// Reconcile ensures that a ServiceAccount is able to login at
// auth/kubernetes/role/<prefix>_gcp_<namespace>_<name> and retrieve GCP credentials at
// gcp/static-account/<prefix>_gcp_<namespace>_<name> for the service account
// specified in the vault.uw.systems/gcp-service-account annotation
func (o *GCPOperator) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Reload vault configuration from the environment, this is primarily
	// done to pick up CA cert rotations
	if err := o.VaultConfig.ReadEnvironment(); err != nil {
		return ctrl.Result{}, err
	}

	// Check if the service account exists. If it doesn't then it's been
	// deleted and we can remove it from vault
	del := false
	serviceAccount := &corev1.ServiceAccount{}
	err := o.KubeClient.Get(ctx, req.NamespacedName, serviceAccount)
	if err != nil && errors.IsNotFound(err) {
		del = true
	} else if err != nil {
		return ctrl.Result{}, err
	}

	// If the service account exists but isn't valid for reconciling that means
	// it could have previously been valid but the annotation has since been
	// removed or changed to a value that violates the rules described in
	// the config file. In which case it should be removed from vault.
	serviceAccountEmail := serviceAccount.Annotations[gcpSAAnnotation]

	if !o.admitEvent(req.Namespace, serviceAccountEmail) {
		del = true
	}

	// Delete the vault objects
	if del {
		return ctrl.Result{}, o.removeFromVault(req.Namespace, req.Name)
	}

	tokenScopes := serviceAccount.Annotations[gcpScopeAnnotation]

	switch tokenScopes {
	case "":
		err = o.writeToVault(req.Namespace, req.Name, map[string]interface{}{
			"service_account_email": serviceAccountEmail,
			"secret_type":           "service_account_key",
		})
	default:
		err = o.writeToVault(req.Namespace, req.Name, map[string]interface{}{
			"service_account_email": serviceAccountEmail,
			"secret_type":           "access_token",
			"token_scopes":          tokenScopes,
		})
	}

	return ctrl.Result{}, err
}

// admitEvent controls whether an event should be reconciled or not based on the
// presence of a service account and whether the gcp service account is
// permitted for this namespace by the rules laid out in the config file
func (o *GCPOperator) admitEvent(namespace, serviceAccount string) bool {
	if serviceAccount == "" {
		return false
	}

	if serviceAccount != "" {
		allowed, err := o.Rules.allow(namespace, serviceAccount)
		if err != nil {
			o.log.Error(err, "error matching service account against rules for namespace", "role", serviceAccount, "namespace", namespace)
		} else if allowed {
			return true
		}
	}

	return false
}

// SetupWithManager adds the operator as a runnable and a reconciler on the controller-runtime manager. It also
// applies event filters that ensure Reconcile only processes relevant ServiceAccount events.
func (o *GCPOperator) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.Add(o); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ServiceAccount{}).
		WithEventFilter(predicate.Funcs{
			CreateFunc: func(e event.CreateEvent) bool {
				return o.admitEvent(e.Object.GetNamespace(), e.Object.GetAnnotations()[gcpSAAnnotation])
			},
			DeleteFunc: func(e event.DeleteEvent) bool {
				return o.admitEvent(e.Object.GetNamespace(), e.Object.GetAnnotations()[gcpSAAnnotation])
			},
			GenericFunc: func(e event.GenericEvent) bool {
				return o.admitEvent(e.Object.GetNamespace(), e.Object.GetAnnotations()[gcpSAAnnotation])
			},
			UpdateFunc: func(e event.UpdateEvent) bool {
				// Update events are a special case, because we want to remove roles in
				// vault when the annotation is removed or changed to an invalid value.
				return e.ObjectOld.GetAnnotations()[gcpSAAnnotation] != e.ObjectNew.GetAnnotations()[gcpSAAnnotation]
			},
		}).
		Complete(o)
}

// renderGCPPolicyTemplate injects the provided name into a policy allowing access
// to the corresponding GCP service account
func (o *GCPOperator) renderGCPPolicyTemplate(name string) (string, error) {
	var policy bytes.Buffer
	if err := o.tmpl.Execute(&policy, struct {
		GCPPath string
		Name    string
	}{
		GCPPath: o.GCPPath,
		Name:    name,
	}); err != nil {
		return "", err
	}

	return policy.String(), nil
}

// writeToVault creates the kubernetes auth role and vault static account
// required for the given serviceAccount to login and use the provided gcp
// service account
func (o *GCPOperator) writeToVault(namespace, serviceAccount string, data map[string]interface{}) error {
	n := name(o.Prefix, "_gcp_", namespace, serviceAccount)

	// Create policy for kubernetes auth role
	policy, err := o.renderGCPPolicyTemplate(n)
	if err != nil {
		return err
	}
	if _, err := o.VaultClient.Logical().Write("sys/policy/"+n, map[string]interface{}{
		"policy": policy,
	}); err != nil {
		return err
	}
	o.log.Info("Wrote policy", "namespace", namespace, "serviceaccount", serviceAccount, "key", n)

	// Create kubernetes auth backend role
	if _, err := o.VaultClient.Logical().Write("auth/"+o.KubernetesAuthBackend+"/role/"+n, map[string]interface{}{
		"bound_service_account_names":      []string{serviceAccount},
		"bound_service_account_namespaces": []string{namespace},
		"policies":                         []string{"default", n},
		"ttl":                              900,
	}); err != nil {
		return err
	}
	o.log.Info("Wrote kubernetes auth backend role", "namespace", namespace, "serviceaccount", serviceAccount, "key", n)

	// Create gcp static account
	if _, err := o.VaultClient.Logical().Write(o.GCPPath+"/static-account/"+n, data); err != nil {
		return err
	}
	o.log.Info("Wrote GCP static account", "namespace", namespace, "serviceaccount", serviceAccount, "key", n)

	return nil
}

// removeFromVault removes the items from vault for the provided serviceAccount
func (o *GCPOperator) removeFromVault(namespace, serviceAccount string) error {
	n := name(o.Prefix, "_gcp_", namespace, serviceAccount)

	_, err := o.VaultClient.Logical().Delete(o.GCPPath + "/static-account/" + n)
	if err != nil {
		return err
	}
	o.log.Info("Deleted GCP backend role", "namespace", namespace, "serviceaccount", serviceAccount, "key", n)

	_, err = o.VaultClient.Logical().Delete("auth/" + o.KubernetesAuthBackend + "/role/" + n)
	if err != nil {
		return err
	}
	o.log.Info("Deleted Kubernetes auth role", "namespace", namespace, "serviceaccount", serviceAccount, "key", n)

	_, err = o.VaultClient.Logical().Delete("sys/policy/" + n)
	if err != nil {
		return err
	}
	o.log.Info("Deleted policy", "namespace", namespace, "serviceaccount", serviceAccount, "key", n)

	return nil
}

// garbageCollect iterates through a list of keys from a vault list, finds items
// managed by the operator and removes them if they don't have a corresponding
// serviceaccount in Kubernetes
func (o *GCPOperator) garbageCollect(keys []interface{}) error {
	for _, k := range keys {
		key, ok := k.(string)
		if !ok {
			continue
		}

		namespace, name, parsed := parseKey(key, o.Prefix, "_gcp_")
		if parsed {
			has, err := o.hasServiceAccount(namespace, name)
			if err != nil {
				return err
			}
			if !has {
				// Delete
				err := o.removeFromVault(namespace, name)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// hasServiceAccount checks if a managed service account exists for the given
// namespace+name combination, annotated with a correct and valid annotation
func (o *GCPOperator) hasServiceAccount(namespace, name string) (bool, error) {
	serviceAccountList := &corev1.ServiceAccountList{}
	err := o.KubeClient.List(context.Background(), serviceAccountList)
	if err != nil {
		return false, err
	}

	for _, serviceAccount := range serviceAccountList.Items {
		if serviceAccount.Namespace == namespace &&
			serviceAccount.Name == name &&
			o.admitEvent(
				serviceAccount.Namespace,
				serviceAccount.Annotations[gcpSAAnnotation],
			) {
			return true, nil
		}
	}

	return false, nil
}
