package operator

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"

	// Enables all auth methods for the kube client
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const (
	awsRoleAnnotation = "vault.uw.systems/aws-role"
)

var awsPolicyTemplate = `
path "{{ .AWSPath }}/creds/{{ .Name }}" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "{{ .AWSPath }}/sts/{{ .Name }}" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
`

// AWSRules are a collection of rules.
type AWSRules []AWSRule

// allow returns true if there is a rule in the list of rules which allows
// a service account in the given namespace to assume the given role. Rules are
// evaluated in order and allow returns true for the first matching rule in the
// list
func (ar AWSRules) allow(namespace, roleArn string) (bool, error) {
	a, err := arn.Parse(roleArn)
	if err != nil {
		return false, err
	}

	for _, r := range ar {
		allowed, err := r.allows(namespace, a)
		if err != nil {
			return false, err
		}
		if allowed {
			return true, nil
		}
	}

	return len(ar) == 0, nil
}

// AWSRule restricts the arns that a service account can assume based on
// patterns which match its namespace to an arn or arns
type AWSRule struct {
	NamespacePatterns []string `yaml:"namespacePatterns"`
	RoleNamePatterns  []string `yaml:"roleNamePatterns"`
	AccountIDs        []string `yaml:"accountIDs"`
}

// allows checks whether this rule allows a namespace to assume the given role_arn
func (ar *AWSRule) allows(namespace string, roleArn arn.ARN) (bool, error) {
	accountIDAllowed := ar.matchesAccountID(roleArn.AccountID)

	namespaceAllowed, err := ar.matchesNamespace(namespace)
	if err != nil {
		return false, err
	}

	roleAllowed := false
	if strings.HasPrefix(roleArn.Resource, "role/") {
		roleAllowed, err = ar.matchesRoleName(strings.TrimPrefix(roleArn.Resource, "role/"))
		if err != nil {
			return false, err
		}
	}

	return accountIDAllowed && namespaceAllowed && roleAllowed, nil
}

// matchesAccountID returns true if the rule allows an accountID, or if it
// doesn't contain an accountID at all
func (ar *AWSRule) matchesAccountID(accountID string) bool {
	for _, id := range ar.AccountIDs {
		if id == accountID {
			return true
		}
	}

	return len(ar.AccountIDs) == 0
}

// matchesNamespace returns true if the rule allows the given namespace
func (ar *AWSRule) matchesNamespace(namespace string) (bool, error) {
	for _, np := range ar.NamespacePatterns {
		match, err := filepath.Match(np, namespace)
		if err != nil {
			return false, err
		}
		if match {
			return true, nil
		}
	}

	return false, nil
}

// matchesRoleName returns true if the rule allows the given role name
func (ar *AWSRule) matchesRoleName(roleName string) (bool, error) {
	for _, rp := range ar.RoleNamePatterns {
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

// AWSOperatorConfig provides configuration when creating a new Operator
type AWSOperatorConfig struct {
	*Config
	AWSPath    string
	DefaultTTL time.Duration
	Rules      AWSRules
}

// AWSOperator is responsible for creating Kubernetes auth roles and AWS secret
// roles based on ServiceAccount annotations
type AWSOperator struct {
	*AWSOperatorConfig
	log  logr.Logger
	tmpl *template.Template
}

// NewAWSOperator returns a configured AWSOperator
func NewAWSOperator(config *AWSOperatorConfig) (*AWSOperator, error) {
	tmpl, err := template.New("policy").Parse(awsPolicyTemplate)
	if err != nil {
		return nil, err
	}

	ar := &AWSOperator{
		AWSOperatorConfig: config,
		log:               log.WithName("aws"),
		tmpl:              tmpl,
	}

	return ar, nil
}

// Start is ran when the manager starts up. We're using it to clear up orphaned
// serviceaccounts that could have been missed while the operator was down
func (o *AWSOperator) Start(ctx context.Context) error {
	o.log.Info("garbage collection started")

	// AWS secret roles
	awsRoleList, err := o.VaultClient.Logical().List(o.AWSPath + "/roles/")
	if err != nil {
		return err
	}
	if awsRoleList != nil {
		if keys, ok := awsRoleList.Data["keys"].([]interface{}); ok {
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
// auth/kubernetes/role/<prefix>_aws_<namespace>_<name> and retrieve AWS credentials at
// aws/roles/<prefix>_aws_<namespace>_<name> for the role_arn specified in the
// vault.uw.systems/aws-role annotation
func (o *AWSOperator) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
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
	roleArn := serviceAccount.Annotations[awsRoleAnnotation]
	if !o.admitEvent(req.Namespace, roleArn) {
		del = true
	}

	// Delete the vault objects
	if del {
		return ctrl.Result{}, o.removeFromVault(req.Namespace, req.Name)
	}

	err = o.writeToVault(req.Namespace, req.Name, map[string]interface{}{
		"default_sts_ttl": int(o.DefaultTTL.Seconds()),
		"role_arns":       []string{roleArn},
		"credential_type": "assumed_role",
	})

	return ctrl.Result{}, err
}

// admitEvent controls whether an event should be reconciled or not based on the
// presence of a role arn and whether the role arn is permitted for this
// namespace by the rules laid out in the config file
func (o *AWSOperator) admitEvent(namespace, roleArn string) bool {
	if roleArn != "" {
		allowed, err := o.Rules.allow(namespace, roleArn)
		if err != nil {
			o.log.Error(err, "error matching role arn against rules for namespace", "role_arn", roleArn, "namespace", namespace)
		} else if allowed {
			return true
		}
	}

	return false
}

// SetupWithManager adds the operator as a runnable and a reconciler on the controller-runtime manager. It also
// applies event filters that ensure Reconcile only processes relevant ServiceAccount events.
func (o *AWSOperator) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.Add(o); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ServiceAccount{}).
		WithEventFilter(predicate.Funcs{
			CreateFunc: func(e event.CreateEvent) bool {
				return o.admitEvent(e.Object.GetNamespace(), e.Object.GetAnnotations()[awsRoleAnnotation])
			},
			DeleteFunc: func(e event.DeleteEvent) bool {
				return o.admitEvent(e.Object.GetNamespace(), e.Object.GetAnnotations()[awsRoleAnnotation])
			},
			GenericFunc: func(e event.GenericEvent) bool {
				return o.admitEvent(e.Object.GetNamespace(), e.Object.GetAnnotations()[awsRoleAnnotation])
			},
			UpdateFunc: func(e event.UpdateEvent) bool {
				// Update events are a special case, because we
				// want to remove the roles in vault when the
				// annotation is removed or changed to an
				// invalid value.
				return e.ObjectOld.GetAnnotations()[awsRoleAnnotation] != e.ObjectNew.GetAnnotations()[awsRoleAnnotation]
			},
		}).
		Complete(o)
}

// name returns a unique name for the key in vault, derived from the namespace and name of the
// serviceaccount
func (o *AWSOperator) name(namespace, serviceAccount string) string {
	return o.Prefix + "_aws_" + namespace + "_" + serviceAccount
}

// parseKey parses a key from vault into its namespace and name. Also returns a
// bool that indicates whether parsing was successful
func (o *AWSOperator) parseKey(key string) (string, string, bool) {
	keyParts := strings.Split(key, "_")
	if len(keyParts) == 4 && keyParts[0] == o.Prefix && keyParts[1] == "aws" {
		return keyParts[2], keyParts[3], true
	}

	return "", "", false
}

// renderAWSPolicyTemplate injects the provided name into a policy allowing access
// to the corresponding AWS secret role
func (o *AWSOperator) renderAWSPolicyTemplate(name string) (string, error) {
	var policy bytes.Buffer
	if err := o.tmpl.Execute(&policy, struct {
		AWSPath string
		Name    string
	}{
		AWSPath: o.AWSPath,
		Name:    name,
	}); err != nil {
		return "", err
	}

	return policy.String(), nil
}

// writeToVault creates the kubernetes auth role and aws secret role required
// for the given serviceaccount to login and assume the provided role arn
func (o *AWSOperator) writeToVault(namespace, serviceAccount string, data map[string]interface{}) error {
	n := o.name(namespace, serviceAccount)

	// Create policy for kubernetes auth role
	policy, err := o.renderAWSPolicyTemplate(n)
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

	// Create aws secret backend role
	if _, err := o.VaultClient.Logical().Write(o.AWSPath+"/roles/"+n, data); err != nil {
		return err
	}
	o.log.Info("Wrote aws secret backend role", "namespace", namespace, "serviceaccount", serviceAccount, "key", n)

	return nil
}

// removeFromVault removes the items from vault for the provided serviceaccount
func (o *AWSOperator) removeFromVault(namespace, serviceAccount string) error {
	n := o.name(namespace, serviceAccount)

	_, err := o.VaultClient.Logical().Delete(o.AWSPath + "/roles/" + n)
	if err != nil {
		return err
	}
	o.log.Info("Deleted AWS backend role", "namespace", namespace, "serviceaccount", serviceAccount, "key", n)

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
func (o *AWSOperator) garbageCollect(keys []interface{}) error {
	for _, k := range keys {
		key, ok := k.(string)
		if !ok {
			continue
		}

		namespace, name, parsed := o.parseKey(key)
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
func (o *AWSOperator) hasServiceAccount(namespace, name string) (bool, error) {
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
				serviceAccount.Annotations[awsRoleAnnotation],
			) {
			return true, nil
		}
	}

	return false, nil
}
