package operator

import (
	"bytes"
	"context"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	// Enables all auth methods for the kube client
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"log"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"strings"
	"text/template"
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

// AWSOperatorConfig provides configuration when creating a new Operator
type AWSOperatorConfig struct {
	*Config
	AWSPath string
}

// AWSOperator is responsible for creating Kubernetes auth roles and AWS secret
// roles based on ServiceAccount annotations
type AWSOperator struct {
	*AWSOperatorConfig
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
		tmpl:              tmpl,
	}

	return ar, nil
}

// Start is ran when the manager starts up. We're using it to clear up orphaned
// serviceaccounts that could have been missed while the operator was down
func (o *AWSOperator) Start(stop <-chan struct{}) error {
	log.Print("aws garbage collection started")

	// AWS secret roles
	awsRoleList, err := o.VaultClient.Logical().List(o.AWSPath + "/roles/")
	if err != nil {
		return err
	}
	err = o.garbageCollect(awsRoleList.Data["keys"].([]interface{}))
	if err != nil {
		return err
	}

	// Kubernetes auth roles
	kubeAuthRoleList, err := o.VaultClient.Logical().List("auth/" + o.KubernetesAuthBackend + "/role/")
	if err != nil {
		return err
	}
	err = o.garbageCollect(kubeAuthRoleList.Data["keys"].([]interface{}))
	if err != nil {
		return err
	}

	// Policies
	policies, err := o.VaultClient.Logical().List("sys/policy")
	if err != nil {
		return err
	}
	err = o.garbageCollect(policies.Data["keys"].([]interface{}))
	if err != nil {
		return err
	}

	log.Print("aws garbage collection finished")

	return nil
}

// Reconcile ensures that a ServiceAccount is able to login at
// auth/kubernetes/role/<prefix>_aws_<namespace>_<name> and retrieve AWS credentials at
// aws/roles/<prefix>_aws_<namespace>_<name> for the role_arn specified in the
// vault.uw.systems/aws-role annotation
func (o *AWSOperator) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()

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

	// Similarly, we can remove it from vault if there is no annotation
	roleArn := serviceAccount.Annotations[awsRoleAnnotation]
	if roleArn == "" {
		del = true
	}

	// Delete the vault objects
	if del {
		return ctrl.Result{}, o.removeFromVault(req.Namespace, req.Name)
	}

	err = o.writeToVault(req.Namespace, req.Name, map[string]interface{}{
		"default_sts_ttl": 900,
		"role_arns":       []string{roleArn},
		"credential_type": "assumed_role",
	})

	return ctrl.Result{}, err
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
				return e.Meta.GetAnnotations()[awsRoleAnnotation] != ""
			},
			DeleteFunc: func(e event.DeleteEvent) bool {
				return e.Meta.GetAnnotations()[awsRoleAnnotation] != ""
			},
			GenericFunc: func(e event.GenericEvent) bool {
				return e.Meta.GetAnnotations()[awsRoleAnnotation] != ""
			},
			UpdateFunc: func(e event.UpdateEvent) bool {
				return e.MetaOld.GetAnnotations()[awsRoleAnnotation] != e.MetaNew.GetAnnotations()[awsRoleAnnotation]
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
	log.Printf("Wrote policy %s for serviceaccount: %s/%s", n, namespace, serviceAccount)

	// Create kubernetes auth backend role
	if _, err := o.VaultClient.Logical().Write("auth/"+o.KubernetesAuthBackend+"/role/"+n, map[string]interface{}{
		"bound_service_account_names":      []string{serviceAccount},
		"bound_service_account_namespaces": []string{namespace},
		"policies":                         []string{"default", n},
		"ttl":                              900,
	}); err != nil {
		return err
	}
	log.Printf("Wrote kubernetes auth backend role: %s for serviceaccount: %s/%s", n, namespace, serviceAccount)

	// Create aws secret backend role
	if _, err := o.VaultClient.Logical().Write(o.AWSPath+"/roles/"+n, data); err != nil {
		return err
	}
	log.Printf("Wrote aws secret backend role: %s for serviceaccount: %s/%s", n, namespace, serviceAccount)

	return nil
}

// removeFromVault removes the items from vault for the provided serviceaccount
func (o *AWSOperator) removeFromVault(namespace, serviceAccount string) error {
	n := o.name(namespace, serviceAccount)

	_, err := o.VaultClient.Logical().Delete(o.AWSPath + "/roles/" + n)
	if err != nil {
		return err
	}
	log.Printf("Deleted AWS backend role: %s", n)

	_, err = o.VaultClient.Logical().Delete("auth/" + o.KubernetesAuthBackend + "/role/" + n)

	if err != nil {
		return err
	}
	log.Printf("Deleted Kubernetes auth role: %s", n)

	_, err = o.VaultClient.Logical().Delete("sys/policy/" + n)
	if err != nil {
		return err
	}
	log.Printf("Deleted policy: %s", n)

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
// namespace+name combination, annotated with the correct annotation
func (o *AWSOperator) hasServiceAccount(namespace, name string) (bool, error) {
	serviceAccountList := &corev1.ServiceAccountList{}
	err := o.KubeClient.List(context.Background(), serviceAccountList)
	if err != nil {
		return false, err
	}

	for _, serviceAccount := range serviceAccountList.Items {
		if serviceAccount.Namespace == namespace && serviceAccount.Name == name && serviceAccount.Annotations[awsRoleAnnotation] != "" {
			return true, nil
		}
	}

	return false, nil
}
