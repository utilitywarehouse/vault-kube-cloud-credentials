package operator

import (
	"context"
	"strings"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"

	// Enables all auth methods for the kube client
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// Operator is responsible for creating Kubernetes auth roles and AWS secret
// roles based on ServiceAccount annotations
type Operator struct {
	*Config
	log logr.Logger
	provider
}

type provider interface {
	allow(namespace, roleArn string) (bool, error)
	name() string
	processUpdateEvent(e event.UpdateEvent) bool
	renderPolicyTemplate(name string) (string, error)
	secretIdentityAnnotation() string
	secretPath() string
	secretPayload(serviceAccount *corev1.ServiceAccount) (map[string]interface{}, error)
}

// NewOperator returns a configured AWSOperator
func NewOperator(config *Config, provider provider) (*Operator, error) {
	ar := &Operator{
		Config:   config,
		log:      log.WithName(provider.name()),
		provider: provider,
	}

	return ar, nil
}

// Start is ran when the manager starts up. We're using it to clear up orphaned
// serviceaccounts that could have been missed while the operator was down
func (o *Operator) Start(ctx context.Context) error {
	o.log.Info("garbage collection started")

	// AWS secret roles
	secretList, err := o.VaultClient.Logical().List(o.provider.secretPath())
	if err != nil {
		return err
	}
	if secretList != nil {
		if keys, ok := secretList.Data["keys"].([]interface{}); ok {
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
func (o *Operator) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
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
	secretIdentity := serviceAccount.Annotations[o.provider.secretIdentityAnnotation()]
	if !o.admitEvent(req.Namespace, secretIdentity) {
		del = true
	}

	// Delete the vault objects
	if del {
		return ctrl.Result{}, o.removeFromVault(req.Namespace, req.Name)
	}

	payload, err := o.provider.secretPayload(serviceAccount)
	if err != nil {
		return ctrl.Result{}, err
	}

	err = o.writeToVault(req.Namespace, req.Name, payload)

	return ctrl.Result{}, err
}

// admitEvent controls whether an event should be reconciled or not based on the
// presence of a role arn and whether the role arn is permitted for this
// namespace by the rules laid out in the config file
// in AWS secretEntity is a role ARN and in GCP it's service account email
func (o *Operator) admitEvent(namespace, secretIdentity string) bool {
	if secretIdentity != "" {
		allowed, err := o.provider.allow(namespace, secretIdentity)
		if err != nil {
			o.log.Error(err, "error matching role arn against rules for namespace", "secretIdentity", secretIdentity, "namespace", namespace)
		} else if allowed {
			return true
		}
	}

	return false
}

// SetupWithManager adds the operator as a runnable and a reconciler on the controller-runtime manager. It also
// applies event filters that ensure Reconcile only processes relevant ServiceAccount events.
func (o *Operator) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.Add(o); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ServiceAccount{}).
		WithEventFilter(predicate.Funcs{
			CreateFunc: func(e event.CreateEvent) bool {
				return o.admitEvent(e.Object.GetNamespace(), e.Object.GetAnnotations()[o.provider.secretIdentityAnnotation()])
			},
			DeleteFunc: func(e event.DeleteEvent) bool {
				return o.admitEvent(e.Object.GetNamespace(), e.Object.GetAnnotations()[o.provider.secretIdentityAnnotation()])
			},
			GenericFunc: func(e event.GenericEvent) bool {
				return o.admitEvent(e.Object.GetNamespace(), e.Object.GetAnnotations()[o.provider.secretIdentityAnnotation()])
			},
			UpdateFunc: func(e event.UpdateEvent) bool {
				// Update events are a special case, because we
				// want to remove the roles in vault when the
				// annotation is removed or changed to an
				// invalid value.
				return o.provider.processUpdateEvent(e)
			},
		}).
		Complete(o)
}

// name returns a unique name for the key in vault, derived from the namespace and name of the
// serviceaccount
func (o *Operator) name(namespace, serviceAccount string) string {
	return o.Prefix + "_" + o.provider.name() + "_" + namespace + "_" + serviceAccount
}

// parseKey parses a key from vault into its namespace and name. Also returns a
// bool that indicates whether parsing was successful
func (o *Operator) parseKey(key string) (string, string, bool) {
	keyParts := strings.Split(key, "_")
	if len(keyParts) == 4 && keyParts[0] == o.Prefix && keyParts[1] == o.provider.name() {
		return keyParts[2], keyParts[3], true
	}

	return "", "", false
}

// writeToVault creates the kubernetes auth role and aws secret role required
// for the given serviceaccount to login and assume the provided role arn
func (o *Operator) writeToVault(namespace, serviceAccount string, data map[string]interface{}) error {
	n := o.name(namespace, serviceAccount)

	// Create policy for kubernetes auth role
	policy, err := o.provider.renderPolicyTemplate(n)
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
	if _, err := o.VaultClient.Logical().Write(o.provider.secretPath()+n, data); err != nil {
		return err
	}
	o.log.Info("Wrote secret identity to vault", "namespace", namespace, "serviceaccount", serviceAccount, "key", n)

	return nil
}

// removeFromVault removes the items from vault for the provided serviceaccount
func (o *Operator) removeFromVault(namespace, serviceAccount string) error {
	n := o.name(namespace, serviceAccount)

	_, err := o.VaultClient.Logical().Delete(o.provider.secretPath() + n)
	if err != nil {
		return err
	}
	o.log.Info("Deleted secret identity from vault", "namespace", namespace, "serviceaccount", serviceAccount, "key", n)

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
func (o *Operator) garbageCollect(keys []interface{}) error {
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
func (o *Operator) hasServiceAccount(namespace, name string) (bool, error) {
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
				serviceAccount.Annotations[o.provider.secretIdentityAnnotation()],
			) {
			return true, nil
		}
	}

	return false, nil
}
