package operator

import (
	"encoding/json"
	"testing"

	vaultkube "github.com/hashicorp/vault-plugin-auth-kubernetes"
	vaultapi "github.com/hashicorp/vault/api"
	vaultaws "github.com/hashicorp/vault/builtin/logical/aws"
	vaulthttp "github.com/hashicorp/vault/http"
	vaultlogical "github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/vault"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestAWSOperatorReconcile walks through creating, updating and removing objects
// in vault based on the state of the annotation
func TestAWSOperatorReconcile(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	fakeKubeClient := fake.NewFakeClientWithScheme(scheme, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Annotations: map[string]string{
				awsRoleAnnotation: "fakerole",
			},
		},
	})

	fakeVaultCluster := newFakeVaultCluster(t)

	core := fakeVaultCluster.Cores[0]

	a, err := NewAWSOperator(&AWSOperatorConfig{
		Config: &Config{
			KubeClient:            fakeKubeClient,
			KubernetesAuthBackend: "kubernetes",
			Prefix:                "vkcc",
			VaultClient:           core.Client,
			VaultConfig:           vaultapi.DefaultConfig(),
		},
		AWSPath: "aws",
	})
	if err != nil {
		t.Fatal(err)
	}

	// CREATE: test that Reconcile creates the vault objects for a new SA
	result, err := a.Reconcile(ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "foo",
			Namespace: "bar",
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// Test that the policy isn't empty
	policy, err := core.Client.Logical().Read("sys/policy/vkcc_aws_bar_foo")
	assert.NoError(t, err)
	assert.NotEmpty(t, policy.Data["rules"])

	// Test the fields of the kubernetes auth role
	kubeAuthRole, err := core.Client.Logical().Read("auth/kubernetes/role/vkcc_aws_bar_foo")
	assert.NoError(t, err)
	assert.Equal(t, []interface{}{"foo"}, kubeAuthRole.Data["bound_service_account_names"].([]interface{}))
	assert.Equal(t, []interface{}{"bar"}, kubeAuthRole.Data["bound_service_account_namespaces"].([]interface{}))
	assert.Equal(t, []interface{}{"default", "vkcc_aws_bar_foo"}, kubeAuthRole.Data["policies"].([]interface{}))
	assert.Equal(t, json.Number("900"), kubeAuthRole.Data["ttl"].(json.Number))

	// Test the fields of the aws secret role
	awsRole, err := core.Client.Logical().Read("aws/roles/vkcc_aws_bar_foo")
	assert.NoError(t, err)
	assert.Equal(t, []interface{}{"fakerole"}, awsRole.Data["role_arns"].([]interface{}))
	assert.Equal(t, json.Number("900"), awsRole.Data["default_sts_ttl"].(json.Number))

	// UPDATE: test that Reconcile updates the role when the annotation
	// changes
	a.KubeClient = fake.NewFakeClientWithScheme(scheme, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Annotations: map[string]string{
				awsRoleAnnotation: "anotherfakerole",
			},
		},
	})

	updateResult, err := a.Reconcile(ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "foo",
			Namespace: "bar",
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, updateResult)

	// Test that the role has been updated
	updatedAWSRole, err := core.Client.Logical().Read("aws/roles/vkcc_aws_bar_foo")
	assert.NoError(t, err)
	assert.Equal(t, []interface{}{"anotherfakerole"}, updatedAWSRole.Data["role_arns"].([]interface{}))

	// REMOVE: finally, test that removing the annotation deletes the objects in
	// vault
	a.KubeClient = fake.NewFakeClientWithScheme(scheme, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
	})
	removeResult, err := a.Reconcile(ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "foo",
			Namespace: "bar",
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, removeResult)

	// Test that the returned policy is nil
	removedPolicy, err := core.Client.Logical().Read("sys/policy/vkcc_aws_bar_foo")
	assert.NoError(t, err)
	assert.Empty(t, removedPolicy)

	// Test that the returned kubernetes auth role is nil
	removedKubeAuthRole, err := core.Client.Logical().Read("auth/kubernetes/role/vkcc_aws_bar_foo")
	assert.NoError(t, err)
	assert.Empty(t, removedKubeAuthRole)

	// Test that the returned aws role is nil
	removedAWSRole, err := core.Client.Logical().Read("aws/roles/vkcc_aws_bar_foo")
	assert.Empty(t, removedAWSRole)
}

// TestOperatorReconcileDelete tests that the objects are deleted from vault
// when the SA doesn't exist
func TestOperatorReconcileDelete(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	fakeKubeClient := fake.NewFakeClientWithScheme(scheme)

	fakeVaultCluster := newFakeVaultCluster(t)

	core := fakeVaultCluster.Cores[0]

	a, err := NewAWSOperator(&AWSOperatorConfig{
		Config: &Config{
			KubeClient:            fakeKubeClient,
			KubernetesAuthBackend: "kubernetes",
			Prefix:                "vkcc",
			VaultClient:           core.Client,
			VaultConfig:           vaultapi.DefaultConfig(),
		},
		AWSPath: "aws",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create a policy
	policy, err := a.renderAWSPolicyTemplate("vkcc_aws_bar_foo")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.VaultClient.Logical().Write("sys/policy/vkcc_bar_foo", map[string]interface{}{
		"policy": policy,
	}); err != nil {
		t.Fatal(err)
	}

	// Create kubernetes auth backend role
	if _, err := a.VaultClient.Logical().Write("auth/kubernetes/role/vkcc_aws_bar_foo", map[string]interface{}{
		"bound_service_account_names":      []string{"foo"},
		"bound_service_account_namespaces": []string{"bar"},
		"policies":                         []string{"default", "vkcc_aws_bar_foo"},
		"ttl":                              900,
	}); err != nil {
		t.Fatal(err)
	}

	// Create aws secret backend role
	if _, err := a.VaultClient.Logical().Write("aws/roles/vkcc_aws_bar_foo", map[string]interface{}{
		"default_sts_ttl": 900,
		"role_arns":       []string{"fakerole"},
		"credential_type": "assumed_role",
	}); err != nil {
		t.Fatal(err)
	}

	// This should remove the objects from vault
	result, err := a.Reconcile(ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "foo",
			Namespace: "bar",
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// Test that the returned policy is nil
	removedPolicy, err := core.Client.Logical().Read("sys/policy/vkcc_aws_bar_foo")
	assert.NoError(t, err)
	assert.Empty(t, removedPolicy)

	// Test that the returned kubernetes auth role is nil
	removedKubeAuthRole, err := core.Client.Logical().Read("auth/kubernetes/role/vkcc_aws_bar_foo")
	assert.NoError(t, err)
	assert.Empty(t, removedKubeAuthRole)

	// Test that the returned aws role is nil
	removedAWSRole, err := core.Client.Logical().Read("aws/roles/vcco_bar_foo")
	assert.Empty(t, removedAWSRole)
}

// fakeVaultCluster creates a mock vault cluster with the kubernetes credential
// backend and the aws secret backend loaded and mounted
func newFakeVaultCluster(t *testing.T) *vault.TestCluster {
	coreConfig := &vault.CoreConfig{
		CredentialBackends: map[string]vaultlogical.Factory{
			"kubernetes": vaultkube.Factory,
		},
		LogicalBackends: map[string]vaultlogical.Factory{
			"aws": vaultaws.Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		NumCores:    1,
		HandlerFunc: vaulthttp.Handler,
	})

	cluster.Start()
	if len(cluster.Cores) != 1 {
		t.Fatalf("expected exactly one core")
	}
	core := cluster.Cores[0]
	vault.TestWaitActive(t, core.Core)

	// load the auth plugin
	if err := core.Client.Sys().EnableAuthWithOptions("kubernetes", &vaultapi.EnableAuthOptions{
		Type: "kubernetes",
	}); err != nil {
		t.Fatal(err)
	}

	// load the secrets backend
	if err := core.Client.Sys().Mount("aws", &vaultapi.MountInput{
		Type: "aws",
	}); err != nil {
		t.Fatal(err)
	}
	return cluster
}
