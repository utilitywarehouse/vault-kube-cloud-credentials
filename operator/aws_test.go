package operator

import (
	"encoding/json"
	"testing"
	"time"

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
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
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
				awsRoleAnnotation: "arn:aws:iam::111111111111:role/foobar-role",
			},
		},
	})

	fakeVaultCluster := newFakeVaultCluster(t)

	core := fakeVaultCluster.Cores[0]

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	a, err := NewAWSOperator(&AWSOperatorConfig{
		Config: &Config{
			KubeClient:            fakeKubeClient,
			KubernetesAuthBackend: "kubernetes",
			Prefix:                "vkcc",
			VaultClient:           core.Client,
			VaultConfig:           vaultapi.DefaultConfig(),
		},
		AWSPath:    "aws",
		DefaultTTL: 3600 * time.Second,
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
	assert.Equal(t, []interface{}{"arn:aws:iam::111111111111:role/foobar-role"}, awsRole.Data["role_arns"].([]interface{}))
	assert.Equal(t, json.Number("3600"), awsRole.Data["default_sts_ttl"].(json.Number))

	// UPDATE: test that Reconcile updates the role when the annotation
	// changes
	a.KubeClient = fake.NewFakeClientWithScheme(scheme, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Annotations: map[string]string{
				awsRoleAnnotation: "arn:aws:iam::111111111111:role/another/foobar-role",
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
	assert.Equal(t, []interface{}{"arn:aws:iam::111111111111:role/another/foobar-role"}, updatedAWSRole.Data["role_arns"].([]interface{}))

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

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

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
		"role_arns":       []string{"arn:aws:iam::111111111111:role/foobar-role"},
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
	removedAWSRole, err := core.Client.Logical().Read("aws/roles/vkcc_bar_foo")
	assert.Empty(t, removedAWSRole)
}

// TestOperatorReconcileBlocked tests that the objects aren't written to vault
// if the request doesn't match a rule
func TestOperatorReconcileBlocked(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	fakeKubeClient := fake.NewFakeClientWithScheme(scheme, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Annotations: map[string]string{
				awsRoleAnnotation: "arn:aws:iam::111111111111:role/foobar-role",
			},
		},
	})

	fakeVaultCluster := newFakeVaultCluster(t)

	core := fakeVaultCluster.Cores[0]

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

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

	a.rules = AWSRules{
		AWSRule{
			NamespacePatterns: []string{
				"notbar",
			},
			RoleNamePatterns: []string{
				"not-foobar-role",
			},
		},
	}

	// This shouldn't create the objects in vault
	result, err := a.Reconcile(ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "foo",
			Namespace: "bar",
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// Test that the returned policy is nil
	noPolicy, err := core.Client.Logical().Read("sys/policy/vkcc_aws_bar_foo")
	assert.NoError(t, err)
	assert.Empty(t, noPolicy)

	// Test that the returned kubernetes auth role is nil
	noKubeAuthRole, err := core.Client.Logical().Read("auth/kubernetes/role/vkcc_aws_bar_foo")
	assert.NoError(t, err)
	assert.Empty(t, noKubeAuthRole)

	// Test that the returned aws role is nil
	noAWSRole, err := core.Client.Logical().Read("aws/roles/vkcc_bar_foo")
	assert.Empty(t, noAWSRole)
}

// TestAWSOperatorStart tests the garbage collection performed by the Start
// method
func TestAWSOperatorStart(t *testing.T) {
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

	stopc := make(<-chan struct{})

	// Test that Start returns cleanly when there are no items in vault
	err = a.Start(stopc)
	assert.NoError(t, err)

	// Create policies
	policy, err := a.renderAWSPolicyTemplate("vkcc_aws_bar_foo")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := core.Client.Logical().Write("sys/policy/vkcc_aws_bar_foo", map[string]interface{}{
		"policy": policy,
	}); err != nil {
		t.Fatal(err)
	}
	policyGC, err := a.renderAWSPolicyTemplate("vkcc_aws_bar_gc")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := core.Client.Logical().Write("sys/policy/vkcc_aws_bar_gc", map[string]interface{}{
		"policy": policyGC,
	}); err != nil {
		t.Fatal(err)
	}

	// Create kubernetes auth backend roles
	if _, err := core.Client.Logical().Write("auth/kubernetes/role/vkcc_aws_bar_foo", map[string]interface{}{
		"bound_service_account_names":      []string{"foo"},
		"bound_service_account_namespaces": []string{"bar"},
		"policies":                         []string{"default", "vkcc_aws_bar_foo"},
		"ttl":                              900,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := core.Client.Logical().Write("auth/kubernetes/role/vkcc_aws_bar_gc", map[string]interface{}{
		"bound_service_account_names":      []string{"gc"},
		"bound_service_account_namespaces": []string{"bar"},
		"policies":                         []string{"default", "vkcc_aws_bar_gc"},
		"ttl":                              900,
	}); err != nil {
		t.Fatal(err)
	}

	// Create aws secret backend roles
	if _, err := core.Client.Logical().Write("aws/roles/vkcc_aws_bar_foo", map[string]interface{}{
		"default_sts_ttl": 900,
		"role_arns":       []string{"arn:aws:iam::111111111111:role/foobar-role"},
		"credential_type": "assumed_role",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := core.Client.Logical().Write("aws/roles/vkcc_aws_bar_gc", map[string]interface{}{
		"default_sts_ttl": 900,
		"role_arns":       []string{"arn:aws:iam::111111111111:role/foobar-gc-role"},
		"credential_type": "assumed_role",
	}); err != nil {
		t.Fatal(err)
	}

	// Add a service account for only one of the keys that have been written
	// to vault
	a.KubeClient = fake.NewFakeClientWithScheme(scheme, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Annotations: map[string]string{
				awsRoleAnnotation: "arn:aws:iam::111111111111:role/foobar-role",
			},
		},
	})

	// This should remove keys for vkcc_aws_bar_gc but leave
	// vkcc_aws_bar_foo
	err = a.Start(stopc)
	assert.NoError(t, err)

	// Test that the gc'd policy is nil
	removedPolicy, err := core.Client.Logical().Read("sys/policy/vkcc_aws_bar_gc")
	assert.NoError(t, err)
	assert.Empty(t, removedPolicy)

	// Test that the gc'd kubernetes auth role is nil
	removedKubeAuthRole, err := core.Client.Logical().Read("auth/kubernetes/role/vkcc_aws_bar_gc")
	assert.NoError(t, err)
	assert.Empty(t, removedKubeAuthRole)

	// Test that the gc'd aws role is nil
	removedAWSRole, err := core.Client.Logical().Read("aws/roles/vkcc_aws_bar_gc")
	assert.NoError(t, err)
	assert.Empty(t, removedAWSRole)

	// Test that the bar/foo policy has not been gc'd
	keptPolicy, err := core.Client.Logical().Read("sys/policy/vkcc_aws_bar_foo")
	assert.NoError(t, err)
	assert.NotEmpty(t, keptPolicy)

	// Test that the bar/foo kubernetes auth role has not been gc'd
	keptKubeAuthRole, err := core.Client.Logical().Read("auth/kubernetes/role/vkcc_aws_bar_foo")
	assert.NoError(t, err)
	assert.NotEmpty(t, keptKubeAuthRole)

	// Test that the bar/foo aws secret role has not been gc'd
	keptAWSRole, err := core.Client.Logical().Read("aws/roles/vkcc_aws_bar_foo")
	assert.NoError(t, err)
	assert.NotEmpty(t, keptAWSRole)
}

// TestAWSOperatorAdmitEvent tests that events are allowed and disallowed
// according to the rules
func TestAWSOperatorAdmitEvent(t *testing.T) {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	o := &AWSOperator{
		log: ctrl.Log.WithName("operator").WithName("aws"),
	}

	// Test that without any rules any valid event is admitted
	assert.True(t, o.admitEvent("foobar", "arn:aws:iam::111111111111:role/foobar-role"))

	// Test that an empty role is not admitted
	assert.False(t, o.admitEvent("foobar", ""))

	// Test that an invalid role is not admitted
	assert.False(t, o.admitEvent("foobar", "foobar"))

	// Test that a malformed arn is not admitted (missing a second : after
	// iam)
	assert.False(t, o.admitEvent("foobar", "arn:aws:iam:111111111111:role/foobar-role"))

	o.rules = AWSRules{
		AWSRule{
			NamespacePatterns: []string{
				"foo",
				"bar-*",
			},
			RoleNamePatterns: []string{
				"foobar-*",
				"barfoo/*",
			},
			AccountIDs: []string{
				"000000000000",
				"111111111111",
			},
		},
		AWSRule{
			NamespacePatterns: []string{
				"kube-system",
			},
			RoleNamePatterns: []string{
				"org*",
				"org-*/test-*/*",
				"syste?",
			},
		},
		AWSRule{
			RoleNamePatterns: []string{
				"fuubar-*",
			},
		},
		AWSRule{
			NamespacePatterns: []string{
				"fuubar",
			},
		},
	}

	// Test bar-* : foobar-* is allowed
	assert.True(t, o.admitEvent("bar-foo", "arn:aws:iam::111111111111:role/foobar-role"))

	// Test that foo : barfoo/* is allowed
	assert.True(t, o.admitEvent("foo", "arn:aws:iam::111111111111:role/barfoo/role"))

	// Test that another account ID from the list is matched
	assert.True(t, o.admitEvent("foo", "arn:aws:iam::000000000000:role/barfoo/role"))

	// Test the second rule is evaluated
	assert.True(t, o.admitEvent("kube-system", "arn:aws:iam::000000000000:role/organisation"))

	// Test the second rule is evaluated
	assert.True(t, o.admitEvent("kube-system", "arn:aws:iam::000000000000:role/org-admins/test-subdivision/foobar"))

	// Test the ? match
	assert.True(t, o.admitEvent("kube-system", "arn:aws:iam::000000000000:role/system"))

	// Test that foo : barfoo is not allowed
	assert.False(t, o.admitEvent("foo", "arn:aws:iam::111111111111:role/barfoo"))

	// Test that the matching doesn't match the namespace foo to foobar as a
	// substring
	assert.False(t, o.admitEvent("foobar", "arn:aws:iam::111111111111:role/foobar-role"))

	// Test that an account ID outside of the list is not allowed
	assert.False(t, o.admitEvent("foo", "arn:aws:iam::222222222222:role/barfoo/role"))

	// Test that the rules don't mix
	assert.False(t, o.admitEvent("foo", "arn:aws:iam::000000000000:role/organisation"))

	// Test that a rule without a namespace pattern does not admit
	assert.False(t, o.admitEvent("foo", "arn:aws:iam::000000000000:role/fuubar-role"))

	// Test that a rule without a role pattern does not admit
	assert.False(t, o.admitEvent("fuubar", "arn:aws:iam::000000000000:role/fuubar-role"))
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
