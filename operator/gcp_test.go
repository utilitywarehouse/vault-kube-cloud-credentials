package operator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// TestGCPOperatorAdmitEvent tests that events are allowed and disallowed
// according to the rules
func TestGCPOperatorAdmitEvent(t *testing.T) {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	fc := &fileConfig{}
	config := &Config{}
	gcp, _ := NewGCPProvider(fc.GCP)
	o, _ := NewOperator(config, gcp)

	// Test that without any rules any valid event is admitted
	assert.True(t, o.admitEvent("foobar", "foo@bar.gserviceaccount.com"))

	// Test that an empty service account is not admitted
	assert.False(t, o.admitEvent("foobar", ""))

	// Test that an invalid service account is not admitted
	assert.False(t, o.admitEvent("foobar", "foobar"))

	// Test that a malformed service account is not admitted (not a gserviceaccount.com email)
	assert.False(t, o.admitEvent("foobar", "foo@bar.baz.com"))

	gcp.Rules = GCPRules{
		GCPRule{
			NamespacePatterns: []string{
				"foo",
				"bar-*",
			},
			ServiceAccEmailPatterns: []string{
				"foo@bar.iam.gserviceaccount.com",
			},
		},
		GCPRule{
			NamespacePatterns: []string{
				"kube-system",
				"syste?",
			},
			ServiceAccEmailPatterns: []string{
				"bar*@bar.iam.gserviceaccount.com",
			},
		},
		GCPRule{
			ServiceAccEmailPatterns: []string{
				"baz@bar.iam.gserviceaccount.com",
			},
		},
		GCPRule{
			NamespacePatterns: []string{
				"foobar",
			},
		},
	}

	// Test foo foo@bar.iam.gserviceaccount.com is allowd
	assert.True(t, o.admitEvent("foo", "foo@bar.iam.gserviceaccount.com"))

	// Test bar-* foo@bar.iam.gserviceaccount.com is allowd
	assert.True(t, o.admitEvent("bar-foo", "foo@bar.iam.gserviceaccount.com"))

	// Test the second rule is evaluated
	assert.True(t, o.admitEvent("kube-system", "bar@bar.iam.gserviceaccount.com"))

	// Test the second rule is evaluated
	assert.True(t, o.admitEvent("kube-system", "bar-baz@bar.iam.gserviceaccount.com"))

	// Test the ? match
	assert.True(t, o.admitEvent("system", "bar-foo@bar.iam.gserviceaccount.com"))

	// Test that baz foo@bar.iam.gserviceaccount.com is not allowed
	assert.False(t, o.admitEvent("baz", "foo@bar.iam.gserviceaccount.com"))

	// Test that the matching doesn't match the namespace foo to foobar as a
	// substring
	assert.False(t, o.admitEvent("foobar", "foo@bar.iam.gserviceaccount.com"))

	// Test that the rules don't mix
	assert.False(t, o.admitEvent("foo", "baz@bar.iam.gserviceaccount.com"))

	// Test that a rule without a namespace pattern does not admit
	assert.False(t, o.admitEvent("foo", "baz@bar.iam.gserviceaccount.com"))

	// Test that a rule without a service account email pattern does not admit
	assert.False(t, o.admitEvent("foobar", "baz@bar.iam.gserviceaccount.com"))
}
