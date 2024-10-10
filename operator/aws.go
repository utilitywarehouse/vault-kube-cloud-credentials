package operator

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/aws/aws-sdk-go/aws/arn"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

const (
	awsRoleAnnotation       = "vault.uw.systems/aws-role"
	defaultSTSTTLAnnotation = "vault.uw.systems/default-sts-ttl"
	maxSTSTTLDuration       = 12 * time.Hour
)

var awsPolicyTemplate = `
path "{{ .Path }}/creds/{{ .Name }}" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "{{ .Path }}/sts/{{ .Name }}" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
`

// AWSRules are a collection of rules.
type AWSRules []AWSRule

// AWSRule restricts the arns that a service account can assume based on
// patterns which match its namespace to an arn or arns
type AWSRule struct {
	NamespacePatterns []string `yaml:"namespacePatterns"`
	RoleNamePatterns  []string `yaml:"roleNamePatterns"`
	AccountIDs        []string `yaml:"accountIDs"`
}

// AWSOperatorConfig provides configuration when creating a new Operator
type AWS struct {
	DefaultTTL time.Duration
	MinTTL     time.Duration
	Path       string
	Rules      AWSRules
	tmpl       *template.Template
}

// NewAWSProvider returns a configured AWS provider config
func NewAWSProvider(config awsFileConfig) (*AWS, error) {
	tmpl, err := template.New("policy").Parse(awsPolicyTemplate)
	if err != nil {
		return nil, err
	}

	return &AWS{
		DefaultTTL: config.DefaultTTL,
		MinTTL:     config.MinTTL,
		tmpl:       tmpl,
		Path:       config.Path,
		Rules:      config.Rules,
	}, nil
}

// name returns the name of the AWS provider
func (a *AWS) name() string {
	return "aws"
}

// secretIdentityAnnotation returns
func (a *AWS) secretIdentityAnnotation() string {
	return awsRoleAnnotation
}

func (a *AWS) secretPath() string {
	return a.Path + "/roles/"
}

func (a *AWS) processUpdateEvent(e event.UpdateEvent) bool {
	return e.ObjectOld.GetAnnotations()[awsRoleAnnotation] != e.ObjectNew.GetAnnotations()[awsRoleAnnotation] ||
		e.ObjectOld.GetAnnotations()[defaultSTSTTLAnnotation] != e.ObjectNew.GetAnnotations()[defaultSTSTTLAnnotation]
}

func (a *AWS) secretPayload(serviceAccount *corev1.ServiceAccount) (map[string]interface{}, error) {
	var err error
	// check if default-sts-ttl is set if not use config default
	defaultTTL := a.DefaultTTL
	if v, ok := serviceAccount.Annotations[defaultSTSTTLAnnotation]; ok {
		defaultTTL, err = time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("error parsing default_sts_ttl %w", err)
		}
	}

	if defaultTTL < a.MinTTL {
		return nil, fmt.Errorf("minimum default-sts-ttl value allowed is %s, its set to %s", a.MinTTL, defaultTTL)
	}
	if defaultTTL > maxSTSTTLDuration {
		return nil, fmt.Errorf("maximum default-sts-ttl value allowed is %s, its set to %s", maxSTSTTLDuration, defaultTTL)
	}

	return map[string]interface{}{
		"default_sts_ttl": int(defaultTTL.Seconds()),
		"role_arns":       []string{serviceAccount.Annotations[awsRoleAnnotation]},
		"credential_type": "assumed_role",

		// https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
		// Valid Range: Minimum value of 900. Maximum value of 43200.
		// if this value it not set then default max will be either maxLease of vault or 1h
		"max_sts_ttl": int(maxSTSTTLDuration.Seconds()),
	}, nil
}

// renderAWSPolicyTemplate injects the provided name into a policy allowing access
// to the corresponding AWS secret role
func (a *AWS) renderPolicyTemplate(name string) (string, error) {
	var policy bytes.Buffer
	if err := a.tmpl.Execute(&policy, struct {
		Path string
		Name string
	}{
		Path: a.Path,
		Name: name,
	}); err != nil {
		return "", err
	}

	return policy.String(), nil
}

func (a *AWS) allow(namespace, roleArn string) (bool, error) {
	return a.Rules.allow(namespace, roleArn)
}

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

// allows checks whether this rule allows a namespace to assume the given role_arn
func (ar *AWSRule) allows(namespace string, roleArn arn.ARN) (bool, error) {
	accountIDAllowed := ar.matchesAccountID(roleArn.AccountID)

	namespaceAllowed, err := matchesNamespace(namespace, ar.NamespacePatterns)
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
