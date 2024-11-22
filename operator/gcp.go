package operator

import (
	"bytes"
	"fmt"
	"path/filepath"
	"regexp"
	"text/template"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

const (
	gcpServiceAccountAnnotation = "vault.uw.systems/gcp-service-account"
	gcpScopeAnnotation          = "vault.uw.systems/gcp-token-scopes"
	defaultGCPKeyTTLAnnotation  = "vault.uw.systems/default-gcp-key-ttl"
)

var gcpPolicyTemplate = `
path "{{ .Path }}/static-account/{{ .Name }}" {
  capabilities = ["read"]
}
path "{{ .Path }}/static-account/{{ .Name }}/token" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "{{ .Path }}/static-account/{{ .Name }}/key" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "{{ .Path }}/token/{{ .Name }}" {
capabilities = ["create", "read", "update", "delete", "list"]
}
path "{{ .Path }}/key/{{ .Name }}" {
  capabilities = ["create", "read", "update", "delete", "list"]
}`

// GCPRules are a collection of rules.
type GCPRules []GCPRule

// GCPRuns which match its namespace to an arn or arns
// GCPRule restricts the GCP service accounts that a k8s serviceAccount can use
// based on patterns which match its namespace to GCP service account email(s)
type GCPRule struct {
	NamespacePatterns       []string `yaml:"namespacePatterns"`
	ServiceAccEmailPatterns []string `yaml:"serviceAccountEmailPatterns"`
}

// GCPOperatorConfig provides configuration when creating a new Operator
type GCP struct {
	DefaultTTL time.Duration
	Path       string
	Rules      GCPRules
	tmpl       *template.Template
}

// NewGCPProvider returns a configured GCP provider config
func NewGCPProvider(config gcpFileConfig) (*GCP, error) {
	tmpl, err := template.New("policy").Parse(gcpPolicyTemplate)
	if err != nil {
		return nil, err
	}

	return &GCP{
		tmpl:  tmpl,
		Path:  config.Path,
		Rules: config.Rules,
	}, nil
}

// name returns the name of the GCP provider
func (g *GCP) name() string {
	return "gcp"
}

func (g *GCP) secretIdentityAnnotation() string {
	return gcpServiceAccountAnnotation
}

func (g *GCP) secretPath() string {
	return g.Path + "/static-account/"
}

func (g *GCP) processUpdateEvent(e event.UpdateEvent) bool {
	return e.ObjectOld.GetAnnotations()[gcpServiceAccountAnnotation] != e.ObjectNew.GetAnnotations()[gcpServiceAccountAnnotation] ||
		e.ObjectOld.GetAnnotations()[gcpScopeAnnotation] != e.ObjectNew.GetAnnotations()[gcpScopeAnnotation]
}

func (g *GCP) secretTTL(serviceAccount *corev1.ServiceAccount) (time.Duration, error) {
	var err error

	secretTTL := g.DefaultTTL
	if v, ok := serviceAccount.Annotations[defaultGCPKeyTTLAnnotation]; ok {
		secretTTL, err = time.ParseDuration(v)
		if err != nil {
			return 0, fmt.Errorf("error parsing default-gcp-key-ttl %w", err)
		}
	}

	return secretTTL, nil
}

func (g *GCP) secretPayload(serviceAccount *corev1.ServiceAccount) (map[string]interface{}, error) {
	tokenScopes := serviceAccount.Annotations[gcpScopeAnnotation]

	switch tokenScopes {
	case "":
		return map[string]interface{}{
			"service_account_email": serviceAccount.Annotations[gcpServiceAccountAnnotation],
			"secret_type":           "service_account_key",
		}, nil
	default:
		return map[string]interface{}{
			"service_account_email": serviceAccount.Annotations[gcpServiceAccountAnnotation],
			"secret_type":           "access_token",
			"token_scopes":          tokenScopes,
		}, nil
	}
}

// renderGCPPolicyTemplate injects the provided name into a policy allowing access
// to the corresponding GCP secret role
func (g *GCP) renderPolicyTemplate(name string) (string, error) {
	var policy bytes.Buffer
	if err := g.tmpl.Execute(&policy, struct {
		Path string
		Name string
	}{
		Path: g.Path,
		Name: name,
	}); err != nil {
		return "", err
	}

	return policy.String(), nil
}

func (g *GCP) allow(namespace, serviceAccountEmail string) (bool, error) {
	return g.Rules.allow(namespace, serviceAccountEmail)
}

// allow returns true if there is a rule in the list of rules which allows
// a service account in the given namespace to assume the given role. Rules are
// evaluated in order and allow returns true for the first matching rule in the
// list
func (gcr GCPRules) allow(namespace, serviceAccountEmail string) (bool, error) {
	err := validateServiceAccountEmail(serviceAccountEmail)
	if err != nil {
		return false, err
	}

	for _, r := range gcr {
		allowed, err := r.allows(namespace, serviceAccountEmail)
		if err != nil {
			return false, err
		}
		if allowed {
			return true, nil
		}
	}

	return len(gcr) == 0, nil
}

func validateServiceAccountEmail(email string) error {
	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.gserviceaccount\.com$`

	re := regexp.MustCompile(pattern)

	if !re.MatchString(email) {
		return fmt.Errorf("invalid service account email format")
	}

	return nil
}

// allows checks whether this rule allows a namespace to assume the given role_arn
func (gcr *GCPRule) allows(namespace string, serviceAccountEmail string) (bool, error) {
	namespaceAllowed, err := matchesNamespace(namespace, gcr.NamespacePatterns)
	if err != nil {
		return false, err
	}

	serviceAccountAllowed, err := gcr.matchesServiceAccountEmail(serviceAccountEmail)
	if err != nil {
		return false, err
	}

	return namespaceAllowed && serviceAccountAllowed, nil
}

// matchesServiceAccountEmail returns true if the rule allows the given service account
func (gcr *GCPRule) matchesServiceAccountEmail(serviceAccountEmail string) (bool, error) {
	for _, rp := range gcr.ServiceAccEmailPatterns {
		match, err := filepath.Match(rp, serviceAccountEmail)
		if err != nil {
			return false, err
		}
		if match {
			return true, nil
		}
	}

	return false, nil
}
