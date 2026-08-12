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
path "{{ .Path }}/impersonated-account/{{ .Name }}" {
  capabilities = ["read"]
}
path "{{ .Path }}/impersonated-account/{{ .Name }}/token" {
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
	DefaultTTL   time.Duration
	Path         string
	Rules        GCPRules
	Impersonated bool
	tmpl         *template.Template
}

// NewGCPProvider returns a configured GCP provider config
func NewGCPProvider(config gcpFileConfig) (*GCP, error) {
	tmpl, err := template.New("policy").Parse(gcpPolicyTemplate)
	if err != nil {
		return nil, err
	}

	return &GCP{
		tmpl: tmpl,

		DefaultTTL:   config.DefaultTTL,
		Path:         config.Path,
		Rules:        config.Rules,
		Impersonated: config.Impersonated,
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

// impersonatedSecretPath is the vault path where GCP access-token accounts
// are stored when impersonation is enabled. Impersonated accounts generate
// tokens via signJwt/impersonation and do not create a GCP service account
// key, avoiding the 10-key-per-service-account limit.
func (g *GCP) impersonatedSecretPath() string {
	return g.Path + "/impersonated-account/"
}

// secretPaths returns all vault secret paths managed by the operator. GCP
// manages both impersonated accounts and legacy static accounts so that
// garbage collection and removal cover accounts of either type.
func (g *GCP) secretPaths() []string {
	return []string{g.impersonatedSecretPath(), g.secretPath()}
}

func (g *GCP) processUpdateEvent(e event.UpdateEvent) bool {
	return e.ObjectOld.GetAnnotations()[gcpServiceAccountAnnotation] != e.ObjectNew.GetAnnotations()[gcpServiceAccountAnnotation] ||
		e.ObjectOld.GetAnnotations()[gcpScopeAnnotation] != e.ObjectNew.GetAnnotations()[gcpScopeAnnotation] ||
		e.ObjectOld.GetAnnotations()[defaultGCPKeyTTLAnnotation] != e.ObjectNew.GetAnnotations()[defaultGCPKeyTTLAnnotation]
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
		if g.Impersonated {
			secretTTL, err := g.secretTTL(serviceAccount)
			if err != nil {
				return nil, err
			}
			// Impersonated accounts generate tokens via signJwt and never
			// create a GCP service account key, so they are not subject to
			// the 10-key-per-service-account limit.
			return map[string]interface{}{
				"service_account_email": serviceAccount.Annotations[gcpServiceAccountAnnotation],
				"token_scopes":          tokenScopes,
				"ttl":                   int(secretTTL.Seconds()),
			}, nil
		}
		return map[string]interface{}{
			"service_account_email": serviceAccount.Annotations[gcpServiceAccountAnnotation],
			"secret_type":           "access_token",
			"token_scopes":          tokenScopes,
		}, nil
	}
}

// secretWritePath returns the vault path to write a secret payload to.
// Access-token payloads go to the impersonated-account path (no secret_type);
// service account key payloads stay on the legacy static-account path.
func (g *GCP) secretWritePath(data map[string]interface{}) string {
	if _, ok := data["secret_type"]; ok {
		return g.secretPath()
	}
	return g.impersonatedSecretPath()
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
