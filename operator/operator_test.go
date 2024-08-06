package operator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_matchesNamespace(t *testing.T) {
	tests := []struct {
		name             string
		namespace        string
		namespacePattern []string
		expectedResult   bool
		expectError      bool
	}{
		{
			name:             "Exact match",
			namespace:        "foo",
			namespacePattern: []string{"foo"},
			expectedResult:   true,
			expectError:      false,
		},
		{
			name:             "Wildcard match",
			namespace:        "foo-bar",
			namespacePattern: []string{"foo-*"},
			expectedResult:   true,
			expectError:      false,
		},
		{
			name:             "No match",
			namespace:        "bar",
			namespacePattern: []string{"foo-*"},
			expectedResult:   false,
			expectError:      false,
		},
		{
			name:             "Invalid pattern",
			namespace:        "foo",
			namespacePattern: []string{"["}, // Invalid pattern
			expectedResult:   false,
			expectError:      true,
		},
		{
			name:             "Multiple patterns with a match",
			namespace:        "bar",
			namespacePattern: []string{"foo-*", "bar", "baz"},
			expectedResult:   true,
			expectError:      false,
		},
		{
			name:             "Multiple patterns with no match",
			namespace:        "bar",
			namespacePattern: []string{"foo-*", "baz"},
			expectedResult:   false,
			expectError:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := matchesNamespace(tt.namespace, tt.namespacePattern)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func Test_name(t *testing.T) {
	tests := []struct {
		name           string
		prefix         string
		provider       string
		namespace      string
		serviceAccount string
		expectedResult string
	}{
		{
			name:           "Basic case",
			prefix:         "foo_",
			provider:       "aws_",
			namespace:      "bar",
			serviceAccount: "my-service-account",
			expectedResult: "foo_aws_bar_my-service-account",
		},
		{
			name:           "Empty prefix",
			prefix:         "",
			provider:       "gcp_",
			namespace:      "bar",
			serviceAccount: "my-service-account",
			expectedResult: "gcp_bar_my-service-account",
		},
		{
			name:           "Empty provider",
			prefix:         "foo_",
			provider:       "",
			namespace:      "bar",
			serviceAccount: "my-service-account",
			expectedResult: "foo_bar_my-service-account",
		},
		{
			name:           "Empty namespace",
			prefix:         "foo_",
			provider:       "gcp_",
			namespace:      "",
			serviceAccount: "my-service-account",
			expectedResult: "foo_gcp__my-service-account",
		},
		{
			name:           "Empty serviceAccount",
			prefix:         "foo_",
			provider:       "aws_",
			namespace:      "bar",
			serviceAccount: "",
			expectedResult: "foo_aws_bar_",
		},
		{
			name:           "All empty values",
			prefix:         "",
			provider:       "",
			namespace:      "",
			serviceAccount: "",
			expectedResult: "_",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := name(tt.prefix, tt.provider, tt.namespace, tt.serviceAccount)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func Test_parseKey(t *testing.T) {
	tests := []struct {
		name           string
		key            string
		prefix         string
		provider       string
		expectedNs     string
		expectedName   string
		expectedResult bool
	}{
		{
			name:           "Valid key with exact match",
			key:            "foo_aws_bar_my-service-account",
			prefix:         "foo",
			provider:       "aws",
			expectedNs:     "bar",
			expectedName:   "my-service-account",
			expectedResult: true,
		},
		{
			name:           "Invalid prefix",
			key:            "foo_aws_bar_my-service-account",
			prefix:         "gcp",
			provider:       "aws",
			expectedNs:     "",
			expectedName:   "",
			expectedResult: false,
		},
		{
			name:           "Invalid provider",
			key:            "foo_aws_bar_my-service-account",
			prefix:         "foo",
			provider:       "gcp",
			expectedNs:     "",
			expectedName:   "",
			expectedResult: false,
		},
		{
			name:           "Key with missing parts",
			key:            "foo_aws_bar",
			prefix:         "foo",
			provider:       "aws",
			expectedNs:     "",
			expectedName:   "",
			expectedResult: false,
		},
		{
			name:           "Key with extra parts",
			key:            "foo_aws_bar_my-service-account_extra",
			prefix:         "foo",
			provider:       "aws",
			expectedNs:     "",
			expectedName:   "",
			expectedResult: false,
		},
		{
			name:           "Valid key with different provider",
			key:            "foo_gcp_prod_svc-prod",
			prefix:         "foo",
			provider:       "gcp",
			expectedNs:     "prod",
			expectedName:   "svc-prod",
			expectedResult: true,
		},
		{
			name:           "Invalid structure (no underscores)",
			key:            "fooawsbarmyserviceaccount",
			prefix:         "foo",
			provider:       "aws",
			expectedNs:     "",
			expectedName:   "",
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns, sa, result := parseKey(tt.key, tt.prefix, tt.provider)
			assert.Equal(t, tt.expectedResult, result)
			assert.Equal(t, tt.expectedNs, ns)
			assert.Equal(t, tt.expectedName, sa)
		})
	}
}
