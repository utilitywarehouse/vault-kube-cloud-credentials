package main

import "testing"

func TestEnvOr(t *testing.T) {
	t.Setenv("VKCC_TEST_VALUE", "from-env")

	if got := envOr("VKCC_TEST_VALUE", "fallback"); got != "from-env" {
		t.Errorf("envOr() = %q, want %q", got, "from-env")
	}

	if got := envOr("VKCC_TEST_MISSING", "fallback"); got != "fallback" {
		t.Errorf("envOr() = %q, want %q", got, "fallback")
	}
}

// Only the first two segments are structural: the provider is pinned so a
// name cannot parse into a wrong provider, while the namespace and service
// account (or GitHub permission set) may contain underscores.
func TestAccountProvider(t *testing.T) {
	tests := []struct {
		name    string
		account string
		want    string
		ok      bool
	}{
		{
			name:    "aws",
			account: "prod_aws_sys-prom_thanos-compact",
			want:    "aws",
			ok:      true,
		},
		{
			name:    "gcp",
			account: "dev_gcp_data-science_langfuse",
			want:    "gcp",
			ok:      true,
		},
		{
			name:    "github",
			account: "exp-1_github_data-science_langfuse",
			want:    "github",
			ok:      true,
		},
		{
			name:    "underscore in service account",
			account: "prod_github_myns_myapp_2",
			want:    "github",
			ok:      true,
		},
		{
			name:    "multiple underscores in service account",
			account: "prod_github_myns_myapp_extra_more",
			want:    "github",
			ok:      true,
		},
		{
			name:    "underscore in namespace",
			account: "prod_github_my_ns_app",
			want:    "github",
			ok:      true,
		},
		{
			name:    "github permission set with underscore",
			account: "k8s_github_uw_ro_k8s",
			want:    "github",
			ok:      true,
		},
		{
			name:    "github permission set without underscore",
			account: "k8s_github_readonly",
			want:    "github",
			ok:      true,
		},
		{
			name:    "short account name",
			account: "prod_aws_myns",
			want:    "aws",
			ok:      true,
		},
		{
			name:    "wrong provider position",
			account: "prod_myns_github_myapp",
		},
		{
			name:    "no prefix",
			account: "myrole",
		},
		{
			name:    "leading junk",
			account: "x!prod_github_myns_myapp",
		},
		{
			name:    "trailing junk",
			account: "prod_github_myns_myapp!",
		},
		{
			name:    "leading space",
			account: " prod_github_myns_myapp",
		},
		{
			name:    "empty",
			account: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, ok := accountProvider(tt.account)
			if ok != tt.ok {
				t.Errorf("accountProvider(%q) ok = %v, want %v", tt.account, ok, tt.ok)
			}
			if provider != tt.want {
				t.Errorf("accountProvider(%q) provider = %q, want %q", tt.account, provider, tt.want)
			}
		})
	}
}
