package main

import "testing"

// Names that do not have exactly four underscore separated segments are the
// ones that used to slip through: the greedy segments absorbed the extra
// underscores and the provider came out as a namespace or prefix.
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
			name:    "extra segment",
			account: "prod_github_myns_myapp_2",
		},
		{
			name:    "extra segments",
			account: "prod_github_myns_myapp_extra_more",
		},
		{
			name:    "underscore in namespace",
			account: "prod_github_my_ns_app",
		},
		{
			name:    "too few segments",
			account: "prod_aws_myns",
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
