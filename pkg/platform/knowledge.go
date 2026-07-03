package platform

// Knowledge holds platform-specific semantics for configuration fields.
// When a config field is empty/nil/zero, its meaning depends on the platform.
// This database captures those semantics for known fields.
type Knowledge struct {
	entries map[string]FieldSemantics
}

// FieldSemantics describes what a configuration field means when set to various values.
type FieldSemantics struct {
	Field          string
	EmptyMeaning   string
	Permissiveness string // PERMISSIVE, RESTRICTIVE, NEUTRAL
	Description    string
}

// NewKnowledge creates a Knowledge instance loaded with known platform semantics.
func NewKnowledge() *Knowledge {
	k := &Knowledge{
		entries: make(map[string]FieldSemantics),
	}
	k.loadK8sSemantics()
	return k
}

// Lookup returns the semantics for a field name, if known.
func (k *Knowledge) Lookup(field string) (FieldSemantics, bool) {
	fs, ok := k.entries[field]
	return fs, ok
}

func (k *Knowledge) loadK8sSemantics() {
	k.entries["audiences"] = FieldSemantics{
		Field:          "audiences",
		EmptyMeaning:   "Accept API server audience (all in-cluster pods)",
		Permissiveness: "PERMISSIVE",
		Description:    "TokenReview audiences field. Empty means accept the API server's default audience, which includes all service account tokens.",
	}
	k.entries["AllowedGroups"] = FieldSemantics{
		Field:          "AllowedGroups",
		EmptyMeaning:   "Authorize all authenticated users",
		Permissiveness: "PERMISSIVE",
		Description:    "When AllowedGroups is empty, the len==0 check returns true, authorizing any authenticated user.",
	}
	k.entries["email-domain"] = FieldSemantics{
		Field:          "email-domain",
		EmptyMeaning:   "Accept any email domain",
		Permissiveness: "PERMISSIVE",
		Description:    "Email domain validator. Empty or wildcard means accept any email address.",
	}
	k.entries["EmailDomain"] = FieldSemantics{
		Field:          "EmailDomain",
		EmptyMeaning:   "Accept any email domain",
		Permissiveness: "PERMISSIVE",
		Description:    "Email domain validator. Empty or wildcard means accept any email address.",
	}
	k.entries["InsecureSkipNonce"] = FieldSemantics{
		Field:          "InsecureSkipNonce",
		EmptyMeaning:   "OIDC nonce validation enabled (replay protection active)",
		Permissiveness: "RESTRICTIVE",
		Description:    "Zero value (false) means nonce validation is active. When set to true, skips OIDC nonce validation allowing token replay.",
	}
	k.entries["InsecureSkipVerify"] = FieldSemantics{
		Field:          "InsecureSkipVerify",
		EmptyMeaning:   "TLS certificate verification enabled (secure default)",
		Permissiveness: "RESTRICTIVE",
		Description:    "When false/empty, TLS certificates are verified. When true, certificates are not verified.",
	}
	k.entries["AllowedOrganizations"] = FieldSemantics{
		Field:          "AllowedOrganizations",
		EmptyMeaning:   "Accept users from any organization",
		Permissiveness: "PERMISSIVE",
		Description:    "Organization restriction for OAuth providers. Empty means accept all.",
	}
	k.entries["Namespace"] = FieldSemantics{
		Field:          "Namespace",
		EmptyMeaning:   "Watch all namespaces",
		Permissiveness: "PERMISSIVE",
		Description:    "Controller namespace scope. Empty means cluster-scoped watch.",
	}
	k.entries["ServiceAccountName"] = FieldSemantics{
		Field:          "ServiceAccountName",
		EmptyMeaning:   "Use default service account",
		Permissiveness: "NEUTRAL",
		Description:    "Pod service account. Empty uses the 'default' SA for the namespace.",
	}

	k.entries["sslMode"] = FieldSemantics{
		Field:          "sslMode",
		EmptyMeaning:   "SSL/TLS mode for database connections",
		Permissiveness: "PERMISSIVE",
		Description:    "When set to 'disable', database connections use plaintext. Passwords transmitted in cleartext.",
	}
	k.entries["SslMode"] = FieldSemantics{
		Field:          "SslMode",
		EmptyMeaning:   "SSL/TLS mode for database connections",
		Permissiveness: "PERMISSIVE",
		Description:    "When set to 'disable', database connections use plaintext. Passwords transmitted in cleartext.",
	}

	k.entries["KubeRBACProxy"] = FieldSemantics{
		Field:          "KubeRBACProxy",
		EmptyMeaning:   "No kube-rbac-proxy sidecar deployed. API endpoints have no auth.",
		Permissiveness: "PERMISSIVE",
		Description:    "When nil/absent, the operator does not inject a kube-rbac-proxy sidecar. The application's API is exposed without authentication or authorization.",
	}
	k.entries["OAuthProxy"] = FieldSemantics{
		Field:          "OAuthProxy",
		EmptyMeaning:   "No OAuth proxy sidecar deployed. API endpoints have no auth.",
		Permissiveness: "PERMISSIVE",
		Description:    "When nil/absent, the operator does not inject an OAuth proxy sidecar. The application's API is exposed without authentication.",
	}
	k.entries["Authorino"] = FieldSemantics{
		Field:          "Authorino",
		EmptyMeaning:   "No Authorino auth policy deployed.",
		Permissiveness: "PERMISSIVE",
		Description:    "When nil/absent, no Authorino-based auth policy is applied to the service.",
	}
}
