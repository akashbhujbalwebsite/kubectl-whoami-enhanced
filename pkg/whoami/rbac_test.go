package whoami

import (
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
)

// ── subjectMatches ────────────────────────────────────────────────────────────

func TestSubjectMatches_User(t *testing.T) {
	subjects := []rbacv1.Subject{{Kind: "User", Name: "akash"}}
	if !subjectMatches(subjects, "akash", nil, "default") {
		t.Fatal("expected match for User")
	}
}

func TestSubjectMatches_UserNoMatch(t *testing.T) {
	subjects := []rbacv1.Subject{{Kind: "User", Name: "other"}}
	if subjectMatches(subjects, "akash", nil, "default") {
		t.Fatal("expected no match")
	}
}

func TestSubjectMatches_Group(t *testing.T) {
	subjects := []rbacv1.Subject{{Kind: "Group", Name: "dev-team"}}
	if !subjectMatches(subjects, "akash", []string{"dev-team", "staff"}, "default") {
		t.Fatal("expected match via group")
	}
}

func TestSubjectMatches_ServiceAccount(t *testing.T) {
	subjects := []rbacv1.Subject{{Kind: "ServiceAccount", Name: "limited-user", Namespace: "test-ns"}}
	if !subjectMatches(subjects, "system:serviceaccount:test-ns:limited-user", nil, "test-ns") {
		t.Fatal("expected match for ServiceAccount")
	}
}

func TestSubjectMatches_ServiceAccountBareName(t *testing.T) {
	// when TokenReview unavailable, username == bare SA name from kubeconfig
	subjects := []rbacv1.Subject{{Kind: "ServiceAccount", Name: "limited-user", Namespace: "test-ns"}}
	if !subjectMatches(subjects, "limited-user", nil, "test-ns") {
		t.Fatal("expected match via bare SA name fallback")
	}
}

func TestSubjectMatches_ServiceAccountNoMatch(t *testing.T) {
	subjects := []rbacv1.Subject{{Kind: "ServiceAccount", Name: "other", Namespace: "test-ns"}}
	if subjectMatches(subjects, "system:serviceaccount:test-ns:limited-user", nil, "test-ns") {
		t.Fatal("expected no match for wrong ServiceAccount")
	}
}

// ── ruleMatches ───────────────────────────────────────────────────────────────

func TestRuleMatches_ExactMatch(t *testing.T) {
	rules := []rbacv1.PolicyRule{
		{Verbs: []string{"get", "list"}, Resources: []string{"pods"}},
	}
	if !ruleMatches(rules, "get", "pods") {
		t.Fatal("expected match for get pods")
	}
}

func TestRuleMatches_Wildcard(t *testing.T) {
	rules := []rbacv1.PolicyRule{
		{Verbs: []string{"*"}, Resources: []string{"*"}},
	}
	if !ruleMatches(rules, "delete", "secrets") {
		t.Fatal("expected wildcard to match")
	}
}

func TestRuleMatches_NoMatch(t *testing.T) {
	rules := []rbacv1.PolicyRule{
		{Verbs: []string{"get"}, Resources: []string{"pods"}},
	}
	if ruleMatches(rules, "delete", "pods") {
		t.Fatal("expected no match for delete pods")
	}
}

func TestRuleMatches_EmptyRules(t *testing.T) {
	if ruleMatches([]rbacv1.PolicyRule{}, "get", "pods") {
		t.Fatal("expected no match for empty rules")
	}
}

// ── GrantInfo.String() ────────────────────────────────────────────────────────

func TestGrantInfo_Found(t *testing.T) {
	g := GrantInfo{Found: true, Role: "Role/pod-reader", Binding: "RoleBinding/dev-binding"}
	s := g.String()
	if !contains(s, "Role/pod-reader") || !contains(s, "RoleBinding/dev-binding") {
		t.Fatalf("unexpected output: %s", s)
	}
}

func TestGrantInfo_NotFound(t *testing.T) {
	g := GrantInfo{Found: false}
	if g.String() != "no matching rule found" {
		t.Fatalf("unexpected: %s", g.String())
	}
}

func TestGrantInfo_Unavailable(t *testing.T) {
	g := GrantInfo{Unavailable: true}
	if !contains(g.String(), "need list roles") {
		t.Fatalf("unexpected: %s", g.String())
	}
}

// ── containsOrWildcard ────────────────────────────────────────────────────────

func TestContainsOrWildcard_Match(t *testing.T) {
	if !containsOrWildcard([]string{"get", "list"}, "get") {
		t.Fatal("expected match")
	}
}

func TestContainsOrWildcard_Wildcard(t *testing.T) {
	if !containsOrWildcard([]string{"*"}, "delete") {
		t.Fatal("expected wildcard match")
	}
}

func TestContainsOrWildcard_NoMatch(t *testing.T) {
	if containsOrWildcard([]string{"get"}, "delete") {
		t.Fatal("expected no match")
	}
}
