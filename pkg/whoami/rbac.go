package whoami

import (
	"context"
	"fmt"
	"strings"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// GrantInfo describes which Role/RoleBinding grants a permission
type GrantInfo struct {
	Found       bool   `json:"found"`
	Role        string `json:"role,omitempty"`        // e.g. "ClusterRole/cluster-admin"
	Binding     string `json:"binding,omitempty"`     // e.g. "ClusterRoleBinding/admins"
	Unavailable bool   `json:"unavailable,omitempty"` // true if we lacked permission to list bindings
}

func (g GrantInfo) String() string {
	if g.Unavailable {
		return "(need list roles/bindings permission to show why)"
	}
	if !g.Found {
		return "no matching rule found"
	}
	return fmt.Sprintf("%s → %s", g.Role, g.Binding)
}

// FindGrants returns GrantInfo for each PermCheck — why is this allowed/denied?
//
// API call budget (fixed, not per-permission):
//   - 1× list RoleBindings in namespace
//   - 1× list ClusterRoleBindings
//   - 1× Get per unique Role name referenced by RoleBindings
//   - 1× Get per unique ClusterRole name referenced by any binding
//
// If listing is denied, GrantInfo.Unavailable is set instead of failing.
//
// Multiple bindings: first match wins. When a user is covered by several bindings
// that all grant the same permission, we show the first one the API returns.
// This is intentional for v0.1 — "which binding" is less important than "there is one".
func FindGrants(clientset kubernetes.Interface, username string, groups []string, namespace string, perms []PermCheck) []GrantInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rbs, rbErr := clientset.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	crbs, crbErr := clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})

	// Pre-fetch all roles referenced by bindings — one Get per unique name, done once.
	// This eliminates the N+1 pattern that would otherwise fire inside the per-permission loop.
	roleRules := map[string][]rbacv1.PolicyRule{}        // "Role/name" → rules
	clusterRoleRules := map[string][]rbacv1.PolicyRule{} // "ClusterRole/name" → rules

	if rbErr == nil {
		for _, rb := range rbs.Items {
			key := rb.RoleRef.Kind + "/" + rb.RoleRef.Name
			if _, seen := roleRules[key]; seen {
				continue
			}
			if rb.RoleRef.Kind == "ClusterRole" {
				cr, err := clientset.RbacV1().ClusterRoles().Get(ctx, rb.RoleRef.Name, metav1.GetOptions{})
				if err == nil {
					roleRules[key] = cr.Rules
				}
			} else {
				r, err := clientset.RbacV1().Roles(namespace).Get(ctx, rb.RoleRef.Name, metav1.GetOptions{})
				if err == nil {
					roleRules[key] = r.Rules
				}
			}
		}
	}

	if crbErr == nil {
		for _, crb := range crbs.Items {
			key := "ClusterRole/" + crb.RoleRef.Name
			if _, seen := clusterRoleRules[key]; seen {
				continue
			}
			cr, err := clientset.RbacV1().ClusterRoles().Get(ctx, crb.RoleRef.Name, metav1.GetOptions{})
			if err == nil {
				clusterRoleRules[key] = cr.Rules
			}
		}
	}

	grants := make([]GrantInfo, len(perms))

	for i, p := range perms {
		if rbErr != nil && crbErr != nil {
			grants[i] = GrantInfo{Unavailable: true}
			continue
		}

		if !p.Allowed {
			grants[i] = GrantInfo{Found: false}
			continue
		}

		verb := p.Verb
		resource := strings.Split(p.Resource, " ")[0] // strip "[namespace]" suffix from -A mode
		found := false

		// Check namespace RoleBindings — pure in-memory after pre-fetch above
		if rbErr == nil {
			for _, rb := range rbs.Items {
				if !subjectMatches(rb.Subjects, username, groups, namespace) {
					continue
				}
				key := rb.RoleRef.Kind + "/" + rb.RoleRef.Name
				rules, ok := roleRules[key]
				if !ok {
					continue
				}
				if ruleMatches(rules, verb, resource) {
					grants[i] = GrantInfo{
						Found:   true,
						Role:    key,
						Binding: "RoleBinding/" + rb.Name,
					}
					found = true
					break
				}
			}
		}

		// Check ClusterRoleBindings — pure in-memory after pre-fetch above
		if !found && crbErr == nil {
			for _, crb := range crbs.Items {
				if !subjectMatches(crb.Subjects, username, groups, namespace) {
					continue
				}
				key := "ClusterRole/" + crb.RoleRef.Name
				rules, ok := clusterRoleRules[key]
				if !ok {
					continue
				}
				if ruleMatches(rules, verb, resource) {
					grants[i] = GrantInfo{
						Found:   true,
						Role:    key,
						Binding: "ClusterRoleBinding/" + crb.Name,
					}
					found = true
					break
				}
			}
		}

		if !found {
			grants[i] = GrantInfo{Found: false}
		}
	}

	return grants
}

// subjectMatches returns true if username or any group is in the subjects list
func subjectMatches(subjects []rbacv1.Subject, username string, groups []string, namespace string) bool {
	for _, s := range subjects {
		switch s.Kind {
		case "User":
			if s.Name == username {
				return true
			}
		case "Group":
			for _, g := range groups {
				if s.Name == g {
					return true
				}
			}
		case "ServiceAccount":
			// match "system:serviceaccount:namespace:name" format
			// also match bare name when TokenReview was unavailable and username = kubeconfig authinfo name
			saName := fmt.Sprintf("system:serviceaccount:%s:%s", s.Namespace, s.Name)
			if saName == username || s.Name == username {
				return true
			}
		}
	}
	return false
}

// ruleMatches checks if any PolicyRule in the list covers the given verb+resource
func ruleMatches(rules []rbacv1.PolicyRule, verb, resource string) bool {
	for _, rule := range rules {
		if containsOrWildcard(rule.Verbs, verb) && containsOrWildcard(rule.Resources, resource) {
			return true
		}
	}
	return false
}

func containsOrWildcard(list []string, target string) bool {
	for _, item := range list {
		if item == "*" || item == target {
			return true
		}
	}
	return false
}
