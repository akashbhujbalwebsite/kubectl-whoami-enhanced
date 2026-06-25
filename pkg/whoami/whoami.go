package whoami

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	authv1  "k8s.io/api/authorization/v1"
	authnv1 "k8s.io/api/authentication/v1"
	metav1  "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/tools/clientcmd"
)

type Info struct {
	Context     string      `json:"context"`
	User        string      `json:"user"`
	Groups      []string    `json:"groups"`
	GroupsNote  string      `json:"groups_note,omitempty"`
	Namespace   string      `json:"namespace"`
	TokenExpiry string      `json:"token_expiry"`
	Permissions []PermCheck `json:"permissions"`
}

type PermCheck struct {
	Verb      string    `json:"verb"`
	Resource  string    `json:"resource"`
	Allowed   bool      `json:"allowed"`
	GrantedBy GrantInfo `json:"granted_by"`
}

var checks = []struct{ verb, resource, group string }{
	{"get", "pods", ""},
	{"list", "pods", ""},
	{"delete", "pods", ""},
	{"exec", "pods", ""},
	{"get", "deployments", "apps"},
	{"create", "deployments", "apps"},
	{"delete", "deployments", "apps"},
	{"get", "secrets", ""},
	{"get", "configmaps", ""},
	{"get", "nodes", ""},
}

func Run(namespace string, allNamespaces bool, outputJSON bool) error {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules, &clientcmd.ConfigOverrides{},
	)

	config, err := kubeConfig.ClientConfig()
	if err != nil {
		return fmt.Errorf("failed to load kubeconfig: %w", err)
	}

	rawConfig, err := kubeConfig.RawConfig()
	if err != nil {
		return fmt.Errorf("failed to read raw config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	currentContext := rawConfig.CurrentContext
	ctxObj := rawConfig.Contexts[currentContext]
	userName := ""
	if ctxObj != nil {
		userName = ctxObj.AuthInfo
	}

	authInfo := rawConfig.AuthInfos[userName]

	// Get groups + real username via TokenReview (token auth only)
	groups := []string{}
	groupsNote := groupsNoteForAuthMethod(authInfo)
	if authInfo != nil && authInfo.Token != "" {
		tr, err := clientset.AuthenticationV1().TokenReviews().Create(
			context.TODO(),
			&authnv1.TokenReview{
				Spec: authnv1.TokenReviewSpec{Token: authInfo.Token},
			},
			metav1.CreateOptions{},
		)
		if err == nil && tr.Status.Authenticated {
			userName = tr.Status.User.Username
			groups = tr.Status.User.Groups
		}
	}

	// Token expiry
	tokenExpiry := resolveTokenExpiry(authInfo)

	// Namespaces to check
	namespaces := []string{namespace}
	if allNamespaces {
		nsList, err := clientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
		if err == nil {
			namespaces = []string{}
			for _, ns := range nsList.Items {
				namespaces = append(namespaces, ns.Name)
			}
		}
	}

	// Parallel permission checks — goroutine per check, max 10 concurrent
	type indexedResult struct {
		idx   int
		check PermCheck
	}

	total := len(namespaces) * len(checks)
	resultsCh := make(chan indexedResult, total)
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	i := 0
	for _, ns := range namespaces {
		for _, c := range checks {
			wg.Add(1)
			go func(idx int, ns, verb, resource, group string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()

				sar := &authv1.SelfSubjectAccessReview{
					Spec: authv1.SelfSubjectAccessReviewSpec{
						ResourceAttributes: &authv1.ResourceAttributes{
							Namespace: ns,
							Verb:      verb,
							Resource:  resource,
							Group:     group,
						},
					},
				}
				res, err := clientset.AuthorizationV1().SelfSubjectAccessReviews().Create(
					ctx, sar, metav1.CreateOptions{},
				)
				allowed := err == nil && res.Status.Allowed
				label := resource
				if allNamespaces {
					label = fmt.Sprintf("%s [%s]", resource, ns)
				}
				resultsCh <- indexedResult{
					idx:   idx,
					check: PermCheck{Verb: verb, Resource: label, Allowed: allowed},
				}
			}(i, ns, c.verb, c.resource, c.group)
			i++
		}
	}

	wg.Wait()
	close(resultsCh)

	permChecks := make([]PermCheck, total)
	for r := range resultsCh {
		permChecks[r.idx] = r.check
	}

	// Enrich with Role/RoleBinding grant info (best effort — graceful if no RBAC read access)
	grants := FindGrants(clientset, userName, groups, namespace, permChecks)
	for i := range permChecks {
		permChecks[i].GrantedBy = grants[i]
	}

	info := Info{
		Context:     currentContext,
		User:        userName,
		Groups:      groups,
		GroupsNote:  groupsNote,
		Namespace:   strings.Join(namespaces, ", "),
		TokenExpiry: tokenExpiry,
		Permissions: permChecks,
	}

	if outputJSON {
		return printJSON(info)
	}
	printTable(info)
	return nil
}

// groupsNoteForAuthMethod returns an explanatory note when groups cannot be retrieved
func groupsNoteForAuthMethod(authInfo *clientcmdapi.AuthInfo) string {
	if authInfo == nil {
		return "no auth info found in kubeconfig"
	}
	if authInfo.Token != "" {
		return "" // TokenReview will fetch groups — no note needed
	}
	if authInfo.ClientCertificate != "" || len(authInfo.ClientCertificateData) > 0 {
		return "unavailable with certificate auth — groups are embedded in the client cert OU fields"
	}
	if authInfo.Exec != nil {
		return "unavailable with exec-based auth (OIDC/AWS IAM/GKE) — token is generated at runtime"
	}
	return "unavailable — auth method not recognised"
}

// resolveTokenExpiry returns a human-readable expiry string based on auth method
func resolveTokenExpiry(authInfo *clientcmdapi.AuthInfo) string {
	if authInfo == nil {
		return "unknown"
	}
	if authInfo.Token != "" {
		exp, err := parseJWTExpiry(authInfo.Token)
		if err != nil {
			// Static token with no JWT structure (e.g. opaque service account tokens)
			return "static token (no expiry claim)"
		}
		return exp
	}
	if authInfo.ClientCertificate != "" || len(authInfo.ClientCertificateData) > 0 {
		return "N/A (certificate auth — check cert expiry separately)"
	}
	if authInfo.Exec != nil {
		return "managed by exec plugin (OIDC/AWS IAM/GKE)"
	}
	return "unknown"
}

// parseJWTExpiry decodes the exp claim from a JWT token safely — no panics
func parseJWTExpiry(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("not a JWT: expected 3 parts, got %d", len(parts))
	}
	payload := parts[1]
	// restore base64 padding
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}
	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return "", fmt.Errorf("failed to base64-decode JWT payload: %w", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return "", fmt.Errorf("failed to parse JWT JSON: %w", err)
	}
	// two-value assertion — never panics if exp is missing or wrong type
	exp, ok := claims["exp"].(float64)
	if !ok {
		return "", fmt.Errorf("exp claim missing or not a number")
	}
	expTime := time.Unix(int64(exp), 0)
	remaining := time.Until(expTime)
	if remaining < 0 {
		return "EXPIRED", nil
	}
	h := int(remaining.Hours())
	m := int(remaining.Minutes()) % 60
	return fmt.Sprintf("expires in %dh %dm (at %s)", h, m, expTime.Format("2006-01-02 15:04:05")), nil
}

func printTable(info Info) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "\n KUBECTL WHOAMI — Enhanced")
	fmt.Fprintln(w, strings.Repeat("─", 55))
	fmt.Fprintf(w, " Context:\t%s\n", info.Context)
	fmt.Fprintf(w, " User:\t%s\n", info.User)
	if len(info.Groups) > 0 {
		fmt.Fprintf(w, " Groups:\t%s\n", strings.Join(info.Groups, ", "))
	} else if info.GroupsNote != "" {
		fmt.Fprintf(w, " Groups:\t(%s)\n", info.GroupsNote)
	} else {
		fmt.Fprintf(w, " Groups:\t(none)\n")
	}
	fmt.Fprintf(w, " Namespace:\t%s\n", info.Namespace)
	fmt.Fprintf(w, " Token:\t%s\n", info.TokenExpiry)
	fmt.Fprintln(w, strings.Repeat("─", 55))
	fmt.Fprintln(w, " PERMISSIONS")
	fmt.Fprintln(w, strings.Repeat("─", 55))
	fmt.Fprintf(w, " %-10s %-20s %-6s %s\n", "VERB", "RESOURCE", "ACCESS", "REASON")
	for _, p := range info.Permissions {
		symbol := "✓"
		if !p.Allowed {
			symbol = "✗"
		}
		fmt.Fprintf(w, " %-10s %-20s %-6s %s\n", p.Verb, p.Resource, symbol, p.GrantedBy.String())
	}
	fmt.Fprintln(w, strings.Repeat("─", 55))
	fmt.Fprintln(w, " NOTE: v0.1.0 checks core resources only. CRDs not included.")
	fmt.Fprintln(w, strings.Repeat("─", 55))
	w.Flush()
}

func printJSON(info Info) error {
	b, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}
