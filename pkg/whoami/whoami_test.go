package whoami

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// buildFakeJWT creates a minimal JWT with just an exp claim for testing
func buildFakeJWT(exp int64) string {
	header  := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, exp)))
	return header + "." + payload + ".fakesignature"
}

// ── JWT parsing ──────────────────────────────────────────────────────────────

func TestParseJWTExpiry_ValidToken(t *testing.T) {
	exp := time.Now().Add(2 * time.Hour).Unix()
	result, err := parseJWTExpiry(buildFakeJWT(exp))
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if result == "EXPIRED" {
		t.Fatal("expected not expired, got EXPIRED")
	}
	t.Logf("output: %s", result)
}

func TestParseJWTExpiry_ExpiredToken(t *testing.T) {
	exp := time.Now().Add(-1 * time.Hour).Unix()
	result, err := parseJWTExpiry(buildFakeJWT(exp))
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if result != "EXPIRED" {
		t.Fatalf("expected EXPIRED, got: %s", result)
	}
}

func TestParseJWTExpiry_NotAJWT(t *testing.T) {
	_, err := parseJWTExpiry("not-a-jwt-token")
	if err == nil {
		t.Fatal("expected error for non-JWT, got nil")
	}
}

func TestParseJWTExpiry_TwoParts(t *testing.T) {
	_, err := parseJWTExpiry("header.payload")
	if err == nil {
		t.Fatal("expected error for 2-part token")
	}
}

func TestParseJWTExpiry_MissingExpClaim(t *testing.T) {
	// JWT with no exp field — must NOT panic, must return error
	header  := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user","iat":1000}`))
	token := header + "." + payload + ".sig"
	_, err := parseJWTExpiry(token)
	if err == nil {
		t.Fatal("expected error for missing exp claim, got nil")
	}
}

func TestParseJWTExpiry_WrongExpType(t *testing.T) {
	// exp is a string, not a number — must NOT panic
	header  := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":"not-a-number"}`))
	token := header + "." + payload + ".sig"
	_, err := parseJWTExpiry(token)
	if err == nil {
		t.Fatal("expected error for wrong exp type, got nil")
	}
}

// ── Auth method detection ────────────────────────────────────────────────────

func TestGroupsNote_TokenAuth(t *testing.T) {
	authInfo := &clientcmdapi.AuthInfo{Token: "some-token"}
	note := groupsNoteForAuthMethod(authInfo)
	if note != "" {
		t.Fatalf("expected empty note for token auth, got: %s", note)
	}
}

func TestGroupsNote_CertAuth(t *testing.T) {
	authInfo := &clientcmdapi.AuthInfo{ClientCertificate: "/path/to/cert"}
	note := groupsNoteForAuthMethod(authInfo)
	if !contains(note, "certificate") {
		t.Fatalf("expected certificate note, got: %s", note)
	}
}

func TestGroupsNote_ExecAuth(t *testing.T) {
	authInfo := &clientcmdapi.AuthInfo{
		Exec: &clientcmdapi.ExecConfig{Command: "aws"},
	}
	note := groupsNoteForAuthMethod(authInfo)
	if !contains(note, "exec") {
		t.Fatalf("expected exec note, got: %s", note)
	}
}

func TestGroupsNote_NilAuthInfo(t *testing.T) {
	note := groupsNoteForAuthMethod(nil)
	if note == "" {
		t.Fatal("expected non-empty note for nil authInfo")
	}
}

// ── Token expiry resolution ──────────────────────────────────────────────────

func TestResolveTokenExpiry_CertAuth(t *testing.T) {
	authInfo := &clientcmdapi.AuthInfo{ClientCertificate: "/path/to/cert"}
	result := resolveTokenExpiry(authInfo)
	if !contains(result, "certificate") {
		t.Fatalf("expected certificate message, got: %s", result)
	}
}

func TestResolveTokenExpiry_ExecAuth(t *testing.T) {
	authInfo := &clientcmdapi.AuthInfo{
		Exec: &clientcmdapi.ExecConfig{Command: "gke-gcloud-auth-plugin"},
	}
	result := resolveTokenExpiry(authInfo)
	if !contains(result, "exec") {
		t.Fatalf("expected exec message, got: %s", result)
	}
}

func TestResolveTokenExpiry_NilAuthInfo(t *testing.T) {
	result := resolveTokenExpiry(nil)
	if result == "" {
		t.Fatal("expected non-empty result for nil authInfo")
	}
}

// ── checks list — API group correctness ──────────────────────────────────────
// This test would have caught the deployments/apps bug: SAR without Group="apps"
// silently returns denied for apps-group resources, giving a confident-looking wrong ✗.

var appsResources = map[string]bool{
	"deployments":  true,
	"replicasets":  true,
	"daemonsets":   true,
	"statefulsets": true,
}

func TestChecks_APIGroupsCorrect(t *testing.T) {
	for _, c := range checks {
		wantApps := appsResources[c.resource]
		if wantApps && c.group != "apps" {
			t.Errorf("check %q %q: expected group \"apps\", got %q — SAR will silently return denied", c.verb, c.resource, c.group)
		}
		if !wantApps && c.group == "apps" {
			t.Errorf("check %q %q: unexpected group \"apps\" for a core-group resource", c.verb, c.resource)
		}
	}
}

// ── PermCheck struct ─────────────────────────────────────────────────────────

func TestPermCheck_Allowed(t *testing.T) {
	p := PermCheck{Verb: "get", Resource: "pods", Allowed: true}
	if !p.Allowed {
		t.Fatal("expected allowed=true")
	}
}

func TestPermCheck_Denied(t *testing.T) {
	p := PermCheck{Verb: "delete", Resource: "pods", Allowed: false}
	if p.Allowed {
		t.Fatal("expected allowed=false")
	}
}

// ── helper ───────────────────────────────────────────────────────────────────
func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) >= len(substr) &&
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}
