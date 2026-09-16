package sso

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const discoveryBody = `{
  "issuer": "https://sso.example.com",
  "authorization_endpoint": "https://sso.example.com/web/openid/auth",
  "token_endpoint": "https://sso.example.com/api/v1/openid/token",
  "userinfo_endpoint": "https://sso.example.com/api/v1/openid/userinfo",
  "end_session_endpoint": "https://sso.example.com/web/openid/logout",
  "jwks_uri": "https://sso.example.com/public/jwks.json",
  "code_challenge_methods_supported": ["S256"]
}`

func TestDiscoveryReadsTheDocument(t *testing.T) {
	var hits int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != DiscoveryPath {
			t.Errorf("discovery was fetched from %q, want %q", r.URL.Path, DiscoveryPath)
		}

		hits++

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(discoveryBody))
	}))

	defer server.Close()

	client := New(Config{BaseURL: server.URL, ClientID: "client", ClientSecret: "secret"})

	doc := client.Discovery(context.Background())

	if doc.Fallback {
		t.Error("the document was read from the server but is marked as a fallback")
	}

	// The whole point of discovery: these are the server's URLs, not ones
	// derived from BaseURL.
	if doc.Issuer != "https://sso.example.com" {
		t.Errorf("issuer = %q, want the value from the document", doc.Issuer)
	}

	if doc.TokenEndpoint != "https://sso.example.com/api/v1/openid/token" {
		t.Errorf("token_endpoint = %q", doc.TokenEndpoint)
	}

	client.Discovery(context.Background())

	if hits != 1 {
		t.Errorf("discovery was fetched %d times, want it cached after the first", hits)
	}
}

func TestDiscoveryFallsBackWhenUnreachable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))

	base := server.URL
	server.Close()

	client := New(Config{BaseURL: base})

	doc := client.Discovery(context.Background())

	if !doc.Fallback {
		t.Error("an unreachable provider should produce a fallback document, not a zero one")
	}

	if doc.AuthorizationEndpoint != base+"/web/openid/auth" {
		t.Errorf("authorization_endpoint = %q, want the documented default path", doc.AuthorizationEndpoint)
	}

	if doc.Issuer != base {
		t.Errorf("issuer = %q, want %q", doc.Issuer, base)
	}
}

func TestDefaultDiscoveryTrimsTrailingSlash(t *testing.T) {
	// An issuer identifier must not carry a trailing slash, or it will not match
	// the iss claim the server signs into its tokens.
	doc := DefaultDiscovery("https://stg.sso.nuanu.com/")

	if doc.Issuer != "https://stg.sso.nuanu.com" {
		t.Errorf("issuer = %q, want no trailing slash", doc.Issuer)
	}

	if doc.JWKSURI != "https://stg.sso.nuanu.com/public/jwks.json" {
		t.Errorf("jwks_uri = %q", doc.JWKSURI)
	}
}
