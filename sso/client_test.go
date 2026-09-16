package sso

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func testClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	client := New(Config{
		BaseURL:               server.URL,
		ClientID:              "the-client",
		ClientSecret:          "the-secret",
		RedirectURI:           "http://localhost:3001/auth/callback",
		PostLogoutRedirectURI: "http://localhost:3001/auth/logout/callback",
		Scopes:                "openid profile email",
		IDTokenAlg:            AlgHS256,
		SkipDiscovery:         true,
	})

	return client, server
}

func TestAuthorizationURLCarriesEverythingTheServerNeeds(t *testing.T) {
	client, server := testClient(t, func(http.ResponseWriter, *http.Request) {})

	req, err := NewAuthRequest()

	if err != nil {
		t.Fatalf("NewAuthRequest() returned %v", err)
	}

	req.Prompt = "login"
	req.MaxAge = 300

	raw, err := client.AuthorizationURL(context.Background(), req)

	if err != nil {
		t.Fatalf("AuthorizationURL() returned %v", err)
	}

	parsed, err := url.Parse(raw)

	if err != nil {
		t.Fatalf("the authorization URL does not parse: %v", err)
	}

	if want := server.URL + "/web/openid/auth"; strings.Split(raw, "?")[0] != want {
		t.Errorf("authorization endpoint = %q, want %q", strings.Split(raw, "?")[0], want)
	}

	query := parsed.Query()

	expected := map[string]string{
		"response_type":         "code",
		"client_id":             "the-client",
		"redirect_uri":          "http://localhost:3001/auth/callback",
		"scope":                 "openid profile email",
		"state":                 req.State,
		"nonce":                 req.Nonce,
		"code_challenge":        req.PKCE.Challenge,
		"code_challenge_method": "S256",
		"prompt":                "login",
		"max_age":               "300",
	}

	for key, want := range expected {
		if got := query.Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}

	// The verifier is the secret half. If it ever reaches the query string, PKCE
	// protects nothing.
	if strings.Contains(raw, req.PKCE.Verifier) {
		t.Error("the code verifier leaked into the authorization URL")
	}
}

func TestExchangeCodeSendsAFormEncodedGrant(t *testing.T) {
	var body url.Values
	var contentType string

	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body, _ = url.ParseQuery(string(raw))
		contentType = r.Header.Get("Content-Type")

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"at","token_type":"Bearer","expires_in":3600,"scope":"openid","id_token":"it","refresh_token":"rt"}`))
	})

	tokens, err := client.ExchangeCode(context.Background(), "the-code", "the-verifier")

	if err != nil {
		t.Fatalf("ExchangeCode() returned %v", err)
	}

	// JSON here returns 422 from the server, so the encoding is not incidental.
	if contentType != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded", contentType)
	}

	expected := map[string]string{
		"grant_type":    "authorization_code",
		"code":          "the-code",
		"code_verifier": "the-verifier",
		"redirect_uri":  "http://localhost:3001/auth/callback",
		"client_id":     "the-client",
		"client_secret": "the-secret",
	}

	for key, want := range expected {
		if got := body.Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}

	if tokens.ExpiresIn != 3600 || tokens.RefreshToken != "rt" {
		t.Errorf("token response decoded as %+v", tokens)
	}
}

func TestExchangeCodeOmitsTheVerifierWhenPKCEWasNotUsed(t *testing.T) {
	var body url.Values

	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body, _ = url.ParseQuery(string(raw))

		w.Write([]byte(`{"access_token":"at","expires_in":60}`))
	})

	if _, err := client.ExchangeCode(context.Background(), "the-code", ""); err != nil {
		t.Fatalf("ExchangeCode() returned %v", err)
	}

	// The server rejects a code_verifier that was never challenged, so sending
	// an empty one is worse than sending none.
	if _, present := body["code_verifier"]; present {
		t.Error("code_verifier was sent for a request that carried no challenge")
	}
}

func TestTokenErrorsKeepTheirOAuthShape(t *testing.T) {
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant","error_description":"the authorization code is not valid"}`))
	})

	_, err := client.ExchangeCode(context.Background(), "stale", "verifier")

	if err == nil {
		t.Fatal("a 400 from the token endpoint produced no error")
	}

	oauthErr, ok := err.(*Error)

	if !ok {
		t.Fatalf("error is %T, want *sso.Error so the code can be shown to the user", err)
	}

	if oauthErr.Code != "invalid_grant" {
		t.Errorf("error code = %q, want invalid_grant", oauthErr.Code)
	}

	if oauthErr.Status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", oauthErr.Status)
	}
}

func TestErrorsFallBackToFastAPIDetail(t *testing.T) {
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"detail":"invalid oauth client id"}`))
	})

	_, err := client.ExchangeCode(context.Background(), "code", "")

	if err == nil {
		t.Fatal("a 403 produced no error")
	}

	if !strings.Contains(err.Error(), "invalid oauth client id") {
		t.Errorf("error = %q, want it to carry the detail from the body", err)
	}
}

func TestRefreshUsesTheRefreshGrant(t *testing.T) {
	var body url.Values

	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body, _ = url.ParseQuery(string(raw))

		w.Write([]byte(`{"access_token":"new-at","expires_in":3600,"refresh_token":"rotated-rt"}`))
	})

	tokens, err := client.Refresh(context.Background(), "old-rt")

	if err != nil {
		t.Fatalf("Refresh() returned %v", err)
	}

	if body.Get("grant_type") != "refresh_token" || body.Get("refresh_token") != "old-rt" {
		t.Errorf("refresh body = %v", body)
	}

	// Rotation is the behaviour callers have to persist against.
	if tokens.RefreshToken != "rotated-rt" {
		t.Errorf("refresh_token = %q, want the rotated value", tokens.RefreshToken)
	}
}

func TestUserInfoSendsTheBearerToken(t *testing.T) {
	var authorization string

	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get("Authorization")

		w.Write([]byte(`{"sub":"9c1e","name":"Jane Doe","email":"jane@example.com"}`))
	})

	info, err := client.UserInfo(context.Background(), "the-access-token")

	if err != nil {
		t.Fatalf("UserInfo() returned %v", err)
	}

	if authorization != "Bearer the-access-token" {
		t.Errorf("Authorization = %q", authorization)
	}

	if info.Sub != "9c1e" || info.Name != "Jane Doe" {
		t.Errorf("userinfo decoded as %+v", info)
	}
}

func TestUserInfoRejectsAResponseWithoutSub(t *testing.T) {
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		// What /users/me returns: Nuanu's own field names, an `id` where a
		// UserInfo response must carry `sub`.
		w.Write([]byte(`{"id":"9c1e","full_name":"Jane Doe"}`))
	})

	if _, err := client.UserInfo(context.Background(), "token"); err == nil {
		t.Error("a response with no sub was accepted as a UserInfo response")
	}
}

func TestLogoutURLCarriesTheHintAndState(t *testing.T) {
	client, server := testClient(t, func(http.ResponseWriter, *http.Request) {})

	raw, err := client.LogoutURL(context.Background(), "the-id-token", "the-state")

	if err != nil {
		t.Fatalf("LogoutURL() returned %v", err)
	}

	parsed, _ := url.Parse(raw)
	query := parsed.Query()

	if strings.Split(raw, "?")[0] != server.URL+"/web/openid/logout" {
		t.Errorf("logout endpoint = %q", raw)
	}

	expected := map[string]string{
		"post_logout_redirect_uri": "http://localhost:3001/auth/logout/callback",
		"client_id":                "the-client",
		"id_token_hint":            "the-id-token",
		"state":                    "the-state",
	}

	for key, want := range expected {
		if got := query.Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}
