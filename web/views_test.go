package web

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/template/html/v3"

	"github.com/nuanu/sso-demo/config"
	"github.com/nuanu/sso-demo/core"
	"github.com/nuanu/sso-demo/session"
)

// The dashboard is the one page no end-to-end test can reach: rendering it
// needs a real sign-in, and the suite deliberately runs without an identity
// provider. Rendering the templates directly catches the failure that would
// otherwise only appear in front of a signed-in user - a renamed assign, a
// missing template function, a typo in a field.
func renderer(t *testing.T) *html.Engine {
	t.Helper()

	config.InitEnv()

	engine := html.New("../views", ".html")

	core.AssetHtml(engine)
	core.Helpers(engine)

	if err := engine.Load(); err != nil {
		t.Fatalf("unable to load the views: %v", err)
	}

	return engine
}

func render(t *testing.T, engine *html.Engine, template string, assigns fiber.Map) string {
	t.Helper()

	var out bytes.Buffer

	if err := engine.Render(&out, template, assigns, "layouts/app"); err != nil {
		t.Fatalf("rendering %s failed: %v", template, err)
	}

	return out.String()
}

func demoProvider() fiber.Map {
	return providerSummary(
		defaultTestDiscovery(),
		testConfig(),
	)
}

func TestDashboardRendersASignedInSession(t *testing.T) {
	engine := renderer(t)

	user := session.User{
		Sub:         "9c1e0000-0000-4000-8000-000000000000",
		Name:        "Jane Doe",
		Email:       "jane@example.com",
		PhoneNumber: "+6281234567890",
		Nationality: "Indonesia",
	}

	idToken := jwtWithPayload(t, map[string]any{
		"iss":   "https://sso.example.com",
		"sub":   user.Sub,
		"aud":   "the-client",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"nonce": "the-nonce",
	})

	out := render(t, engine, "pages/dashboard", fiber.Map{
		"User":     user,
		"Provider": demoProvider(),
		"Tokens": fiber.Map{
			"Scope":        "openid email",
			"ExpiresAt":    time.Now().Add(time.Hour).Format(time.RFC3339),
			"Expired":      false,
			"HasRefresh":   true,
			"IDTokenAlg":   "HS256",
			"RefreshedAt":  "",
			"AccessTokenP": previewToken(strings.Repeat("a", 300)),
			"IDTokenP":     previewToken(idToken),
			"RefreshP":     previewToken(strings.Repeat("r", 120)),
		},
		"IDClaims":     decodeClaims(idToken),
		"AccessClaims": decodeClaims(jwtWithPayload(t, map[string]any{"sub": user.Sub, "exp": time.Now().Unix()})),
		"SessionStatus": fiber.Map{
			"expiresInSeconds": 3600,
			"hasRefreshToken":  true,
			"refreshPath":      "/auth/refresh",
		},
	})

	for _, want := range []string{
		"Jane Doe",
		"jane@example.com",
		user.Sub,
		`data-island="session-status"`,
		"Sign out",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the dashboard does not render %q", want)
		}
	}

	// A signed-in page must not be shipping a usable token to the browser.
	if strings.Contains(out, strings.Repeat("r", 120)) {
		t.Error("the refresh token was rendered in full")
	}

	// data-props is what the island reads; html/template escapes it, so the
	// JSON arrives as &#34; rather than ".
	if !strings.Contains(out, "expiresInSeconds") {
		t.Error("the island received no props")
	}
}

func TestDashboardSurvivesAProfileWithOnlyASub(t *testing.T) {
	engine := renderer(t)

	// Every claim except sub is scope-dependent and omitted when it has no
	// value, so a profile this bare is a normal response, not an error.
	out := render(t, engine, "pages/dashboard", fiber.Map{
		"User":     session.User{Sub: "9c1e"},
		"Provider": demoProvider(),
		"Tokens": fiber.Map{
			"Scope": "openid", "ExpiresAt": "2026-01-01T00:00:00Z", "IDTokenAlg": "HS256",
			"HasRefresh": false, "AccessTokenP": "ab…cd (10 chars)", "IDTokenP": "", "RefreshP": "",
		},
		"IDClaims":      nil,
		"AccessClaims":  nil,
		"SessionStatus": fiber.Map{"expiresInSeconds": 0, "hasRefreshToken": false},
	})

	if !strings.Contains(out, "none issued") {
		t.Error("a session with no refresh token should say so")
	}

	if !strings.Contains(out, "No claims to show.") {
		t.Error("an undecodable token should render an empty-state, not a broken table")
	}
}

func TestIndexRendersBothConfigurationStates(t *testing.T) {
	engine := renderer(t)

	configured := render(t, engine, "pages/index", fiber.Map{
		"Configured": true,
		"Provider":   demoProvider(),
		"Checklist":  flowSteps(),
	})

	if !strings.Contains(configured, `href="/auth/login"`) {
		t.Error("a configured app does not offer sign-in")
	}

	unconfigured := demoProvider()
	unconfigured["ClientID"] = ""

	out := render(t, engine, "pages/index", fiber.Map{
		"Configured": false,
		"Provider":   unconfigured,
		"Checklist":  flowSteps(),
	})

	// With no client there is nothing to sign in to, so the page has to explain
	// the registration call instead of offering a button that cannot work.
	if strings.Contains(out, `href="/auth/login"`) {
		t.Error("an unconfigured app offers a sign-in link that cannot work")
	}

	if !strings.Contains(out, "oauth_clients") {
		t.Error("the unconfigured state does not show how to register a client")
	}
}

func TestErrorAndSignedOutPagesRender(t *testing.T) {
	engine := renderer(t)

	out := render(t, engine, "pages/error", fiber.Map{
		"Title":   "The code exchange failed",
		"Code":    "invalid_grant",
		"Message": "the authorization code is not valid",
		"Status":  400,
	})

	for _, want := range []string{"invalid_grant", "HTTP 400", "the authorization code is not valid"} {
		if !strings.Contains(out, want) {
			t.Errorf("the error page does not render %q", want)
		}
	}

	// The same template is used for failures that carry no OAuth error code.
	bare := render(t, engine, "pages/error", fiber.Map{"Title": "State mismatch", "Message": "no"})

	if !strings.Contains(bare, "State mismatch") {
		t.Error("the error page needs no error code to render")
	}

	verified := render(t, engine, "pages/signed-out", fiber.Map{"StateVerified": true, "StateReturned": true})

	if !strings.Contains(verified, "state verified") {
		t.Error("a verified logout state is not reported")
	}

	mismatched := render(t, engine, "pages/signed-out", fiber.Map{"StateVerified": false, "StateReturned": true})

	if !strings.Contains(mismatched, "state mismatch") {
		t.Error("a logout state that does not match is not reported")
	}
}
