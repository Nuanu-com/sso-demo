package web

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nuanu/sso-demo/sso"
)

func jwtWithPayload(t *testing.T, payload map[string]any) string {
	t.Helper()

	encoded, err := json.Marshal(payload)

	if err != nil {
		t.Fatalf("unable to encode the test payload: %v", err)
	}

	return strings.Join([]string{
		base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`)),
		base64.RawURLEncoding.EncodeToString(encoded),
		"signature",
	}, ".")
}

func TestDecodeClaimsOrdersRegisteredClaimsFirst(t *testing.T) {
	token := jwtWithPayload(t, map[string]any{
		"zeta":  "last",
		"nonce": "n",
		"sub":   "9c1e",
		"iss":   "https://sso.example.com",
		"aud":   "client",
		"alpha": "also last",
	})

	claims := decodeClaims(token)

	var names []string

	for _, claim := range claims {
		names = append(names, claim.Name)
	}

	want := []string{"iss", "sub", "aud", "nonce", "alpha", "zeta"}

	if len(names) != len(want) {
		t.Fatalf("decoded %v, want %v", names, want)
	}

	for i := range want {
		if names[i] != want[i] {
			t.Errorf("claim %d = %q, want %q (full order %v)", i, names[i], want[i], names)
		}
	}
}

func TestDecodeClaimsAnnotatesTimestamps(t *testing.T) {
	claims := decodeClaims(jwtWithPayload(t, map[string]any{"exp": 1700000000}))

	if len(claims) != 1 {
		t.Fatalf("decoded %d claims, want 1", len(claims))
	}

	// A bare 1700000000 on screen tells nobody anything.
	if claims[0].Value != "1700000000" {
		t.Errorf("exp rendered as %q, want the integer unchanged", claims[0].Value)
	}

	if claims[0].Note == "" {
		t.Error("exp carries no human-readable note")
	}
}

func TestDecodeClaimsIsSafeOnGarbage(t *testing.T) {
	for _, token := range []string{"", "not-a-jwt", "a.b", "a.!!!.c", "a." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".c"} {
		if claims := decodeClaims(token); claims != nil {
			t.Errorf("decodeClaims(%q) = %v, want nil", token, claims)
		}
	}
}

func TestPreviewTokenNeverShowsAUsableToken(t *testing.T) {
	token := strings.Repeat("a", 200) + "END123"

	preview := previewToken(token)

	if strings.Contains(token, preview) {
		t.Error("the preview is a verbatim substring of the token")
	}

	if !strings.Contains(preview, "206 chars") {
		t.Errorf("preview = %q, want it to state the length", preview)
	}

	if previewToken("") != "" {
		t.Error("an absent token should preview as nothing at all")
	}

	// Something too short to elide is masked rather than half-shown.
	if short := previewToken("shorty"); strings.Contains(short, "shorty") {
		t.Errorf("preview = %q, want a masked value", short)
	}
}

// The two fixtures the view tests build a provider summary from.
func testConfig() sso.Config {
	return sso.Config{
		BaseURL:               "https://sso.example.com",
		ClientID:              "the-client",
		ClientSecret:          "the-secret",
		RedirectURI:           "http://localhost:3001/auth/callback",
		PostLogoutRedirectURI: "http://localhost:3001/auth/logout/callback",
		Scopes:                "openid profile email phone",
		IDTokenAlg:            sso.AlgHS256,
	}
}

func defaultTestDiscovery() sso.Discovery {
	return sso.DefaultDiscovery("https://sso.example.com")
}
