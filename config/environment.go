package config

import (
	"io/fs"
	"os"
	"strconv"
	"strings"
	"time"
)

type AppEnvType string

const (
	AppEnvLocal      AppEnvType = "local"
	AppEnvStaging    AppEnvType = "staging"
	AppEnvTest       AppEnvType = "test"
	AppEnvProduction AppEnvType = "production"
)

var AppEnv string
var ViteServerPort string
var ManifestData []byte

// Serving from these rather than from disk keeps the binary self contained.
var PublicFS fs.FS
var ViewsFS fs.FS

var NodeEnv string

// SessionSecret keys the session cookie. The demo stores tokens server side in
// the session store, so the cookie only ever carries an opaque id, but the
// secret still has to be stable across restarts or every browser is signed out
// on deploy.
var SessionSecret string
var SessionIdleTimeout time.Duration
var CookieSecure bool

// --- Nuanu SSO ----------------------------------------------------------
//
// SSOBaseURL is the only endpoint hard-coded anywhere: everything else is read
// from the discovery document at {SSO}/.well-known/openid-configuration, which
// is what SSO_INTEGRATION.md section 1a asks integrators to do.
var SSOBaseURL string
var SSOClientID string
var SSOClientSecret string
var SSORedirectURI string
var SSOPostLogoutRedirectURI string
var SSOScopes string

// SSOIDTokenAlg mirrors the `id_token_signed_response_alg` on your OauthClient
// row. It is a per-client server-side setting, so the demo cannot detect it -
// it has to be told. HS256 (the registration default) verifies against the
// client secret; RS256 verifies against the published JWKS.
var SSOIDTokenAlg string

// SSODepartmentID is optional; it selects the organization branding shown on
// the SSO login and registration pages.
var SSODepartmentID string

// SSOSkipDiscovery falls back to the documented default paths instead of
// fetching the discovery document, so the demo still boots when the IdP is
// unreachable (and so the e2e tests need no IdP at all).
var SSOSkipDiscovery bool

func InitEnv() {
	AppEnv = getEnv("APP_ENV", string(AppEnvLocal))
	ViteServerPort = getEnv("VITE_SERVER_PORT", "5173")
	NodeEnv = getEnv("NODE_ENV", "local")

	SessionSecret = getEnv("SESSION_SECRET", "dev-only-insecure-session-secret")
	SessionIdleTimeout = time.Duration(getEnvInt("SESSION_IDLE_TIMEOUT_MINUTES", 60)) * time.Minute
	CookieSecure = getEnvBool("COOKIE_SECURE", AppEnv == string(AppEnvProduction))

	SSOBaseURL = strings.TrimRight(getEnv("SSO_BASE_URL", "http://127.0.0.1:8000"), "/")
	SSOClientID = getEnv("SSO_CLIENT_ID", "")
	SSOClientSecret = getEnv("SSO_CLIENT_SECRET", "")
	SSORedirectURI = getEnv("SSO_REDIRECT_URI", "http://localhost:3001/auth/callback")
	SSOPostLogoutRedirectURI = getEnv("SSO_POST_LOGOUT_REDIRECT_URI", "http://localhost:3001/auth/logout/callback")
	SSOScopes = getEnv("SSO_SCOPES", "openid profile email phone")
	SSOIDTokenAlg = strings.ToUpper(getEnv("SSO_ID_TOKEN_ALG", "HS256"))
	SSODepartmentID = getEnv("SSO_DEPARTMENT_ID", "")
	SSOSkipDiscovery = getEnvBool("SSO_SKIP_DISCOVERY", false)
}

// Configured reports whether a client has been registered with the SSO server
// and wired into the environment. The demo still boots without one so it can
// render setup instructions rather than crash on an empty client_id.
func Configured() bool {
	return SSOClientID != "" && SSOClientSecret != ""
}

func getEnv(key string, fallback string) string {
	val := os.Getenv(key)

	if val != "" {
		return val
	}

	return fallback
}

func getEnvInt(key string, fallback int) int {
	val, err := strconv.Atoi(os.Getenv(key))

	if err != nil {
		return fallback
	}

	return val
}

func getEnvBool(key string, fallback bool) bool {
	val, err := strconv.ParseBool(os.Getenv(key))

	if err != nil {
		return fallback
	}

	return val
}
