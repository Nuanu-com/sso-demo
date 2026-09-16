// Package session keeps the demo's sign-in state server side.
//
// Everything the browser holds is an opaque session id in a cookie. Tokens -
// the refresh token in particular - never reach JavaScript, never land in
// localStorage, and never travel in a readable cookie.
package session

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v3"
	fibersession "github.com/gofiber/fiber/v3/middleware/session"

	"github.com/nuanu/sso-demo/config"
	"github.com/nuanu/sso-demo/sso"
)

const (
	keyState        = "sso_state"
	keyNonce        = "sso_nonce"
	keyVerifier     = "sso_verifier"
	keyLogoutState  = "sso_logout_state"
	keyUser         = "user"
	keyTokens       = "tokens"
	keyLastRefresh  = "tokens_refreshed_at"
	keySignedInAt   = "signed_in_at"
	keyIDTokenAlg   = "id_token_alg"
	keyGrantedScope = "granted_scope"
)

// Tokens is what the token endpoint gave us, plus the absolute expiry derived
// from expires_in.
type Tokens struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	IDToken      string    `json:"id_token"`
	Scope        string    `json:"scope"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func (t Tokens) Expired() bool { return time.Now().After(t.ExpiresAt) }

func (t Tokens) ExpiresIn() time.Duration {
	return time.Until(t.ExpiresAt).Truncate(time.Second)
}

// User is the profile as the demo displays it: UserInfo's claims plus the two
// values that come from the id_token rather than from the profile endpoint.
type User struct {
	Sub         string    `json:"sub"`
	Name        string    `json:"name,omitempty"`
	Email       string    `json:"email,omitempty"`
	Picture     string    `json:"picture,omitempty"`
	Birthdate   string    `json:"birthdate,omitempty"`
	Nationality string    `json:"nationality,omitempty"`
	PhoneNumber string    `json:"phone_number,omitempty"`
	AuthTime    time.Time `json:"auth_time,omitzero"`
	SignedInAt  time.Time `json:"signed_in_at"`
}

// Middleware stores sessions in memory, which is why this demo needs no
// database. A real deployment wants a shared store (Redis, Postgres) so that
// sessions survive a restart and work behind more than one instance.
func Middleware() fiber.Handler {
	return fibersession.New(fibersession.Config{
		IdleTimeout:    config.SessionIdleTimeout,
		CookieHTTPOnly: true,
		CookieSecure:   config.CookieSecure,
		// Lax, not Strict: the SSO server returns the browser to the callback
		// through a top-level GET, and Strict would withhold the cookie on that
		// navigation - losing the state and verifier we are about to check.
		CookieSameSite: "Lax",
		CookiePath:     "/",
	})
}

// StartSignIn stores the values that make the callback verifiable. The SSO
// server echoes state and nonce back but validates neither, so they are only
// worth anything because they are kept here and compared on return.
func StartSignIn(c fiber.Ctx, req sso.AuthRequest) {
	store := fibersession.FromContext(c)

	store.Set(keyState, req.State)
	store.Set(keyNonce, req.Nonce)
	store.Set(keyVerifier, req.PKCE.Verifier)
}

// Pending is the stored half of a sign-in attempt.
type Pending struct {
	State    string
	Nonce    string
	Verifier string
}

// TakeSignIn returns the pending attempt and clears it, so a replayed callback
// finds nothing to match against and one code cannot be redeemed twice.
func TakeSignIn(c fiber.Ctx) (Pending, bool) {
	store := fibersession.FromContext(c)

	pending := Pending{
		State:    str(store.Get(keyState)),
		Nonce:    str(store.Get(keyNonce)),
		Verifier: str(store.Get(keyVerifier)),
	}

	store.Delete(keyState)
	store.Delete(keyNonce)
	store.Delete(keyVerifier)

	return pending, pending.State != ""
}

func StartSignOut(c fiber.Ctx, state string) {
	fibersession.FromContext(c).Set(keyLogoutState, state)
}

func TakeSignOut(c fiber.Ctx) (string, bool) {
	store := fibersession.FromContext(c)

	state := str(store.Get(keyLogoutState))
	store.Delete(keyLogoutState)

	return state, state != ""
}

// SignIn records a completed sign-in. The session id is regenerated first: the
// visitor arrived with an id issued before they authenticated, and reusing it
// is what session fixation depends on.
func SignIn(c fiber.Ctx, user User, tokens Tokens, idTokenAlg string) error {
	store := fibersession.FromContext(c)

	if err := store.Regenerate(); err != nil {
		return fmt.Errorf("unable to regenerate the session: %w", err)
	}

	user.SignedInAt = time.Now()

	if err := setJSON(store, keyUser, user); err != nil {
		return err
	}

	if err := setJSON(store, keyTokens, tokens); err != nil {
		return err
	}

	store.Set(keySignedInAt, user.SignedInAt.Format(time.RFC3339))
	store.Set(keyIDTokenAlg, idTokenAlg)
	store.Set(keyGrantedScope, tokens.Scope)

	return nil
}

// UpdateTokens persists a rotated set. Refresh tokens rotate on every use, so
// this has to happen before the next refresh or that one fails.
func UpdateTokens(c fiber.Ctx, tokens Tokens) error {
	store := fibersession.FromContext(c)

	if err := setJSON(store, keyTokens, tokens); err != nil {
		return err
	}

	store.Set(keyLastRefresh, time.Now().Format(time.RFC3339))

	return nil
}

func CurrentUser(c fiber.Ctx) (User, bool) {
	var user User

	if err := getJSON(fibersession.FromContext(c), keyUser, &user); err != nil || user.Sub == "" {
		return User{}, false
	}

	return user, true
}

func CurrentTokens(c fiber.Ctx) (Tokens, bool) {
	var tokens Tokens

	if err := getJSON(fibersession.FromContext(c), keyTokens, &tokens); err != nil || tokens.AccessToken == "" {
		return Tokens{}, false
	}

	return tokens, true
}

func IDTokenAlg(c fiber.Ctx) string {
	return str(fibersession.FromContext(c).Get(keyIDTokenAlg))
}

func LastRefreshedAt(c fiber.Ctx) string {
	return str(fibersession.FromContext(c).Get(keyLastRefresh))
}

// SignOut drops the whole session, tokens included. RP-initiated logout clears
// the SSO server's own cookie but revokes nothing, so discarding the tokens
// here is the only thing that stops this app still holding usable ones.
//
// Reset, not Destroy: Destroy marks the session destroyed and the middleware
// then skips its save, so anything stored afterwards - the logout state, in
// particular - is silently dropped. Reset deletes the old session from storage
// and issues a fresh id, which leaves something to store that state in.
func SignOut(c fiber.Ctx) error {
	return fibersession.FromContext(c).Reset()
}

// The session store encodes values with msgp, so structs go in as JSON strings
// rather than relying on what that encoder happens to support.
func setJSON(store *fibersession.Middleware, key string, value any) error {
	encoded, err := json.Marshal(value)

	if err != nil {
		return fmt.Errorf("unable to encode %s for the session: %w", key, err)
	}

	store.Set(key, string(encoded))

	return nil
}

func getJSON(store *fibersession.Middleware, key string, target any) error {
	raw := str(store.Get(key))

	if raw == "" {
		return fmt.Errorf("%s is not in the session", key)
	}

	return json.Unmarshal([]byte(raw), target)
}

func str(value any) string {
	text, _ := value.(string)

	return text
}
