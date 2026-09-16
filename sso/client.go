// Package sso is an OpenID Connect relying party for the Nuanu SSO service.
//
// It follows the authorization-code flow documented in the auth service's
// docs/SSO_INTEGRATION.md: endpoints come from the discovery document, every
// sign-in carries state, nonce and a PKCE challenge, the code is redeemed
// server side, and both tokens are verified before anything is trusted.
package sso

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc/v3"
)

const (
	AlgHS256 = "HS256"
	AlgRS256 = "RS256"
)

// Config is everything the relying party needs to know about itself. All of it
// comes from the environment; none of it is discoverable.
type Config struct {
	BaseURL      string
	ClientID     string
	ClientSecret string

	// RedirectURI must be registered verbatim in the client's
	// allowed_redirect_urls and must be a clean path: the SSO server bounces the
	// browser back through an auto-submitting GET form, which replaces any query
	// string already on the URL.
	RedirectURI string

	// PostLogoutRedirectURI is validated against post_logout_redirect_urls,
	// falling back to allowed_redirect_urls when the client has none registered.
	PostLogoutRedirectURI string

	Scopes string

	// IDTokenAlg mirrors the client's id_token_signed_response_alg. It is a
	// server-side per-client setting that nothing in the protocol exposes, so it
	// has to be configured here to know which key verifies the id_token.
	IDTokenAlg string

	// DepartmentID optionally selects the organization branding rendered on the
	// SSO login and registration pages.
	DepartmentID string

	SkipDiscovery bool
}

type Client struct {
	cfg  Config
	http *http.Client

	mu          sync.RWMutex
	discovery   *Discovery
	discoveryAt time.Time
	jwksURI     string
	keyfunc     keyfunc.Keyfunc
}

func New(cfg Config) *Client {
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")

	if cfg.IDTokenAlg == "" {
		cfg.IDTokenAlg = AlgHS256
	}

	if cfg.Scopes == "" {
		cfg.Scopes = "openid"
	}

	return &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *Client) Config() Config { return c.cfg }

// AuthRequest is one sign-in attempt. State, Nonce and PKCE are generated per
// attempt by NewAuthRequest and must be stored in the caller's session: the SSO
// server echoes state and nonce back but validates neither, so checking them is
// the relying party's job.
type AuthRequest struct {
	State string
	Nonce string
	PKCE  PKCE

	// Prompt is space-delimited. "none" renders no UI and returns
	// login_required when there is no session, which is how you probe for one
	// silently; "login" forces re-authentication.
	Prompt string

	// MaxAge in seconds sends the user back through login if the session
	// authenticated longer ago than this, and puts auth_time in the id_token.
	MaxAge int

	// InvitationID is carried through the sign-up screens for your own
	// bookkeeping. It gates nothing - registration is open either way.
	InvitationID string
}

func NewAuthRequest() (AuthRequest, error) {
	state, err := RandomToken(16)

	if err != nil {
		return AuthRequest{}, err
	}

	nonce, err := RandomToken(16)

	if err != nil {
		return AuthRequest{}, err
	}

	pkce, err := NewPKCE()

	if err != nil {
		return AuthRequest{}, err
	}

	return AuthRequest{State: state, Nonce: nonce, PKCE: pkce}, nil
}

// AuthorizationURL is where the browser gets sent to start a sign-in.
func (c *Client) AuthorizationURL(ctx context.Context, req AuthRequest) (string, error) {
	doc := c.Discovery(ctx)

	endpoint, err := url.Parse(doc.AuthorizationEndpoint)

	if err != nil {
		return "", fmt.Errorf("unable to parse the authorization endpoint %q: %w", doc.AuthorizationEndpoint, err)
	}

	query := url.Values{}
	query.Set("response_type", "code")
	query.Set("scope", c.cfg.Scopes)
	query.Set("client_id", c.cfg.ClientID)
	query.Set("redirect_uri", c.cfg.RedirectURI)
	query.Set("state", req.State)
	query.Set("nonce", req.Nonce)

	if req.PKCE.Challenge != "" {
		query.Set("code_challenge", req.PKCE.Challenge)
		query.Set("code_challenge_method", ChallengeMethod)
	}

	if req.Prompt != "" {
		query.Set("prompt", req.Prompt)
	}

	if req.MaxAge > 0 {
		query.Set("max_age", strconv.Itoa(req.MaxAge))
	}

	if c.cfg.DepartmentID != "" {
		query.Set("department_id", c.cfg.DepartmentID)
	}

	if req.InvitationID != "" {
		query.Set("invitation_id", req.InvitationID)
	}

	endpoint.RawQuery = query.Encode()

	return endpoint.String(), nil
}

// TokenResponse is the /openid/token result. ExpiresIn is a number of seconds,
// not a timestamp - the deprecated /openid/validate returns an absolute ISO-8601
// datetime there, which is one of the reasons not to use it.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
}

// ExchangeCode redeems an authorization code. Server side only: this request
// carries the client secret. The code is single use with a 5-minute lifetime,
// and redirectURI must be byte-identical to the one in the authorization
// request or the server answers invalid_grant.
func (c *Client) ExchangeCode(ctx context.Context, code string, codeVerifier string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", c.cfg.RedirectURI)

	// code_verifier is required when the authorization request carried a
	// challenge and rejected when it did not, so it is sent only if we have one.
	if codeVerifier != "" {
		form.Set("code_verifier", codeVerifier)
	}

	return c.token(ctx, form)
}

// Refresh exchanges a refresh token for a new set.
//
// Refresh tokens rotate: every success invalidates the one just used, so the
// new value has to be persisted immediately or the next refresh fails. Callers
// must also serialise concurrent refreshes - two in flight with the same token
// leaves one holding a dead one.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)

	return c.token(ctx, form)
}

func (c *Client) token(ctx context.Context, form url.Values) (*TokenResponse, error) {
	doc := c.Discovery(ctx)

	// client_secret_post. The server also accepts client_secret_basic - the same
	// credentials as an Authorization: Basic header - and advertises both in
	// token_endpoint_auth_methods_supported.
	form.Set("client_id", c.cfg.ClientID)
	form.Set("client_secret", c.cfg.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, doc.TokenEndpoint, strings.NewReader(form.Encode()))

	if err != nil {
		return nil, fmt.Errorf("unable to build the token request: %w", err)
	}

	// Form-encoded, not JSON. A JSON body here returns 422.
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	res, err := c.http.Do(req)

	if err != nil {
		return nil, fmt.Errorf("unable to reach the token endpoint: %w", err)
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, parseError(res)
	}

	var tokens TokenResponse

	if err := json.NewDecoder(res.Body).Decode(&tokens); err != nil {
		return nil, fmt.Errorf("unable to decode the token response: %w", err)
	}

	if tokens.AccessToken == "" {
		return nil, fmt.Errorf("the token response carried no access_token")
	}

	return &tokens, nil
}

// UserInfo is the standard OIDC UserInfo response. Which claims arrive depends
// on the scopes granted: profile covers name, picture, birthdate and
// nationality; email covers email; phone covers phone_number. Claims with no
// value are omitted rather than returned null.
//
// email_verified and locale are deliberately absent from this server - see
// section 8 of the integration guide.
type UserInfo struct {
	Sub         string `json:"sub"`
	Name        string `json:"name,omitempty"`
	Picture     string `json:"picture,omitempty"`
	Birthdate   string `json:"birthdate,omitempty"`
	Nationality string `json:"nationality,omitempty"`
	Email       string `json:"email,omitempty"`
	PhoneNumber string `json:"phone_number,omitempty"`
}

// UserInfo reads the profile from the endpoint named by the discovery document,
// which is /openid/userinfo - not /users/me, which returns Nuanu's own field
// names and an `id` where a UserInfo response must carry `sub`.
func (c *Client) UserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	doc := c.Discovery(ctx)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, doc.UserinfoEndpoint, nil)

	if err != nil {
		return nil, fmt.Errorf("unable to build the userinfo request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	res, err := c.http.Do(req)

	if err != nil {
		return nil, fmt.Errorf("unable to reach the userinfo endpoint: %w", err)
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, parseError(res)
	}

	body, err := io.ReadAll(io.LimitReader(res.Body, 64<<10))

	if err != nil {
		return nil, fmt.Errorf("unable to read the userinfo response: %w", err)
	}

	var info UserInfo

	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("unable to decode the userinfo response: %w", err)
	}

	if info.Sub == "" {
		return nil, fmt.Errorf("the userinfo response carried no sub")
	}

	return &info, nil
}

// LogoutURL is RP-initiated logout: it clears the SSO session cookie and
// bounces the browser back to PostLogoutRedirectURI.
//
// It does not revoke already-issued access or refresh tokens, and it knows
// nothing about this app's session - dropping both is the caller's job.
func (c *Client) LogoutURL(ctx context.Context, idTokenHint string, state string) (string, error) {
	doc := c.Discovery(ctx)

	endpoint, err := url.Parse(doc.EndSessionEndpoint)

	if err != nil {
		return "", fmt.Errorf("unable to parse the end session endpoint %q: %w", doc.EndSessionEndpoint, err)
	}

	query := url.Values{}
	query.Set("post_logout_redirect_uri", c.cfg.PostLogoutRedirectURI)
	query.Set("client_id", c.cfg.ClientID)

	if idTokenHint != "" {
		query.Set("id_token_hint", idTokenHint)
	}

	if state != "" {
		query.Set("state", state)
	}

	if c.cfg.DepartmentID != "" {
		query.Set("department_id", c.cfg.DepartmentID)
	}

	endpoint.RawQuery = query.Encode()

	return endpoint.String(), nil
}
