package sso

import (
	"context"
	"fmt"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

// IDTokenClaims is the id_token issued by /openid/token. nonce is present when
// the authorization request carried one, auth_time when the session's
// authentication time is known.
//
// A refresh issues a fresh id_token with no nonce: nothing authenticated, so
// there is nothing to bind.
type IDTokenClaims struct {
	Nonce    string `json:"nonce,omitempty"`
	AuthTime int64  `json:"auth_time,omitempty"`

	jwt.RegisteredClaims
}

// AccessTokenClaims is the whole access token. It carries sub and exp and
// nothing else - no email, no roles. Anything else about the user comes from
// UserInfo.
type AccessTokenClaims struct {
	jwt.RegisteredClaims
}

// VerifyIDToken checks the id_token's signature, issuer, audience and expiry,
// then binds it to this sign-in attempt by comparing nonce.
//
// The audience check is the one that matters most: without it a token minted
// for a different client passes every other test. The issuer is compared
// against the discovery document's own `issuer` rather than against
// SSO_BASE_URL, so a trailing slash or a proxy hostname cannot make a valid
// token look forged.
//
// The signing algorithm is per client. HS256 (the registration default) signs
// with the client secret, which proves only that the signer holds that secret -
// never forward such a token onward. RS256 signs with the server key pair and
// is verifiable by anyone through the JWKS.
func (c *Client) VerifyIDToken(ctx context.Context, raw string, expectedNonce string) (*IDTokenClaims, error) {
	doc := c.Discovery(ctx)

	var key any
	var err error

	switch c.cfg.IDTokenAlg {
	case AlgHS256:
		key = []byte(c.cfg.ClientSecret)
	case AlgRS256:
		key, err = c.jwksKeyfunc(ctx)

		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported id_token algorithm %q: expected %s or %s", c.cfg.IDTokenAlg, AlgHS256, AlgRS256)
	}

	claims := &IDTokenClaims{}

	parser := jwt.NewParser(
		// Pinning the algorithm is what stops a token re-signed with a different
		// one - or with "none" - from being accepted.
		jwt.WithValidMethods([]string{c.cfg.IDTokenAlg}),
		jwt.WithAudience(c.cfg.ClientID),
		jwt.WithIssuer(doc.Issuer),
		jwt.WithExpirationRequired(),
	)

	if _, err := parser.ParseWithClaims(raw, claims, keyFor(key)); err != nil {
		return nil, fmt.Errorf("the id_token is not valid: %w", err)
	}

	if expectedNonce != "" && claims.Nonce != expectedNonce {
		return nil, fmt.Errorf("the id_token's nonce does not match this sign-in attempt")
	}

	return claims, nil
}

// VerifyAccessToken checks the access token against the JWKS the SSO server
// publishes. It is always RS256, whatever the client's id_token algorithm is.
//
// It carries no audience, so there is nothing to check beyond signature and
// expiry - which is also why it must not be treated as proof of anything about
// this particular client.
func (c *Client) VerifyAccessToken(ctx context.Context, raw string) (*AccessTokenClaims, error) {
	jwks, err := c.jwksKeyfunc(ctx)

	if err != nil {
		return nil, err
	}

	claims := &AccessTokenClaims{}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{AlgRS256}),
		jwt.WithExpirationRequired(),
	)

	if _, err := parser.ParseWithClaims(raw, claims, jwks.Keyfunc); err != nil {
		return nil, fmt.Errorf("the access_token is not valid: %w", err)
	}

	return claims, nil
}

// jwksKeyfunc builds the JWKS client on first use and caches it. It is built
// lazily rather than at boot so an unreachable IdP costs a failed sign-in
// rather than a server that will not start; keyfunc refreshes the key set on
// its own from there, including when it meets an unknown kid.
func (c *Client) jwksKeyfunc(ctx context.Context) (keyfunc.Keyfunc, error) {
	doc := c.Discovery(ctx)

	c.mu.RLock()
	cached := c.keyfunc
	c.mu.RUnlock()

	if cached != nil {
		return cached, nil
	}

	// context.Background, not ctx: the refresh goroutine outlives the request
	// that happened to be first, and tying it to that request would stop it as
	// soon as the response was written.
	jwks, err := keyfunc.NewDefaultCtx(context.Background(), []string{doc.JWKSURI})

	if err != nil {
		return nil, fmt.Errorf("unable to load the JWKS from %s: %w", doc.JWKSURI, err)
	}

	c.mu.Lock()
	// Another request may have won the race; keep whichever landed first so
	// there is only ever one refresh goroutine in play.
	if c.keyfunc == nil {
		c.keyfunc = jwks
	}
	cached = c.keyfunc
	c.mu.Unlock()

	return cached, nil
}

func keyFor(key any) jwt.Keyfunc {
	if jwks, ok := key.(keyfunc.Keyfunc); ok {
		return jwks.Keyfunc
	}

	return func(*jwt.Token) (any, error) { return key, nil }
}

// ExpiresAt turns the token response's expires_in - a number of seconds - into
// the wall-clock instant the demo actually needs.
func ExpiresAt(expiresIn int) time.Time {
	return time.Now().Add(time.Duration(expiresIn) * time.Second)
}
