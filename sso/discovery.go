package sso

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Discovery is the subset of the OpenID Connect discovery document this client
// uses. Reading endpoints from here rather than hard-coding them is what lets
// the same binary talk to the local, staging and production identity providers
// with nothing but SSO_BASE_URL changed.
type Discovery struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
	EndSessionEndpoint               string   `json:"end_session_endpoint"`
	JWKSURI                          string   `json:"jwks_uri"`
	ScopesSupported                  []string `json:"scopes_supported"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	GrantTypesSupported              []string `json:"grant_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`

	// Fallback records that these values came from DefaultDiscovery rather than
	// from the server, so the UI can say so instead of implying it round-tripped.
	Fallback bool `json:"-"`
}

const DiscoveryPath = "/.well-known/openid-configuration"

// discoveryTTL is deliberately long: the document changes when the IdP is
// redeployed, not between requests.
const discoveryTTL = time.Hour

// DefaultDiscovery is the document the Nuanu SSO server publishes, rebuilt from
// the paths documented in SSO_INTEGRATION.md. It is the fallback when discovery
// cannot be fetched, so a sign-in attempt fails at the IdP with a real error
// rather than here with a confusing one.
func DefaultDiscovery(baseURL string) Discovery {
	base := strings.TrimRight(baseURL, "/")

	return Discovery{
		Issuer:                           base,
		AuthorizationEndpoint:            base + "/web/openid/auth",
		TokenEndpoint:                    base + "/api/v1/openid/token",
		UserinfoEndpoint:                 base + "/api/v1/openid/userinfo",
		EndSessionEndpoint:               base + "/web/openid/logout",
		JWKSURI:                          base + "/public/jwks.json",
		ScopesSupported:                  []string{"openid", "profile", "email", "phone"},
		ResponseTypesSupported:           []string{"code"},
		GrantTypesSupported:              []string{"authorization_code", "refresh_token"},
		IDTokenSigningAlgValuesSupported: []string{AlgRS256, AlgHS256},
		CodeChallengeMethodsSupported:    []string{"S256"},
		Fallback:                         true,
	}
}

// Discovery returns the cached discovery document, fetching it if the cache is
// cold or stale. A fetch failure is not fatal: the documented defaults are
// cached briefly instead, so one unreachable moment does not wedge the app.
func (c *Client) Discovery(ctx context.Context) Discovery {
	c.mu.RLock()
	cached, at := c.discovery, c.discoveryAt
	c.mu.RUnlock()

	if cached != nil && time.Since(at) < discoveryTTL {
		return *cached
	}

	doc, err := c.fetchDiscovery(ctx)

	if err != nil {
		doc = DefaultDiscovery(c.cfg.BaseURL)
	}

	c.mu.Lock()
	c.discovery, c.discoveryAt = &doc, time.Now()
	// The JWKS URI is the one piece of discovery the key cache depends on, so a
	// document that moves it has to invalidate the keys built from the old one.
	if c.jwksURI != doc.JWKSURI {
		c.jwksURI, c.keyfunc = doc.JWKSURI, nil
	}
	c.mu.Unlock()

	return doc
}

func (c *Client) fetchDiscovery(ctx context.Context) (Discovery, error) {
	if c.cfg.SkipDiscovery {
		return DefaultDiscovery(c.cfg.BaseURL), nil
	}

	url := strings.TrimRight(c.cfg.BaseURL, "/") + DiscoveryPath

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)

	if err != nil {
		return Discovery{}, fmt.Errorf("unable to build the discovery request: %w", err)
	}

	req.Header.Set("Accept", "application/json")

	res, err := c.http.Do(req)

	if err != nil {
		return Discovery{}, fmt.Errorf("unable to reach %s: %w", url, err)
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return Discovery{}, fmt.Errorf("%s returned %d", url, res.StatusCode)
	}

	var doc Discovery

	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		return Discovery{}, fmt.Errorf("unable to decode the discovery document: %w", err)
	}

	if doc.Issuer == "" || doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" {
		return Discovery{}, fmt.Errorf("%s is missing issuer, authorization_endpoint or token_endpoint", url)
	}

	return doc, nil
}
