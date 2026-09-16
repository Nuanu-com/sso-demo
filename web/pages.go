package web

import (
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/nuanu/sso-demo/config"
	"github.com/nuanu/sso-demo/core"
	"github.com/nuanu/sso-demo/session"
	"github.com/nuanu/sso-demo/sso"
)

type PagesWeb struct {
	client *sso.Client
}

func NewPagesWeb(client *sso.Client) *PagesWeb {
	return &PagesWeb{client: client}
}

// Index is the signed-out landing page. A signed-in visitor goes straight to
// the dashboard, so there is never a "sign in" button on a page belonging to
// someone who already did.
func (p *PagesWeb) Index(ctx *core.AppContext) error {
	if _, ok := session.CurrentUser(ctx); ok {
		return ctx.Redirect().To("/dashboard")
	}

	doc := p.client.Discovery(ctx)

	return page(ctx, "pages/index", fiber.Map{
		"Configured": config.Configured(),
		"Provider":   providerSummary(doc, p.client.Config()),
		"Checklist":  flowSteps(),
	})
}

// Dashboard is everything the sign-in produced, laid out so each value can be
// traced back to the step that produced it.
func (p *PagesWeb) Dashboard(ctx *core.AppContext) error {
	// page() puts the user in the assigns; this only decides whether there is
	// anything to show at all.
	if _, ok := session.CurrentUser(ctx); !ok {
		return ctx.Redirect().To("/")
	}

	tokens, _ := session.CurrentTokens(ctx)
	doc := p.client.Discovery(ctx)

	// Decoding without verifying is fine here and only here: these claims are
	// displayed, and the same token was verified properly at the callback before
	// anything was stored.
	idClaims := decodeClaims(tokens.IDToken)
	accessClaims := decodeClaims(tokens.AccessToken)

	return page(ctx, "pages/dashboard", fiber.Map{
		"Provider": providerSummary(doc, p.client.Config()),
		"Tokens": fiber.Map{
			"Scope":        firstNonEmpty(tokens.Scope, p.client.Config().Scopes),
			"ExpiresAt":    tokens.ExpiresAt.Format(time.RFC3339),
			"Expired":      tokens.Expired(),
			"HasRefresh":   tokens.RefreshToken != "",
			"IDTokenAlg":   session.IDTokenAlg(ctx),
			"RefreshedAt":  session.LastRefreshedAt(ctx),
			"AccessTokenP": previewToken(tokens.AccessToken),
			"IDTokenP":     previewToken(tokens.IDToken),
			"RefreshP":     previewToken(tokens.RefreshToken),
		},
		"IDClaims":     idClaims,
		"AccessClaims": accessClaims,
		// Props for the countdown island. Seconds rather than a timestamp, so
		// a clock skewed between server and browser cannot show a negative
		// countdown on a perfectly good token.
		"SessionStatus": fiber.Map{
			"expiresInSeconds": int(time.Until(tokens.ExpiresAt).Seconds()),
			"hasRefreshToken":  tokens.RefreshToken != "",
			"refreshPath":      "/auth/refresh",
		},
	})
}

func providerSummary(doc sso.Discovery, cfg sso.Config) fiber.Map {
	return fiber.Map{
		"AppEnv":                config.AppEnv,
		"BaseURL":               cfg.BaseURL,
		"Issuer":                doc.Issuer,
		"AuthorizationEndpoint": doc.AuthorizationEndpoint,
		"TokenEndpoint":         doc.TokenEndpoint,
		"UserinfoEndpoint":      doc.UserinfoEndpoint,
		"EndSessionEndpoint":    doc.EndSessionEndpoint,
		"JWKSURI":               doc.JWKSURI,
		"DiscoveryURL":          cfg.BaseURL + sso.DiscoveryPath,
		"DiscoveryLive":         !doc.Fallback,
		"ClientID":              cfg.ClientID,
		"RedirectURI":           cfg.RedirectURI,
		"PostLogoutURI":         cfg.PostLogoutRedirectURI,
		"Scopes":                strings.Fields(cfg.Scopes),
		"IDTokenAlg":            cfg.IDTokenAlg,
		"DepartmentID":          cfg.DepartmentID,
	}
}

// flowSteps is the landing page's explanation of what the demo is about to do.
func flowSteps() []fiber.Map {
	return []fiber.Map{
		{"Title": "Authorization request", "Body": "A fresh state, nonce and PKCE verifier are generated and kept in this app's session. Only the S256 challenge goes through the browser."},
		{"Title": "Sign-in at the identity provider", "Body": "Credentials are entered on Nuanu SSO's own pages - email, Google or Apple. This app never sees them."},
		{"Title": "Callback", "Body": "The returned state is compared against the stored one before anything else is read."},
		{"Title": "Code exchange", "Body": "The single-use code is redeemed server side with the client secret and the PKCE verifier, form-encoded."},
		{"Title": "Token validation", "Body": "The id_token's signature, issuer, audience and nonce are checked; the access_token is verified against the provider's published JWKS."},
		{"Title": "Profile", "Body": "UserInfo is read with the access token, and its sub is compared with the id_token's."},
	}
}
