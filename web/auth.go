package web

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/nuanu/sso-demo/config"
	"github.com/nuanu/sso-demo/core"
	"github.com/nuanu/sso-demo/session"
	"github.com/nuanu/sso-demo/sso"
)

type AuthWeb struct {
	client *sso.Client
}

func NewAuthWeb(client *sso.Client) *AuthWeb {
	return &AuthWeb{client: client}
}

// Login starts the authorization-code flow.
//
// ?prompt=none is worth trying by hand: the SSO server renders no UI and
// returns login_required when there is no session, which is how an app checks
// for one silently. ?prompt=login forces re-authentication even when there is.
func (a *AuthWeb) Login(ctx *core.AppContext) error {
	if !config.Configured() {
		return pageWithStatus(ctx, "pages/error", fiber.StatusServiceUnavailable, fiber.Map{
			"Title":   "No SSO client configured",
			"Message": "SSO_CLIENT_ID and SSO_CLIENT_SECRET are empty, so there is nothing to sign in to. Register a client with the auth team and put the values in your .env file.",
		})
	}

	req, err := sso.NewAuthRequest()

	if err != nil {
		return a.fail(ctx, "Unable to start sign-in", err)
	}

	req.Prompt = fiber.Query[string](ctx, "prompt")
	req.MaxAge = fiber.Query[int](ctx, "max_age")
	req.InvitationID = fiber.Query[string](ctx, "invitation_id")

	url, err := a.client.AuthorizationURL(ctx, req)

	if err != nil {
		return a.fail(ctx, "Unable to build the authorization URL", err)
	}

	// Stored before the redirect, because the callback is only verifiable
	// against values this side kept.
	session.StartSignIn(ctx, req)

	return ctx.Redirect().To(url)
}

// Callback is where the SSO server returns the browser, through an
// auto-submitting GET form. Every step below is a check that has to happen
// before anything in the response is believed.
func (a *AuthWeb) Callback(ctx *core.AppContext) error {
	// 1. An error comes back in the query string, not as a status code, so it
	//    has to be read before looking for a code.
	if errCode := fiber.Query[string](ctx, "error"); errCode != "" {
		description := fiber.Query[string](ctx, "error_description")

		return pageWithStatus(ctx, "pages/error", fiber.StatusBadRequest, fiber.Map{
			"Title":   "The identity provider refused the request",
			"Code":    errCode,
			"Message": description,
		})
	}

	pending, ok := session.TakeSignIn(ctx)

	if !ok {
		return a.fail(ctx, "No sign-in in progress", fmt.Errorf("this callback has no matching request in the session - it was replayed, or the session expired"))
	}

	// 2. state. Constant-time, because the comparison is against a secret this
	//    side generated.
	state := fiber.Query[string](ctx, "state")

	if subtle.ConstantTimeCompare([]byte(state), []byte(pending.State)) != 1 {
		return a.fail(ctx, "State mismatch", fmt.Errorf("the state returned by the identity provider is not the one this session started with"))
	}

	code := fiber.Query[string](ctx, "code")

	if code == "" {
		return a.fail(ctx, "No authorization code", fmt.Errorf("the callback carried neither an error nor a code"))
	}

	// 3. Redeem the code. Server to server, carrying the client secret and the
	//    PKCE verifier whose challenge went out with the request.
	tokens, err := a.client.ExchangeCode(ctx, code, pending.Verifier)

	if err != nil {
		return a.fail(ctx, "The code exchange failed", err)
	}

	// 4. The id_token is what says who signed in. Signature, issuer, audience,
	//    expiry, and the nonce that binds it to this attempt.
	idClaims, err := a.client.VerifyIDToken(ctx, tokens.IDToken, pending.Nonce)

	if err != nil {
		return a.fail(ctx, "The id_token did not validate", err)
	}

	// 5. The access token is independently verifiable through the JWKS. Doing it
	//    here means a token this app is about to send onwards has been checked
	//    once by this app, not just handed over.
	accessClaims, err := a.client.VerifyAccessToken(ctx, tokens.AccessToken)

	if err != nil {
		return a.fail(ctx, "The access_token did not validate", err)
	}

	if accessClaims.Subject != idClaims.Subject {
		return a.fail(ctx, "Token subject mismatch", fmt.Errorf("the access_token and id_token describe different users"))
	}

	// 6. The profile. Its sub has to be the same user again.
	info, err := a.client.UserInfo(ctx, tokens.AccessToken)

	if err != nil {
		return a.fail(ctx, "Unable to read the profile", err)
	}

	if info.Sub != idClaims.Subject {
		return a.fail(ctx, "Profile subject mismatch", fmt.Errorf("userinfo returned a different sub than the id_token"))
	}

	user := session.User{
		Sub:         info.Sub,
		Name:        info.Name,
		Email:       info.Email,
		Picture:     info.Picture,
		Birthdate:   info.Birthdate,
		Nationality: info.Nationality,
		PhoneNumber: info.PhoneNumber,
	}

	if idClaims.AuthTime > 0 {
		user.AuthTime = time.Unix(idClaims.AuthTime, 0)
	}

	stored := session.Tokens{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		IDToken:      tokens.IDToken,
		Scope:        tokens.Scope,
		ExpiresAt:    sso.ExpiresAt(tokens.ExpiresIn),
	}

	if err := session.SignIn(ctx, user, stored, a.client.Config().IDTokenAlg); err != nil {
		return a.fail(ctx, "Unable to store the session", err)
	}

	return ctx.Redirect().To("/dashboard")
}

// Refresh rotates the token set. It answers JSON because the dashboard island
// calls it; the rotated refresh token stays server side either way.
//
// One refresh at a time per session would need a lock in a real app: two in
// flight with the same refresh token leaves one of them holding a dead one.
func (a *AuthWeb) Refresh(ctx *core.AppContext) error {
	tokens, ok := session.CurrentTokens(ctx)

	if !ok {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "not signed in"})
	}

	if tokens.RefreshToken == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "this session has no refresh token"})
	}

	refreshed, err := a.client.Refresh(ctx, tokens.RefreshToken)

	if err != nil {
		return ctx.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}

	// A refreshed id_token carries no nonce - nothing authenticated, so there is
	// nothing to bind - but issuer, audience, signature and expiry still apply.
	if refreshed.IDToken != "" {
		if _, err := a.client.VerifyIDToken(ctx, refreshed.IDToken, ""); err != nil {
			return ctx.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
		}
	}

	if _, err := a.client.VerifyAccessToken(ctx, refreshed.AccessToken); err != nil {
		return ctx.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}

	rotated := session.Tokens{
		AccessToken: refreshed.AccessToken,
		// The server rotates the refresh token on every use, but keep the old one
		// if a response ever omits it rather than losing the ability to refresh.
		RefreshToken: firstNonEmpty(refreshed.RefreshToken, tokens.RefreshToken),
		IDToken:      firstNonEmpty(refreshed.IDToken, tokens.IDToken),
		Scope:        firstNonEmpty(refreshed.Scope, tokens.Scope),
		ExpiresAt:    sso.ExpiresAt(refreshed.ExpiresIn),
	}

	if err := session.UpdateTokens(ctx, rotated); err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return ctx.JSON(fiber.Map{
		"expires_at":           rotated.ExpiresAt,
		"expires_in":           refreshed.ExpiresIn,
		"rotated_refresh":      refreshed.RefreshToken != "" && refreshed.RefreshToken != tokens.RefreshToken,
		"access_token_preview": previewToken(rotated.AccessToken),
	})
}

// Logout clears this app's session first, then hands the browser to the SSO
// server to clear its own. Doing it in that order means a user who closes the
// tab mid-redirect is still signed out here.
func (a *AuthWeb) Logout(ctx *core.AppContext) error {
	tokens, _ := session.CurrentTokens(ctx)

	state, err := sso.RandomToken(16)

	if err != nil {
		return a.fail(ctx, "Unable to start sign-out", err)
	}

	url, err := a.client.LogoutURL(ctx, tokens.IDToken, state)

	if err != nil {
		return a.fail(ctx, "Unable to build the logout URL", err)
	}

	if err := session.SignOut(ctx); err != nil {
		log.Printf("unable to clear the session: %v", err)
	}

	// Stored after the reset, on the fresh session, so it survives to be checked
	// when the identity provider sends the browser back.
	session.StartSignOut(ctx, state)

	return ctx.Redirect().To(url)
}

// LogoutCallback is where the SSO server returns after clearing its cookie.
func (a *AuthWeb) LogoutCallback(ctx *core.AppContext) error {
	expected, ok := session.TakeSignOut(ctx)
	returned := fiber.Query[string](ctx, "state")

	return page(ctx, "pages/signed-out", fiber.Map{
		"StateVerified": ok && subtle.ConstantTimeCompare([]byte(expected), []byte(returned)) == 1,
		"StateReturned": returned != "",
	})
}

func (a *AuthWeb) fail(ctx *core.AppContext, title string, err error) error {
	assigns := fiber.Map{"Title": title, "Message": err.Error()}

	// An OAuth error carries a machine-readable code worth showing next to the
	// prose, because it is what the error table in the integration guide is
	// indexed by.
	var oauthErr *sso.Error

	if errors.As(err, &oauthErr) {
		assigns["Code"] = oauthErr.Code
		assigns["Message"] = oauthErr.Description
		assigns["Status"] = oauthErr.Status
	}

	return pageWithStatus(ctx, "pages/error", fiber.StatusBadRequest, assigns)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}

	return ""
}
