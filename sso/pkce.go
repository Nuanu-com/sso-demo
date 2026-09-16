package sso

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// PKCE holds one sign-in attempt's proof key (RFC 7636). The verifier stays in
// the app's session and is presented at the token endpoint; only its hash
// travels through the browser, so an intercepted authorization code cannot be
// redeemed by whoever intercepted it.
type PKCE struct {
	Verifier  string
	Challenge string
}

// ChallengeMethod is the only method the Nuanu SSO server accepts. RFC 7636
// treats an absent method as "plain", which protects nothing against anyone who
// can read the authorization request, so the server rejects it.
const ChallengeMethod = "S256"

// NewPKCE generates a verifier and its S256 challenge. 32 random bytes encode to
// 43 unpadded base64url characters, the shortest length RFC 7636 allows.
func NewPKCE() (PKCE, error) {
	verifier, err := RandomToken(32)

	if err != nil {
		return PKCE{}, fmt.Errorf("unable to generate a code verifier: %w", err)
	}

	return PKCE{Verifier: verifier, Challenge: ChallengeFor(verifier)}, nil
}

// ChallengeFor is BASE64URL(SHA256(verifier)), unpadded.
func ChallengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// RandomToken returns n cryptographically random bytes as unpadded base64url.
// It backs the `state` and `nonce` values as well as the PKCE verifier.
func RandomToken(n int) (string, error) {
	buf := make([]byte, n)

	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("unable to read random bytes: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}
