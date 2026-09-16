package sso

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testClientID     = "the-client"
	testClientSecret = "the-secret"
	testKID          = "test-key"
)

// idProvider stands in for the SSO server: it publishes a discovery document
// and a JWKS built from a key pair generated for the test, and can mint tokens
// the same way the real server does.
type idProvider struct {
	server *httptest.Server
	key    *rsa.PrivateKey
}

func newIDProvider(t *testing.T) *idProvider {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		t.Fatalf("unable to generate a test key: %v", err)
	}

	provider := &idProvider{key: key}

	mux := http.NewServeMux()

	mux.HandleFunc(DiscoveryPath, func(w http.ResponseWriter, r *http.Request) {
		base := provider.server.URL

		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 base,
			"authorization_endpoint": base + "/web/openid/auth",
			"token_endpoint":         base + "/api/v1/openid/token",
			"userinfo_endpoint":      base + "/api/v1/openid/userinfo",
			"end_session_endpoint":   base + "/web/openid/logout",
			"jwks_uri":               base + "/public/jwks.json",
		})
	})

	mux.HandleFunc("/public/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		pub := key.Public().(*rsa.PublicKey)

		json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"use": "sig",
				"alg": AlgRS256,
				"kid": testKID,
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			}},
		})
	})

	provider.server = httptest.NewServer(mux)
	t.Cleanup(provider.server.Close)

	return provider
}

func (p *idProvider) client(t *testing.T, alg string) *Client {
	t.Helper()

	return New(Config{
		BaseURL:      p.server.URL,
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
		IDTokenAlg:   alg,
	})
}

// claims returns a valid id_token payload, which each test then spoils in
// exactly one way.
func (p *idProvider) claims() jwt.MapClaims {
	return jwt.MapClaims{
		"iss":   p.server.URL,
		"sub":   "9c1e0000-0000-4000-8000-000000000000",
		"aud":   testClientID,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"nonce": "the-nonce",
	}
}

func (p *idProvider) signHS256(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testClientSecret))

	if err != nil {
		t.Fatalf("unable to sign the test token: %v", err)
	}

	return signed
}

func (p *idProvider) signRS256(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = testKID

	signed, err := token.SignedString(p.key)

	if err != nil {
		t.Fatalf("unable to sign the test token: %v", err)
	}

	return signed
}

func TestVerifyIDTokenAcceptsAWellFormedHS256Token(t *testing.T) {
	provider := newIDProvider(t)
	client := provider.client(t, AlgHS256)

	claims, err := client.VerifyIDToken(context.Background(), provider.signHS256(t, provider.claims()), "the-nonce")

	if err != nil {
		t.Fatalf("VerifyIDToken() rejected a valid token: %v", err)
	}

	if claims.Subject != "9c1e0000-0000-4000-8000-000000000000" {
		t.Errorf("sub = %q", claims.Subject)
	}
}

func TestVerifyIDTokenRejectsATokenMintedForAnotherClient(t *testing.T) {
	provider := newIDProvider(t)
	client := provider.client(t, AlgHS256)

	claims := provider.claims()
	claims["aud"] = "someone-elses-client"

	// Without the audience check this token passes every other test: the
	// signature is good, the issuer is right, it has not expired.
	_, err := client.VerifyIDToken(context.Background(), provider.signHS256(t, claims), "the-nonce")

	if err == nil {
		t.Fatal("a token issued to a different client was accepted")
	}
}

func TestVerifyIDTokenRejectsAForeignIssuer(t *testing.T) {
	provider := newIDProvider(t)
	client := provider.client(t, AlgHS256)

	claims := provider.claims()
	claims["iss"] = "https://not-nuanu.example.com"

	if _, err := client.VerifyIDToken(context.Background(), provider.signHS256(t, claims), "the-nonce"); err == nil {
		t.Fatal("a token from another issuer was accepted")
	}
}

func TestVerifyIDTokenRejectsAnExpiredToken(t *testing.T) {
	provider := newIDProvider(t)
	client := provider.client(t, AlgHS256)

	claims := provider.claims()
	claims["exp"] = time.Now().Add(-time.Minute).Unix()

	if _, err := client.VerifyIDToken(context.Background(), provider.signHS256(t, claims), "the-nonce"); err == nil {
		t.Fatal("an expired token was accepted")
	}
}

func TestVerifyIDTokenRejectsAReplayedNonce(t *testing.T) {
	provider := newIDProvider(t)
	client := provider.client(t, AlgHS256)

	claims := provider.claims()
	claims["nonce"] = "a-nonce-from-some-other-sign-in"

	if _, err := client.VerifyIDToken(context.Background(), provider.signHS256(t, claims), "the-nonce"); err == nil {
		t.Fatal("a token carrying another attempt's nonce was accepted")
	}
}

func TestVerifyIDTokenIgnoresNonceWhenNoneIsExpected(t *testing.T) {
	provider := newIDProvider(t)
	client := provider.client(t, AlgHS256)

	claims := provider.claims()
	delete(claims, "nonce")

	// A refresh issues an id_token with no nonce - nothing authenticated, so
	// there is nothing to bind - and that has to keep working.
	if _, err := client.VerifyIDToken(context.Background(), provider.signHS256(t, claims), ""); err != nil {
		t.Fatalf("a refreshed id_token without a nonce was rejected: %v", err)
	}
}

func TestVerifyIDTokenRejectsASwappedAlgorithm(t *testing.T) {
	provider := newIDProvider(t)

	// The client is configured RS256, so its key material is the JWKS. A token
	// signed HS256 must not be accepted no matter what key it claims to use -
	// this is the algorithm-confusion attack.
	client := provider.client(t, AlgRS256)

	if _, err := client.VerifyIDToken(context.Background(), provider.signHS256(t, provider.claims()), "the-nonce"); err == nil {
		t.Fatal("an HS256 token was accepted by a client configured for RS256")
	}
}

func TestVerifyIDTokenAcceptsRS256AgainstTheJWKS(t *testing.T) {
	provider := newIDProvider(t)
	client := provider.client(t, AlgRS256)

	claims, err := client.VerifyIDToken(context.Background(), provider.signRS256(t, provider.claims()), "the-nonce")

	if err != nil {
		t.Fatalf("VerifyIDToken() rejected a valid RS256 token: %v", err)
	}

	if claims.Issuer != provider.server.URL {
		t.Errorf("iss = %q, want %q", claims.Issuer, provider.server.URL)
	}
}

func TestVerifyAccessTokenChecksTheJWKS(t *testing.T) {
	provider := newIDProvider(t)
	client := provider.client(t, AlgHS256)

	// The access token is RS256 whatever the client's id_token algorithm is.
	raw := provider.signRS256(t, jwt.MapClaims{
		"sub": "9c1e0000-0000-4000-8000-000000000000",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	claims, err := client.VerifyAccessToken(context.Background(), raw)

	if err != nil {
		t.Fatalf("VerifyAccessToken() rejected a valid token: %v", err)
	}

	if claims.Subject != "9c1e0000-0000-4000-8000-000000000000" {
		t.Errorf("sub = %q", claims.Subject)
	}
}

func TestVerifyAccessTokenRejectsATamperedPayload(t *testing.T) {
	provider := newIDProvider(t)
	client := provider.client(t, AlgHS256)

	raw := provider.signRS256(t, jwt.MapClaims{
		"sub": "9c1e0000-0000-4000-8000-000000000000",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	parts := strings.Split(raw, ".")

	forged, _ := json.Marshal(map[string]any{
		"sub": "00000000-0000-4000-8000-000000000001",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	parts[1] = base64.RawURLEncoding.EncodeToString(forged)

	if _, err := client.VerifyAccessToken(context.Background(), strings.Join(parts, ".")); err == nil {
		t.Fatal("a token whose payload was rewritten after signing was accepted")
	}
}

func TestVerifyIDTokenRejectsAnUnsupportedAlgorithmSetting(t *testing.T) {
	provider := newIDProvider(t)
	client := provider.client(t, "none")

	if _, err := client.VerifyIDToken(context.Background(), provider.signHS256(t, provider.claims()), ""); err == nil {
		t.Fatal("a client configured with an unsupported algorithm verified a token anyway")
	}
}
