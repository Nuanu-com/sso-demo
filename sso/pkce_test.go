package sso

import (
	"strings"
	"testing"
)

func TestChallengeForMatchesRFC7636(t *testing.T) {
	// The worked example from RFC 7636 appendix B. If this drifts, every
	// PKCE-protected code exchange fails with invalid_grant and nothing else
	// explains why.
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const want = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	if got := ChallengeFor(verifier); got != want {
		t.Errorf("ChallengeFor(%q) = %q, want %q", verifier, got, want)
	}
}

func TestNewPKCEProducesDistinctVerifiersOfLegalLength(t *testing.T) {
	first, err := NewPKCE()

	if err != nil {
		t.Fatalf("NewPKCE() returned %v", err)
	}

	second, err := NewPKCE()

	if err != nil {
		t.Fatalf("NewPKCE() returned %v", err)
	}

	if first.Verifier == second.Verifier {
		t.Error("two verifiers came out identical; the challenge would be reusable")
	}

	// RFC 7636 allows 43-128 characters.
	if length := len(first.Verifier); length < 43 || length > 128 {
		t.Errorf("verifier length = %d, want between 43 and 128", length)
	}

	if strings.ContainsAny(first.Verifier, "+/=") {
		t.Errorf("verifier %q is not unpadded base64url", first.Verifier)
	}

	if first.Challenge != ChallengeFor(first.Verifier) {
		t.Error("the challenge does not hash from its own verifier")
	}
}
