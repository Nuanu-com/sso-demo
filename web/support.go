package web

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Claim is one decoded JWT claim, ready to render.
type Claim struct {
	Name  string
	Value string
	// Note explains a claim whose raw value reads as a number but means
	// something - the timestamps, mostly.
	Note string
}

var claimOrder = map[string]int{
	"iss": 1, "sub": 2, "aud": 3, "exp": 4, "iat": 5, "nonce": 6, "auth_time": 7,
}

// decodeClaims reads a JWT payload for display only. It does not verify
// anything: the token it is given was verified at the callback, and re-checking
// a signature to draw a table would suggest the table is what makes it
// trustworthy.
func decodeClaims(token string) []Claim {
	parts := strings.Split(token, ".")

	if len(parts) != 3 {
		return nil
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])

	if err != nil {
		return nil
	}

	var raw map[string]any

	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil
	}

	claims := make([]Claim, 0, len(raw))

	for name, value := range raw {
		claim := Claim{Name: name, Value: fmt.Sprintf("%v", value)}

		if seconds, ok := value.(float64); ok && isTimestamp(name) {
			claim.Value = fmt.Sprintf("%d", int64(seconds))
			claim.Note = time.Unix(int64(seconds), 0).Format(time.RFC3339)
		}

		claims = append(claims, claim)
	}

	// Registered claims first, in the order the integration guide lists them,
	// then anything else alphabetically.
	sort.Slice(claims, func(i, j int) bool {
		left, right := claimOrder[claims[i].Name], claimOrder[claims[j].Name]

		if left != right {
			if left == 0 {
				return false
			}

			if right == 0 {
				return true
			}

			return left < right
		}

		return claims[i].Name < claims[j].Name
	})

	return claims
}

func isTimestamp(name string) bool {
	switch name {
	case "exp", "iat", "nbf", "auth_time":
		return true
	}

	return false
}

// previewToken shows enough of a token to tell two apart without putting a
// usable one on screen.
func previewToken(token string) string {
	if token == "" {
		return ""
	}

	if len(token) <= 24 {
		return strings.Repeat("•", len(token))
	}

	return fmt.Sprintf("%s…%s (%d chars)", token[:12], token[len(token)-6:], len(token))
}
