package sso

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Error is the OAuth 2.0 error shape the token endpoint returns. It is not
// FastAPI's {"detail": ...}: /openid/token answers with {"error",
// "error_description"} as RFC 6749 requires, and the demo surfaces both.
type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
	Status      int    `json:"-"`
}

func (e *Error) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Description)
	}

	return e.Code
}

// parseError reads an error response body. A body that is not the OAuth shape
// (an unexpected 502 from a proxy, say) still produces a usable error rather
// than an empty one.
func parseError(res *http.Response) *Error {
	body, _ := io.ReadAll(io.LimitReader(res.Body, 8<<10))

	oauthErr := &Error{Status: res.StatusCode}

	if err := json.Unmarshal(body, oauthErr); err == nil && oauthErr.Code != "" {
		return oauthErr
	}

	// The deprecated endpoints and FastAPI's own validation layer answer with
	// {"detail": ...}, so fall back to that before giving up on the body.
	var detail struct {
		Detail any `json:"detail"`
	}

	if err := json.Unmarshal(body, &detail); err == nil && detail.Detail != nil {
		return &Error{
			Code:        fmt.Sprintf("http_%d", res.StatusCode),
			Description: fmt.Sprintf("%v", detail.Detail),
			Status:      res.StatusCode,
		}
	}

	return &Error{
		Code:        fmt.Sprintf("http_%d", res.StatusCode),
		Description: string(body),
		Status:      res.StatusCode,
	}
}
