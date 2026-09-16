package core

import (
	"strings"

	"github.com/gofiber/template/html/v3"

	"github.com/nuanu/sso-demo/config"
)

// Helpers registers the handful of template functions the views need.
// html/template ships no arithmetic and no string helpers, and pushing
// presentation details like initials back into the handlers only spreads them
// around.
func Helpers(engine *html.Engine) {
	engine.AddFunc("add", func(a int, b int) int { return a + b })

	// The layout's environment badge is chrome, not page data: reading it from
	// config here keeps every handler from having to pass it through.
	engine.AddFunc("app_env", func() string { return config.AppEnv })

	engine.AddFunc("fields", strings.Fields)

	// initials falls back to the email when a profile carries no name, which is
	// common: name is a `profile` scope claim and may simply not be set.
	engine.AddFunc("initials", func(name string, email string) string {
		source := strings.TrimSpace(name)

		if source == "" {
			source = strings.TrimSpace(email)
		}

		if source == "" {
			return "?"
		}

		parts := strings.FieldsFunc(source, func(r rune) bool {
			return r == ' ' || r == '.' || r == '@' || r == '_' || r == '-'
		})

		var out strings.Builder

		for _, part := range parts {
			if out.Len() == 2 {
				break
			}

			out.WriteString(strings.ToUpper(part[:1]))
		}

		if out.Len() == 0 {
			return "?"
		}

		return out.String()
	})
}
