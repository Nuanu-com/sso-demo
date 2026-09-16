package web

import (
	"github.com/gofiber/fiber/v3"

	"github.com/nuanu/sso-demo/core"
	"github.com/nuanu/sso-demo/session"
)

// page renders a template inside the app layout, adding the values the layout
// itself needs rather than the page.
//
// The signed-in user is one of those: the header shows a sign-out link, and
// making every handler remember to pass a user it does not otherwise use is how
// a page ends up rendering as signed out for someone who is signed in.
func page(ctx *core.AppContext, template string, assigns fiber.Map) core.HtmlResponse {
	if assigns == nil {
		assigns = fiber.Map{}
	}

	if user, ok := session.CurrentUser(ctx); ok {
		assigns["User"] = user
	}

	return core.HtmlResponse{
		Layouts:  []string{"layouts/app"},
		Template: template,
		Assigns:  assigns,
	}
}

func pageWithStatus(ctx *core.AppContext, template string, status int, assigns fiber.Map) core.HtmlResponse {
	response := page(ctx, template, assigns)
	response.StatusCode = status

	return response
}
