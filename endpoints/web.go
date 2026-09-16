package endpoints

import (
	"github.com/gofiber/fiber/v3"

	"github.com/nuanu/sso-demo/core"
	"github.com/nuanu/sso-demo/web"
)

func RouteWeb(app *fiber.App, pagesWeb *web.PagesWeb, authWeb *web.AuthWeb) {
	app.Get("/", core.HandleReq(pagesWeb.Index))
	app.Get("/dashboard", core.HandleReq(pagesWeb.Dashboard))

	// The callback path has to match SSO_REDIRECT_URI exactly, and that value
	// has to be registered in the client's allowed_redirect_urls.
	app.Get("/auth/login", core.HandleReq(authWeb.Login))
	app.Get("/auth/callback", core.HandleReq(authWeb.Callback))
	app.Post("/auth/refresh", core.HandleReq(authWeb.Refresh))
	app.Get("/auth/logout", core.HandleReq(authWeb.Logout))
	app.Get("/auth/logout/callback", core.HandleReq(authWeb.LogoutCallback))
}
