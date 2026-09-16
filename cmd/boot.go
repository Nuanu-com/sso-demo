package cmd

import (
	"log"
	"net/http"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/template/html/v3"
	"go.uber.org/dig"

	"github.com/nuanu/sso-demo/config"
	"github.com/nuanu/sso-demo/sso"
	"github.com/nuanu/sso-demo/web"
)

var Container *dig.Container

func init() {
	Container = dig.New()

	must(Container.Provide(func() *html.Engine {
		return html.NewFileSystem(http.FS(config.ViewsFS), ".html")
	}))

	must(Container.Provide(func(engine *html.Engine) *fiber.App {
		return fiber.New(fiber.Config{Views: engine})
	}))

	// SSO
	//
	// One client for the process: it caches the discovery document and the JWKS,
	// and the JWKS cache runs a refresh goroutine that should exist once.
	must(Container.Provide(func() *sso.Client {
		return sso.New(sso.Config{
			BaseURL:               config.SSOBaseURL,
			ClientID:              config.SSOClientID,
			ClientSecret:          config.SSOClientSecret,
			RedirectURI:           config.SSORedirectURI,
			PostLogoutRedirectURI: config.SSOPostLogoutRedirectURI,
			Scopes:                config.SSOScopes,
			IDTokenAlg:            config.SSOIDTokenAlg,
			DepartmentID:          config.SSODepartmentID,
			SkipDiscovery:         config.SSOSkipDiscovery,
		})
	}))

	// WEB

	must(Container.Provide(web.NewPagesWeb))
	must(Container.Provide(web.NewAuthWeb))
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
