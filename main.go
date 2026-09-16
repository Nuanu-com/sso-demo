/*
Nuanu SSO demo - an OpenID Connect relying party for the Nuanu identity provider.
*/
package main

import (
	"embed"
	"io/fs"
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/nuanu/sso-demo/cmd"
	"github.com/nuanu/sso-demo/config"
)

// all: is required so .vite/manifest.json is embedded - a plain public/* pattern
// skips paths beginning with a dot.
//
//go:embed all:public
var publicFS embed.FS

//go:embed views
var viewsFS embed.FS

func main() {
	appEnv := os.Getenv("APP_ENV")

	// One file per environment, so pointing the demo at a different Nuanu SSO
	// instance is APP_ENV=staging rather than an edit. Missing files are not an
	// error: in production the values normally arrive as real environment
	// variables, and godotenv never overwrites one that is already set.
	switch appEnv {
	case "test":
		godotenv.Load(".env.test")
	case "staging":
		godotenv.Load(".env.staging")
	case "production":
		godotenv.Load(".env")
	default:
		godotenv.Load(".env.local")
	}

	config.InitEnv()

	public, err := fs.Sub(publicFS, "public")

	if err != nil {
		log.Fatalf("unable to open the embedded public directory: %v", err)
	}

	views, err := fs.Sub(viewsFS, "views")

	if err != nil {
		log.Fatalf("unable to open the embedded views directory: %v", err)
	}

	config.PublicFS = public
	config.ViewsFS = views

	if data, err := fs.ReadFile(public, ".vite/manifest.json"); err == nil {
		config.ManifestData = data
	}

	cmd.Execute()
}
