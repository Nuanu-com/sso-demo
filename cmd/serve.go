/*
 */
package cmd

import (
	"fmt"
	"log"

	"github.com/gofiber/fiber/v3/middleware/static"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/gofiber/template/html/v3"
	"github.com/nuanu/sso-demo/config"
	"github.com/nuanu/sso-demo/core"
	"github.com/nuanu/sso-demo/endpoints"
	"github.com/nuanu/sso-demo/session"
	"github.com/spf13/cobra"
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Starting the server",
	Long: `Starting the http server
		-p to change port
		-b to change ip binding
	`,
	Run: func(cmd *cobra.Command, args []string) {
		flags := cmd.Flags()

		port, err := flags.GetInt16("port")

		if err != nil {
			panic("Failed to get port")
		}

		bind, err := flags.GetString("bind")

		if err != nil {
			panic("Failed to get bind")
		}

		if err := Container.Invoke(func(engine *html.Engine) {
			core.AssetHtml(engine)
			core.Helpers(engine)
		}); err != nil {
			log.Fatal(err)
		}

		if err := Container.Invoke(middlewares); err != nil {
			log.Fatal(err)
		}

		if err := Container.Invoke(endpoints.RouteWeb); err != nil {
			log.Fatal(err)
		}

		if err := Container.Invoke(func(app *fiber.App) {
			app.Get("/*", static.New("", static.Config{FS: config.PublicFS}))

			log.Fatal(app.Listen(fmt.Sprintf("%s:%v", bind, port)))
		}); err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().Int16P("port", "p", 3001, "to set the port")
	serveCmd.Flags().StringP("bind", "b", "127.0.0.1", "to set the IP binding")
}

func middlewares(app *fiber.App) {
	app.Use(logger.New(logger.Config{
		Format:     "${time} ${ip} => ${status} - ${method} ${path} : ${latency} - ${error}\n",
		TimeFormat: "2006/01/02 15:04:05",
	}))

	// Every route gets a session: the sign-in state has to be stored before the
	// user is authenticated, which is precisely when there is no user yet.
	app.Use(session.Middleware())
}
