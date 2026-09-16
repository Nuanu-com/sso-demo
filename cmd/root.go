package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "sso-demo",
	Short: "A Nuanu SSO relying-party demo",
	Long: `A demo relying party for the Nuanu SSO identity provider.

It signs a user in over OpenID Connect - authorization code with PKCE, state and
nonce - verifies both tokens, reads the profile from UserInfo, and shows every
value next to the step that produced it.

	sso-demo serve    start the HTTP server`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

}
