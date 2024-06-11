package commands

import (
	"fmt"
	"os"
	"syscall"

	"github.com/consol-monitoring/snclient/pkg/snclient"
	"github.com/consol-monitoring/snclient/pkg/utils"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func init() {
	hashCmd := &cobra.Command{
		Use:   "hash",
		Short: "Hash password string",
		Long: `Hash can be used to create hashed password strings.

Examples:

# simply convert text to hash:
snclient hash <password>

# ask password from user input and convert this:
snclient hash
`,
		Run: func(cmd *cobra.Command, args []string) {
			agentFlags.Mode = snclient.ModeOneShot
			setInteractiveStdoutLogger()
			var input string
			if len(args) > 0 {
				input = args[0]
			} else {
				input = readPassword(cmd)
			}

			if input == "" {
				fmt.Fprintf(rootCmd.OutOrStderr(), "%s", cmd.Long)
				os.Exit(3)
			}

			sum, err := utils.Sha256Sum(input)
			if err != nil {
				fmt.Fprintf(cmd.OutOrStderr(), "calculating hash sum failed: %s", err.Error())
				os.Exit(3)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "hash sum: %s:%s\n", "SHA256", sum)
			os.Exit(snclient.ExitCodeOK)
		},
	}
	rootCmd.AddCommand(hashCmd)
}

func readPassword(cmd *cobra.Command) string {
	fmt.Fprintf(cmd.OutOrStdout(), "enter password to hash or hit ctrl+c to exit.\n")
	b, _ := term.ReadPassword(int(syscall.Stdin)) //nolint:unconvert,nolintlint // unconvert detects a conversion here but it is one on windows

	return string(b)
}
