/*
Copyright © 2022 Nana Kwadwo <agyemang.nana.b@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/bxffour/kase/utils"
	"github.com/spf13/cobra"
)

var (
	bundle        string
	consoleSocket string
	pidFIle       string
	noPivot       bool
	noNewKeyring  bool
	preserveFds   int
)

// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:   "create",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		runner := &utils.RunnerOpts{
			ConsoleSocket: consoleSocket,
			PidFile:       pidFIle,
			NoNewKeyring:  noNewKeyring,
			PreserveFDs:   preserveFds,
		}

		options := &utils.ConfigOpts{
			UseSystemdCgroup: useSystemdCgroup,
			NoPivotRoot:      noPivot,
			NoNewKeyring:     noNewKeyring,
			Rootless:         rootless,
			StatePath:        statePath,
		}

		status, err := runner.StartContainer(bundle, args[0], statePath, utils.ACT_CREATE, *options)
		if err == nil {
			os.Exit(status)
		}

		return fmt.Errorf("kase create failed: %w", err)
	},
}

func init() {
	consoleUsage := "path to the AF_UNIX for receiving master fd referencing the master end of the console's psuedoterminal"
	bundleUsage := "path to the root directory of the OCI bundle, defaults to current directory"
	preserveFdsUsage := "Pass N additional file descriptors to the container (stdio + $LISTEN_FDS + N in total)"

	rootCmd.AddCommand(createCmd)

	createCmd.Flags().StringVarP(&bundle, "bundle", "b", ".", bundleUsage)
	createCmd.Flags().StringVar(&pidFIle, "pid-file", "", "specify the file to write the process id to")
	createCmd.Flags().StringVar(&consoleSocket, "console-socket", "", consoleUsage)
	createCmd.Flags().BoolVar(&noPivot, "no-pivot", false, "deactivate pivot_root()")
	createCmd.Flags().BoolVar(&noNewKeyring, "no-new-keyring", false, "do not create a new session keyring for the container")
	createCmd.Flags().IntVar(&preserveFds, "preserve-fds", 0, preserveFdsUsage)
}
