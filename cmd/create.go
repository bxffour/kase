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

var cFlag = runFlags{}

var preserveFdsUsage = "Pass N additional file descriptors to the container (stdio + $LISTEN_FDS + N in total)"
var consoleUsage = "path to the AF_UNIX for receiving master fd referencing the master end of the console's psuedoterminal"

var createLong = `This command creates an instance of a container for a given bundle. It takes
the a unique container id as its only are argument.
`

var createCmd = &cobra.Command{
	Use:                   "create [OPTIONS] <container-id>",
	Short:                 "Create an instance of a container",
	Long:                  createLong,
	Args:                  cobra.ExactArgs(1),
	DisableFlagsInUseLine: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// runner := &utils.RunnerOpts{
		// 	ConsoleSocket: cFlag.consoleSocket,
		// 	PidFile:       cFlag.pidFile,
		// 	NoNewKeyring:  cFlag.noNewKeyring,
		// 	PreserveFDs:   cFlag.preseveFds,
		// }

		options := utils.FactoryOpts{
			UseSystemdCgroup: useSystemdCgroup,
			NoPivotRoot:      cFlag.noPivot,
			NoNewKeyring:     cFlag.noNewKeyring,
			Rootless:         rootless,
		}

		runner := &utils.Runner{
			FactoryOpts:   options,
			ConsoleSocket: cFlag.consoleSocket,
			PidFile:       cFlag.pidFile,
			PreserveFDS:   cFlag.preseveFds,
		}

		status, err := runner.StartContainer(cFlag.bundle, args[0], statePath, utils.ACT_CREATE)
		if err == nil {
			os.Exit(status)
		}

		return fmt.Errorf("kase create failed: %w", err)
	},
}

func init() {
	bundleUsage := "path to the root directory of the OCI bundle, defaults to current directory"

	rootCmd.AddCommand(createCmd)

	createCmd.Flags().StringVarP(&cFlag.bundle, "bundle", "b", ".", bundleUsage)
	createCmd.Flags().StringVar(&cFlag.pidFile, "pid-file", "", "specify the file to write the process id to")
	createCmd.Flags().StringVar(&cFlag.consoleSocket, "console-socket", "", consoleUsage)
	createCmd.Flags().BoolVar(&cFlag.noPivot, "no-pivot", false, "deactivate pivot_root()")
	createCmd.Flags().BoolVar(&cFlag.noNewKeyring, "no-new-keyring", false, "do not create a new session keyring for the container")
	createCmd.Flags().IntVar(&cFlag.preseveFds, "preserve-fds", 0, preserveFdsUsage)
}
