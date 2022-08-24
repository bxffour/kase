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
	"os"

	"github.com/bxffour/kase/utils"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type runFlags struct {
	bundle        string
	consoleSocket string
	pidFile       string
	detach        bool
	keep          bool
	noSubreaper   bool
	noPivot       bool
	noNewKeyring  bool
	preseveFds    int
}

var runFlag runFlags

var runLong = `Run creates an instance of a container for a given bundle. The current direcory
is assumed to be the bundle path unless one is specified with the --bundle flag.
`

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:                   "run [OPTIONS] <container-id>",
	Short:                 "Run creates and runs containers",
	Long:                  runLong,
	Args:                  cobra.ExactArgs(1),
	Example:               "# kase run -b bundle/path container-id",
	DisableFlagsInUseLine: true,
	Run: func(cmd *cobra.Command, args []string) {
		runner := &utils.RunnerOpts{
			NoSubreaper:   runFlag.noSubreaper,
			ShouldDestroy: runFlag.keep,
			NoNewKeyring:  runFlag.noNewKeyring,
			ConsoleSocket: runFlag.consoleSocket,
			PidFile:       runFlag.pidFile,
			PreserveFDs:   runFlag.preseveFds,
		}

		createOpts := &utils.ConfigOpts{
			UseSystemdCgroup: useSystemdCgroup,
			NoPivotRoot:      runFlag.noPivot,
			NoNewKeyring:     runFlag.noNewKeyring,
			Rootless:         rootless,
		}

		status, err := runner.StartContainer(runFlag.bundle, args[0], statePath, utils.ACT_RUN, *createOpts)
		if err == nil {
			os.Exit(status)
		}

		logrus.Fatal(err)
	},
}

func init() {
	rootCmd.AddCommand(runCmd)

	runCmd.Flags().StringVarP(&runFlag.bundle, "bundle", "b", "", "specify path to the OCI bundle")
	runCmd.Flags().StringVar(&runFlag.consoleSocket, "console-socket", "", consoleUsage)
	runCmd.Flags().StringVar(&runFlag.pidFile, "pid-file", "", "specify file to write process ID to")
	runCmd.Flags().BoolVarP(&runFlag.detach, "detatch", "d", false, "detatch from container process")
	runCmd.Flags().BoolVar(&runFlag.keep, "keep", false, "keep the container after it exits")
	runCmd.Flags().BoolVar(&runFlag.noSubreaper, "no-subreaper", false, "do not use subreaper to reap reparented processes")
	runCmd.Flags().BoolVar(&runFlag.noPivot, "no-pivot", false, "disable the use of pivot_root()")
	runCmd.Flags().BoolVar(&runFlag.noNewKeyring, "no-new-keyring", false, "do not create a new session keyring for the container")
	runCmd.Flags().IntVar(&runFlag.preseveFds, "preserve-fds", 0, preserveFdsUsage)

}
