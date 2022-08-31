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

var (
	consoleSocket  string
	cwd            string
	env            []string
	tty            bool
	user           string
	additionalGids []int64
	process        string
	detach         bool
	pidFile        string
	processLablel  string
	apparmor       string
	noNewPrivs     bool
	cap            []string
	preserveFds    int
	cgroup         []string
	ignorePaused   bool
)

var execCmd = &cobra.Command{
	Use:   "exec [options] <container-id> command [command-options] || -p process.json <container-id>",
	Short: "Execute a new process inside a container",
	Long: `The exec command execute a new process inside a container. 
	
	The <container-id> is the instance of the container a process should be run in, and <command> is the
	command to be executed in the container. <command> cannot be empty unless the '-p' flag is provided.`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		id := args[0]

		pp := utils.ProcessOpts{
			Process:        process,
			Cwd:            cwd,
			Apparmour:      apparmor,
			ProcessLabel:   processLablel,
			Cap:            cap,
			Env:            env,
			Args:           args,
			Cgroups:        cgroup,
			Tty:            tty,
			NoNewPrivs:     noNewPrivs,
			IgnorePaused:   ignorePaused,
			User:           user,
			AdditionalGids: additionalGids,
		}

		runner := utils.Runner{
			ProcessOpts:   pp,
			PidFile:       pidFile,
			ConsoleSocket: consoleSocket,
			Detach:        detach,
			PreserveFDS:   preserveFds,
		}

		status, err := runner.Exec(statePath, id)
		if err == nil {
			os.Exit(status)
		}

		logrus.Error(err)
	},
}

func init() {
	rootCmd.AddCommand(execCmd)

	execCmd.Flags().StringVar(&consoleSocket, "console-socket", "", "path to an AF_UNIX socket")
	execCmd.Flags().StringVar(&cwd, "cwd", "", "cwd in the container")
	execCmd.Flags().StringVarP(&user, "user", "u", "", "UID (<uid>:<gid>)")
	execCmd.Flags().StringVarP(&process, "process", "p", "", "path to the process.json")
	execCmd.Flags().StringVar(&pidFile, "pid-file", "", "file to write process id to")
	execCmd.Flags().StringVar(&processLablel, "process-label", "", "set the asm label for the process")
	execCmd.Flags().StringVar(&apparmor, "apparmour", "", "set apparmour profile for the process")
	execCmd.Flags().StringSliceVarP(&env, "env", "e", nil, "set environment variables")
	execCmd.Flags().StringSliceVarP(&cap, "cap", "c", []string{}, "add capabilities to bounding set for the process")
	execCmd.Flags().StringSliceVar(&cgroup, "cgroup", nil, "run the process in existing sub-cgroup. Format: [<controller>:]<cgroup>.")
	execCmd.Flags().BoolVar(&tty, "tty", false, "allocate a psuedo-TTY")
	execCmd.Flags().BoolVar(&detach, "detach", false, "detach from the container's process")
	execCmd.Flags().BoolVar(&noNewPrivs, "no-new-privs", false, "set the no new privilege value for the process")
	execCmd.Flags().BoolVar(&ignorePaused, "ignore-paused", false, "allow exec in paused container")
	execCmd.Flags().Int64SliceVarP(&additionalGids, "additional-gids", "g", nil, "additonal gids")
	execCmd.Flags().IntVar(&preserveFds, "preserve-fds", 0, "pass N additional fds to the container")

}
