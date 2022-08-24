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
	"github.com/bxffour/kase/utils"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	all bool
)

var killExample = `1. Sending SIGKILL to all processes inside a container with id alpine01

  # kase kill --all alpine01 KILL

This commands also supports numerical values for signals. The signal argument is also case 
insensitive. The following commands are also valid:

  # kase kill alpine01 kill

  # kase kill alpine01 9
`

var killCmd = &cobra.Command{
	Use:                   "kill [--all] <container-id> [signal]",
	Short:                 "Sends a specified signal to a given container's init process.",
	Example:               killExample,
	DisableFlagsInUseLine: true,
	Args:                  cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		id := args[0]

		container, err := utils.GetContainer(statePath, id)
		if err != nil {
			logrus.Fatal(err)
		}

		var signal string
		if len(args) == 2 {
			signal = args[1]
		}

		if signal == "" {
			signal = "SIGTERM"
		}

		sig, err := utils.ParseSignal(signal)
		if err != nil {
			logrus.Fatal(err)
		}

		if err := container.Signal(sig, all); err != nil {
			logrus.Fatal(err)
		}

	},
}

func init() {
	rootCmd.AddCommand(killCmd)

	killCmd.Flags().BoolVarP(&all, "all", "a", false, "send specified signall to all processes inside the container")
}
