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

// killCmd represents the kill command
var killCmd = &cobra.Command{
	Use:   "kill",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Args: cobra.RangeArgs(1, 2),
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
