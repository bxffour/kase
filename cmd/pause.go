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
	"log"

	"github.com/bxffour/kase/utils"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// pauseCmd represents the pause command
var pauseCmd = &cobra.Command{
	Use:   "pause <container-id>",
	Short: "Pause all processes inside an instance of a container.",
	Long:  `The pause command pauses all processes inside an instance of a container.`,
	Run: func(cmd *cobra.Command, args []string) {
		id := args[0]

		rootless, err := utils.ShouldUseRootlessCgroups(rootless, useSystemdCgroup)
		if err != nil {
			log.Fatal(err)
		}

		if rootless {
			logrus.Warn("pause may fail if you don't have full access to cgroups")
		}

		container, err := utils.GetContainer(statePath, id)
		if err != nil {
			log.Fatal(err)
		}

		if err := container.Pause(); err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(pauseCmd)
}
