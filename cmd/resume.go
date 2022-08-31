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

// resumeCmd represents the resume command
var resumeCmd = &cobra.Command{
	Use:   "resume <container-id>",
	Short: "Resume all processes that have been previously paused",
	Long:  `The resume command resumes processes that have been previously paused.`,
	Run: func(cmd *cobra.Command, args []string) {
		id := args[0]

		rootless, err := utils.ShouldUseRootlessCgroups(rootless, useSystemdCgroup)
		if err != nil {
			logrus.Fatal(err)
		}

		if rootless {
			logrus.Warn("resume may fail if you don't have full access to cgroups")
		}

		container, err := utils.GetContainer(statePath, id)
		if err != nil {
			logrus.Fatal(err)
		}

		if err := container.Resume(); err != nil {
			logrus.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(resumeCmd)
}
