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
	"encoding/json"
	"os"

	kutils "github.com/bxffour/kase/utils"
	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/utils"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// stateCmd represents the state command
var stateCmd = &cobra.Command{
	Use:   "state",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		id := args[0]
		container, err := kutils.GetContainer(statePath, id)
		if err != nil {
			logrus.Fatal(err)
		}

		containerStatus, err := container.Status()
		if err != nil {
			logrus.Fatal(err)
		}

		state, err := container.State()
		if err != nil {
			logrus.Fatal(err)
		}

		pid := state.BaseState.InitProcessPid
		if containerStatus == libcontainer.Stopped {
			pid = 0
		}

		bundle, annotations := utils.Annotations(state.Config.Labels)
		cs := kutils.ConstainerState{
			Version:     state.BaseState.Config.Version,
			ID:          state.BaseState.ID,
			InitPid:     pid,
			Status:      containerStatus.String(),
			Bundle:      bundle,
			Created:     state.BaseState.Created,
			Annotations: annotations,
		}

		data, err := json.MarshalIndent(cs, "", " ")
		if err != nil {
			logrus.Fatal(err)
		}

		os.Stdout.Write(data)
	},
}

func init() {
	rootCmd.AddCommand(stateCmd)
}
