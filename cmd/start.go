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
	"errors"
	"fmt"
	"os"

	"github.com/bxffour/kase/utils"
	"github.com/opencontainers/runc/libcontainer"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var startLong = `
start runs user defines processes in a created container. It takes the container-id as 
its only argument.
`

var startExample = `To start a container with id 'alpine01'

	# kase start alpine01`

var startCmd = &cobra.Command{
	Use:                   "start <container-id>",
	Short:                 "Start runs user defined process in a created container",
	Long:                  startLong,
	Args:                  cobra.ExactArgs(1),
	Example:               startExample,
	DisableFlagsInUseLine: true,
	Run: func(cmd *cobra.Command, args []string) {
		id := args[0]

		container, err := utils.GetContainer(statePath, id)
		if err != nil {
			logrus.Fatal(err)
		}

		status, err := container.Status()
		if err != nil {
			logrus.Fatal(err)
		}

		switch status {
		case libcontainer.Created:
			nsock, err := utils.NotifySocketStart(statePath, os.Getenv("NOTIFY_SOCKET"), container.ID())
			if err != nil {
				logrus.Fatal(err)
			}

			if err := container.Exec(); err != nil {
				logrus.Fatal(err)
			}

			if nsock != nil {
				logrus.Fatal(nsock.WaitForContainer(container))
			}
		case libcontainer.Stopped:
			logrus.Error(errors.New("container stopped: cannot start a stopped container"))
		case libcontainer.Running:
			logrus.Error(errors.New("container running: connot start a running container"))
		default:
			logrus.Error(fmt.Errorf("cannot start a container in %s state", status))
		}
	},
}

func init() {
	rootCmd.AddCommand(startCmd)
}
