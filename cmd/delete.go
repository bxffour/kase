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
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/bxffour/kase/utils"
	"github.com/opencontainers/runc/libcontainer"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

const checkSignal = unix.Signal(0)

var force bool

func killContainer(container libcontainer.Container) error {
	_ = container.Signal(checkSignal, false)
	for i := 0; i < 100; i++ {
		time.Sleep(100 * time.Millisecond)
		if err := container.Signal(checkSignal, false); err != nil {
			utils.Destroy(container)
			return nil
		}
	}
	return errors.New("container still running")
}

// deleteCmd represents the delete command
var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		id := args[0]

		container, err := utils.GetContainer(statePath, id)
		if err != nil {
			if errors.Is(err, libcontainer.ErrNotExist) {
				path := filepath.Join(statePath, id)
				if e := os.RemoveAll(path); e != nil {
					fmt.Fprintf(os.Stderr, "remove %s: %v\n", path, e)
				}

				if force {
					return
				}
			}

			logrus.Fatal(err)
		}

		s, err := container.Status()
		if err != nil {
			log.Fatal(err)
		}

		switch s {
		case libcontainer.Stopped:
			utils.Destroy(container)
		case libcontainer.Created:
			killContainer(container)
		default:
			if force {
				killContainer(container)
			}

			logrus.Error(fmt.Errorf("%s: cannot delete container in a %s state", id, s))
		}
	},
}

func init() {
	rootCmd.AddCommand(deleteCmd)

	deleteCmd.Flags().BoolVarP(&force, "force", "f", false, "uses SIGKILL to forcibly delete container")

}
