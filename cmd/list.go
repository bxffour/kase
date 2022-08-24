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
	"errors"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/bxffour/kase/utils"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	quiet  bool
	format string
)

var listLong = `
The 'list' command lists the containers started by kase with
a given state directory.
The state directory is specified with the '--state' global option.
(default: "` + statePath + `")`

var examples = `1. To list containers created via the global state flag
	# kase list

2. To list containers created via a non default state path
	# kase --state value list
`

var listCmd = &cobra.Command{
	Use:                   "list [OPTIONS]",
	Short:                 "List lists containers started by kase with a given state directory",
	Long:                  listLong,
	Example:               examples,
	Args:                  cobra.NoArgs,
	DisableFlagsInUseLine: true,
	Run: func(cmd *cobra.Command, args []string) {
		s, err := utils.GetContainers(statePath)
		if err != nil {
			logrus.Fatal(err)
		}

		if quiet {
			for _, item := range s {
				fmt.Println(item.ID)
			}
		}

		switch format {
		case "table":
			w := tabwriter.NewWriter(os.Stdout, 12, 1, 3, ' ', 0)
			fmt.Fprintf(w, "ID\tPID\tSTATUS\tBUNDLE\tCREATED\tOWNER\n")
			for _, item := range s {
				fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\n",
					item.ID,
					item.InitPid,
					item.Status,
					item.Bundle,
					item.Created.Format(time.RFC3339Nano),
					item.Owner)
			}

			if err := w.Flush(); err != nil {
				logrus.Fatal(err)
			}

		case "json":
			if err := json.NewEncoder(os.Stdout).Encode(s); err != nil {
				logrus.Fatal(err)
			}

		default:
			logrus.Fatal(errors.New("invalid format option: `json` or `table`"))
		}
	},
}

func init() {
	rootCmd.AddCommand(listCmd)

	listCmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "display only ids for containers")
	listCmd.Flags().StringVarP(&format, "format", "f", "table", "select 'table' or 'json' as the output format")
}
