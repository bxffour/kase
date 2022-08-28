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
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/bxffour/kase/utils"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	statePath        string
	logFile          string
	logFormat        string
	xdgDirUsed       = false
	debug            bool
	useSystemdCgroup bool
	rootless         string
)

var rootLong = `
kase is a simple OCI compliant container runtime. It creates containers from OCI bundles
and performs other management tasks.

To start a new instance of a container:

  # kase run [-b bundle] <container-id>

The  <container-id> is a unique identifier for the container to be started. Providing the
bundle is optional. The default value for bundle is the current directory.
`

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "kase [GLOBAL OPTIONS]",
	Short:   "Kase is a simple OCI compliant container runtime",
	Long:    rootLong,
	Version: "0.0.1",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		switch {
		case xdgDirUsed:
			if err := os.MkdirAll(statePath, 0o700); err != nil {
				fmt.Fprintln(os.Stderr, "the path to $XDG_RUNTIME_DIR must be writable by the user")
				os.Exit(1)
			}

			if err := os.Chmod(statePath, 0o700|os.ModeSticky); err != nil {
				fmt.Fprintln(os.Stderr, "please check the permission of the path in $XDG_RUNTIME_DIR")
				os.Exit(1)
			}

		default:
			var err error

			statePath, err = utils.ReviseStateDir(statePath)
			if err != nil {
				return err
			}
		}

		return configLogrus(debug, logFile, logFormat)
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	defaultStateDir := "/run/kase"

	xdgRuntimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if xdgRuntimeDir != "" && utils.ShouldHonorXDGRuntimeDir() {
		defaultStateDir = xdgRuntimeDir + "/kase"
		xdgDirUsed = true
	}

	rootCmd.PersistentFlags().StringVar(&statePath, "state", defaultStateDir, "root directory for container state")
	rootCmd.PersistentFlags().BoolVar(&useSystemdCgroup, "systemd-cgroup", false, "enable systemd cgroup support")
	rootCmd.PersistentFlags().StringVar(&rootless, "rootless", "auto", "ignore cgroup permission errors")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "enable debug logging")
	rootCmd.PersistentFlags().StringVar(&logFile, "log", "/dev/stderr", "set log file to write kase logs to")
	rootCmd.PersistentFlags().StringVar(&logFormat, "log-format", "text", "set the log format")
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func configLogrus(debug bool, logFile, logFormat string) error {
	if debug {
		logrus.SetLevel(logrus.DebugLevel)
		logrus.SetReportCaller(true)

		_, file, _, _ := runtime.Caller(0)
		prefix := filepath.Dir(file) + "/"
		logrus.SetFormatter(&logrus.TextFormatter{
			CallerPrettyfier: func(f *runtime.Frame) (function string, file string) {
				function = strings.TrimPrefix(f.Function, prefix) + "()"
				fileLine := strings.TrimPrefix(f.File, prefix) + ":" + strconv.Itoa(f.Line)
				return function, fileLine
			},
		})
	}

	switch logFormat {
	case "text":
		// do nothing
	case "json":
		logrus.SetFormatter(new(logrus.JSONFormatter))
	default:
		return errors.New("invalid log-format: " + logFormat)
	}

	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_SYNC, 0o644)
		if err != nil {
			return err
		}

		logrus.SetOutput(f)
	}

	return nil
}
