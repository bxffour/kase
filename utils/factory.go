package utils

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/coreos/go-systemd/v22/activation"
	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/specconv"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

func GetContainer(root, id string) (libcontainer.Container, error) {
	if id == "" {
		return nil, errors.New("container id cannot be empty")
	}

	factory, err := loadfactory(root)
	if err != nil {
		return nil, err
	}

	return factory.Load(id)
}

func Destroy(container libcontainer.Container) {
	if err := container.Destroy(); err != nil {
		logrus.Error(err)
	}
}

type ConfigOpts struct {
	UseSystemdCgroup bool
	NoPivotRoot      bool
	NoNewKeyring     bool
	Rootless         string
	StatePath        string
}

func (co *ConfigOpts) CreateContainer(id string, spec *specs.Spec) (libcontainer.Container, error) {
	rootlessCg, err := shouldUseRootlessCgroups(co.Rootless, co.UseSystemdCgroup)
	if err != nil {
		return nil, err
	}

	config, err := specconv.CreateLibcontainerConfig(&specconv.CreateOpts{
		CgroupName:       id,
		UseSystemdCgroup: co.UseSystemdCgroup,
		NoPivotRoot:      co.NoPivotRoot,
		NoNewKeyring:     co.NoNewKeyring,
		Spec:             spec,
		RootlessEUID:     os.Geteuid() != 0,
		RootlessCgroups:  rootlessCg,
	})

	if err != nil {
		return nil, err
	}

	factory, err := loadfactory(co.StatePath)
	if err != nil {
		return nil, err
	}

	return factory.Create(id, config)
}

type RunnerOpts struct {
	NoSubreaper   bool
	ShouldDestroy bool
	ConsoleSocket string
	PidFile       string
	NoNewKeyring  bool
	PreserveFDs   int
}

func (ro *RunnerOpts) revisePidFile() error {
	if ro.PidFile == "" {
		return nil
	}

	var err error
	ro.PidFile, err = filepath.Abs(ro.PidFile)
	if err != nil {
		return err
	}

	return nil
}

func (ro *RunnerOpts) StartContainer(bundle, id, root string, act action, options ConfigOpts) (int, error) {

	if err := ro.revisePidFile(); err != nil {
		return -1, err
	}

	spec, err := SetupSpec(bundle)
	if err != nil {
		return -1, err
	}

	if id == "" {
		return -1, errors.New("id must not be empty")
	}

	nsock := newNotifySocket(root, os.Getenv("NOTIFY_SOCKET"), id)
	if nsock != nil {
		nsock.setupSpec(spec)
	}

	container, err := options.CreateContainer(id, spec)
	if err != nil {
		return -1, err
	}

	if nsock != nil {
		if err := nsock.setupSocketDir(); err != nil {
			return -1, err
		}

		if act == ACT_RUN {
			if err := nsock.bindSocket(); err != nil {
				return -1, err
			}
		}
	}

	listenFDs := []*os.File{}
	if os.Getenv("LISTEN_FDS") != "" {
		listenFDs = activation.Files(false)
	}

	r := &runner{
		init:            true,
		enableSubreaper: !ro.NoSubreaper,
		shouldDestroy:   ro.ShouldDestroy,
		listenFDs:       listenFDs,
		preserveFDS:     ro.PreserveFDs,
		pidFile:         ro.PidFile,
		consoleSocket:   ro.ConsoleSocket,
		container:       container,
		action:          act,
		notifySocket:    nsock,
	}

	return r.run(spec.Process)
}
