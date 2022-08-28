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

type FactoryOpts struct {
	UseSystemdCgroup bool
	NoPivotRoot      bool
	NoNewKeyring     bool
	Rootless         string
}

func (f *FactoryOpts) CreateContainer(state string, id string, spec *specs.Spec) (libcontainer.Container, error) {
	rootlessCg, err := shouldUseRootlessCgroups(f.Rootless, f.UseSystemdCgroup)
	if err != nil {
		return nil, err
	}

	config, err := specconv.CreateLibcontainerConfig(&specconv.CreateOpts{
		CgroupName:       id,
		UseSystemdCgroup: f.UseSystemdCgroup,
		NoPivotRoot:      f.NoPivotRoot,
		NoNewKeyring:     f.NoNewKeyring,
		Spec:             spec,
		RootlessEUID:     os.Geteuid() != 0,
		RootlessCgroups:  rootlessCg,
	})

	if err != nil {
		return nil, err
	}

	factory, err := loadfactory(state)
	if err != nil {
		return nil, err
	}

	return factory.Create(id, config)
}

func (r *Runner) revisePidFile() error {
	if r.PidFile == "" {
		return nil
	}

	var err error
	r.PidFile, err = filepath.Abs(r.PidFile)
	if err != nil {
		return err
	}

	return nil
}

func (r *Runner) StartContainer(bundle, id, state string, act action) (int, error) {

	if err := r.revisePidFile(); err != nil {
		return -1, err
	}

	spec, err := SetupSpec(bundle)
	if err != nil {
		return -1, err
	}

	if id == "" {
		return -1, errors.New("id must not be empty")
	}

	nsock := newNotifySocket(state, os.Getenv("NOTIFY_SOCKET"), id)
	if nsock != nil {
		nsock.setupSpec(spec)
	}

	container, err := r.CreateContainer(state, id, spec)
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

	r.init = true
	r.listenFDs = listenFDs
	r.container = container
	r.action = act
	r.notifySocket = nsock

	return r.run(spec.Process)
}
