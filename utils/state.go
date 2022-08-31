package utils

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/user"
	"github.com/opencontainers/runc/libcontainer/utils"
)

type ConstainerState struct {
	Version     string            `json:"ociVersion"`
	ID          string            `json:"id"`
	InitPid     int               `json:"pid"`
	Status      string            `json:"status"`
	Bundle      string            `json:"bundle"`
	Rootfs      string            `json:"rootfs"`
	Created     time.Time         `json:"created"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Owner       string            `json:"owner"`
}

func GetContainers(statePath string) ([]ConstainerState, error) {
	ctrlist, err := os.ReadDir(statePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	var s []ConstainerState
	for _, ctr := range ctrlist {
		if !ctr.IsDir() {
			continue
		}

		st, err := ctr.Info()
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}

		uid := st.Sys().(*syscall.Stat_t).Uid
		owner, err := user.LookupUid(int(uid))
		if err != nil {
			owner.Name = fmt.Sprintf("#%d", uid)
		}

		container, err := GetContainer(statePath, ctr.Name())
		if err != nil {
			fmt.Fprintf(os.Stderr, "kase: error loading container %s, %v\n", ctr.Name(), err)
			continue
		}

		ctrStatus, err := container.Status()
		if err != nil {
			fmt.Fprintf(os.Stderr, "kase: status for %s, %v\n", ctr.Name(), err)
			continue
		}

		state, err := container.State()
		if err != nil {
			fmt.Fprintf(os.Stderr, "kase: state for %s, %v\n", ctr.Name(), err)
			continue
		}

		pid := state.BaseState.InitProcessPid
		if ctrStatus == libcontainer.Stopped {
			pid = 0
		}

		bundle, annotations := utils.Annotations(container.Config().Labels)
		s = append(s, ConstainerState{
			Version:     state.BaseState.Config.Version,
			ID:          state.ID,
			InitPid:     pid,
			Status:      ctrStatus.String(),
			Bundle:      bundle,
			Created:     state.BaseState.Created,
			Rootfs:      state.BaseState.Config.Rootfs,
			Annotations: annotations,
			Owner:       owner.Name,
		})
	}

	return s, nil
}
