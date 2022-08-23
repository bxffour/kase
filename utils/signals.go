package utils

import (
	"os"
	"os/signal"

	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/system"
	"github.com/opencontainers/runc/libcontainer/utils"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const signalufferSize = 2048

type signalHandler struct {
	signals      chan os.Signal
	notifySocket *notifySocket
}

type exit struct {
	pid    int
	status int
}

func newSignalHandler(enableSubreaper bool, notifySocket *notifySocket) *signalHandler {
	if enableSubreaper {
		if err := system.SetSubreaper(1); err != nil {
			logrus.Warn(err)
		}
	}

	s := make(chan os.Signal, signalufferSize)
	signal.Notify(s)

	return &signalHandler{
		signals:      s,
		notifySocket: notifySocket,
	}
}

func (h *signalHandler) forward(process *libcontainer.Process, tty *tty, detach bool) (int, error) {
	if detach && h.notifySocket == nil {
		return 0, nil
	}

	pid1, err := process.Pid()
	if err != nil {
		return -1, err
	}

	if h.notifySocket != nil {
		if detach {
			_ = h.notifySocket.Run(pid1)
		}

		_ = h.notifySocket.Run(os.Getpid())
		go func() { _ = h.notifySocket.Run(0) }()
	}

	_ = tty.resize()

	for s := range h.signals {
		switch s {
		case unix.SIGWINCH:
			_ = tty.resize()
		case unix.SIGCHLD:
			exits, err := h.reap()
			if err != nil {
				logrus.Error(err)
			}

			for _, e := range exits {
				logrus.WithFields(logrus.Fields{
					"pid":    e.pid,
					"status": e.status,
				}).Debug("process exited")

				if e.pid == pid1 {
					_, _ = process.Wait()
					return e.status, nil
				}
			}
		case unix.SIGURG:
			// do nothing
		default:
			us := s.(unix.Signal)
			logrus.Debugf("forwarding signal %d (%s) to %d", int(us), unix.SignalName(us), pid1)
			if err := unix.Kill(pid1, us); err != nil {
				logrus.Error(err)
			}
		}
	}

	return -1, nil
}

func (h *signalHandler) reap() (exits []exit, err error) {

	var (
		ws  unix.WaitStatus
		rus unix.Rusage
	)

	for {
		pid, err := unix.Wait4(-1, &ws, unix.WNOHANG, &rus)
		if err != nil {
			if err == unix.ECHILD {
				return exits, err
			}
			return nil, err
		}

		if pid <= 0 {
			return exits, nil
		}

		exits = append(exits, exit{
			pid:    pid,
			status: utils.ExitStatus(ws),
		})
	}
}
