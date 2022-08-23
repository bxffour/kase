package utils

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

type notifySocket struct {
	socket   *net.UnixConn
	host     string
	sockPath string
}

func newNotifySocket(root, notifysockerHost, id string) *notifySocket {
	if notifysockerHost == "" {
		return nil
	}

	root = filepath.Join(root, id)
	socketPath := filepath.Join(root, "notify", "notify.sock")

	return &notifySocket{
		socket:   nil,
		host:     notifysockerHost,
		sockPath: socketPath,
	}
}

func (s *notifySocket) Close() error {
	return s.socket.Close()
}

func (s *notifySocket) setupSpec(spec *specs.Spec) {
	pathInContainer := filepath.Join("/run/notify", filepath.Base(s.sockPath))

	mount := specs.Mount{
		Destination: filepath.Dir(pathInContainer),
		Source:      filepath.Dir(s.sockPath),
		Options:     []string{"bind", "nosuid", "noexec", "nodev", "ro"},
	}

	spec.Mounts = append(spec.Mounts, mount)
	spec.Process.Env = append(spec.Process.Env, "NOTIFY_SOCKET="+pathInContainer)
}

func (s *notifySocket) bindSocket() error {
	addr := net.UnixAddr{
		Name: s.sockPath,
		Net:  "Unixgram",
	}

	socket, err := net.ListenUnixgram("unixgram", &addr)
	if err != nil {
		return err
	}

	err = unix.Chmod(s.sockPath, 0o777)
	if err != nil {
		socket.Close()
		return err
	}

	s.socket = socket
	return err
}

func (s *notifySocket) setupSocketDir() error {
	return os.Mkdir(filepath.Dir(s.sockPath), 0o755)
}

func NotifySocketStart(root, notifySocketPath, id string) (*notifySocket, error) {
	notifySock := newNotifySocket(root, notifySocketPath, id)
	if notifySock == nil {
		return nil, nil
	}

	err := notifySock.bindSocket()
	if err != nil {
		return nil, err
	}

	return notifySock, nil
}

func (s *notifySocket) WaitForContainer(container libcontainer.Container) error {
	state, err := container.State()
	if err != nil {
		return err
	}

	return s.Run(state.InitProcessPid)
}

func (n *notifySocket) Run(pid1 int) error {
	if n.socket == nil {
		return nil
	}

	nsockAddr := net.UnixAddr{Name: "unixgram", Net: n.host}
	client, err := net.DialUnix("unixgram", nil, &nsockAddr)
	if err != nil {
		return err
	}

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	fileChan := make(chan []byte)
	go func() {
		for {
			buf := make([]byte, 4096)
			r, err := n.socket.Read(buf)
			if err != nil {
				return
			}

			got := buf[0:r]

			for _, line := range bytes.Split(got, []byte{'\n'}) {
				if bytes.HasPrefix(got, []byte("READY=")) {
					fileChan <- line
					return
				}
			}
		}
	}()

	for {
		select {
		case <-ticker.C:
			_, err := os.Stat("/proc/" + strconv.Itoa(pid1))
			if err != nil {
				return nil
			}

		case b := <-fileChan:
			var out bytes.Buffer

			_, err = out.Write(b)
			if err != nil {
				return err
			}

			_, err = out.Write([]byte{'\n'})
			if err != nil {
				return err
			}

			_, err := client.Write(out.Bytes())
			if err != nil {
				return err
			}

			newPid := "MAINPID=" + strconv.Itoa(pid1)
			_, err = client.Write([]byte(newPid + "\n"))
			if err != nil {
				return err
			}

			return nil
		}
	}
}
