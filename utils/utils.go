package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/cgroups/systemd"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/userns"
	"github.com/opencontainers/runc/libcontainer/utils"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/opencontainers/selinux/go-selinux"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	specFIle = "config.json"
)

type action uint8

const (
	ACT_CREATE action = iota + 1
	ACT_RUN
)

func loadSpec(specFIle string) (spec *specs.Spec, err error) {
	cf, err := os.Open(specFIle)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("json specification file %s not found", specFIle)
		}
	}

	defer cf.Close()

	if err := json.NewDecoder(cf).Decode(&spec); err != nil {
		return nil, err
	}

	return spec, validateProcess(spec.Process)
}

func setupSpec(bundle string) (spec *specs.Spec, err error) {
	if bundle != "" {
		if err := os.Chdir(bundle); err != nil {
			return nil, err
		}
	}

	spec, err = loadSpec(specFIle)
	if err != nil {
		return nil, err
	}

	return spec, nil
}

type Runner struct {
	FactoryOpts
	ProcessOpts
	EnableSubreaper bool
	ShouldDestroy   bool
	PreserveFDS     int
	PidFile         string
	ConsoleSocket   string
	init            bool
	Detach          bool
	listenFDs       []*os.File
	container       libcontainer.Container
	action          action
	notifySocket    *notifySocket
	subCgroupPaths  map[string]string
}

func (r *Runner) run(p *specs.Process) (int, error) {
	var err error

	defer func() {
		if err != nil {
			r.destoy()
		}
	}()

	if err = r.checkTerminal(p); err != nil {
		return -1, err
	}

	process, err := NewProcess(*p)
	if err != nil {
		return -1, err
	}

	process.LogLevel = strconv.Itoa(int(logrus.GetLevel()))
	process.Init = r.init
	process.SubCgroupPaths = r.subCgroupPaths

	if len(r.listenFDs) > 0 {
		process.Env = append(process.Env, "LISTEN_FDS="+strconv.Itoa(len(r.listenFDs)), "LISTEN_PID=1")
		process.ExtraFiles = append(process.ExtraFiles, r.listenFDs...)
	}

	basefd := 3 + len(process.ExtraFiles)
	for i := basefd; i < basefd+r.PreserveFDS; i++ {
		_, err = os.Stat("/proc/self/fd/" + strconv.Itoa(i))
		if err != nil {
			return -1, fmt.Errorf("unable to stat preserved fd %d (of %d): %w", i-basefd, r.PreserveFDS, err)
		}

		process.ExtraFiles = append(process.ExtraFiles, os.NewFile(uintptr(i), "PreserveFD:"+strconv.Itoa(i)))
	}

	rootuid, err := r.container.Config().HostRootUID()
	if err != nil {
		return -1, err
	}

	rootgid, err := r.container.Config().HostRootGID()
	if err != nil {
		return -1, err
	}

	detach := r.Detach || (r.action == ACT_CREATE)

	handler := newSignalHandler(r.EnableSubreaper, r.notifySocket)
	tty, err := setupIO(process, rootuid, rootgid, p.Terminal, detach, r.ConsoleSocket)
	if err != nil {
		return -1, err
	}

	defer tty.close()

	switch r.action {
	case ACT_CREATE:
		err = r.container.Start(process)
	case ACT_RUN:
		err = r.container.Run(process)
	default:
		panic("unknown action")
	}

	if err != nil {
		return -1, err
	}

	if err := tty.waitConsole(); err != nil {
		r.terminate(process)
		return -1, err
	}

	tty.closePostStart()
	if r.PidFile != "" {
		if err := createPidFile(r.PidFile, process); err != nil {
			r.terminate(process)
			return -1, err
		}
	}

	status, err := handler.forward(process, tty, detach)
	if err != nil {
		r.terminate(process)
	}

	if detach {
		return 0, nil
	}

	if err == nil {
		r.destoy()
	}

	return status, err
}

func (r *Runner) Exec(root, id string) (int, error) {

	container, err := GetContainer(root, id)
	if err != nil {
		return -1, err
	}

	status, err := container.Status()
	if err != nil {
		return -1, err
	}

	pp := r.ProcessOpts

	if status == libcontainer.Stopped {
		return -1, errors.New("cannot exec into a stopped container")
	}

	if status == libcontainer.Paused && !pp.IgnorePaused {
		return -1, errors.New("cannot exec into a paused container until explicitly allowed (--ignore paused=true)")
	}

	if pp.Process == "" && len(pp.Args) == 1 {
		return -1, errors.New("process args cannot be empty")
	}

	state, err := container.State()
	if err != nil {
		return -1, err
	}

	bundle, ok := searchLabels(state.Config.Labels, "bundle")
	if !ok {
		return -1, errors.New("bundle not found in labels")
	}

	p, err := pp.GetProcess(bundle)
	if err != nil {
		return -1, err
	}

	paths, err := GetSubCgroupPaths(pp.Cgroups)
	if err != nil {
		return -1, err
	}

	r.EnableSubreaper = false
	r.ShouldDestroy = false
	r.init = false
	r.container = container
	r.action = ACT_RUN
	r.subCgroupPaths = paths

	return r.run(p)
}

func searchLabels(labels []string, key string) (string, bool) {
	key += "="
	for _, l := range labels {
		if strings.HasPrefix(l, key) {
			return l[len(key):], true
		}
	}

	return "", false
}

type ProcessOpts struct {
	Process        string
	Cwd            string
	Apparmour      string
	ProcessLabel   string
	Cap            []string
	Env            []string
	Args           []string
	Cgroups        []string
	Tty            bool
	NoNewPrivs     bool
	IgnorePaused   bool
	User           string
	AdditionalGids []int64
}

func (pp *ProcessOpts) GetProcess(bundle string) (*specs.Process, error) {
	if pp.Process != "" {
		f, err := os.Open(pp.Process)
		if err != nil {
			return nil, err
		}

		defer f.Close()
		var p specs.Process

		if err := json.NewDecoder(f).Decode(&p); err != nil {
			return nil, err
		}

		return &p, validateProcess(&p)
	}

	spec, err := setupSpec(bundle)
	if err != nil {
		return nil, err
	}

	p := spec.Process

	p.Args = append(p.Args, pp.Args[1:]...)

	if pp.Cwd != "" {
		p.Cwd = pp.Cwd
	}

	if pp.Apparmour != "" {
		p.ApparmorProfile = pp.Apparmour
	}

	if pp.ProcessLabel != "" {
		p.SelinuxLabel = pp.ProcessLabel
	}

	if len(pp.Cap) > 0 {
		for _, c := range pp.Cap {
			p.Capabilities.Bounding = append(p.Capabilities.Bounding, c)
			p.Capabilities.Ambient = append(p.Capabilities.Ambient, c)
			p.Capabilities.Effective = append(p.Capabilities.Effective, c)
			p.Capabilities.Inheritable = append(p.Capabilities.Inheritable, c)
			p.Capabilities.Permitted = append(p.Capabilities.Permitted, c)
		}
	}

	p.Env = append(p.Env, pp.Env...)

	p.Terminal = false
	p.NoNewPrivileges = false

	if pp.Tty {
		p.Terminal = pp.Tty
	}

	if p.NoNewPrivileges {
		p.NoNewPrivileges = pp.NoNewPrivs
	}

	if pp.User != "" {
		user := strings.SplitN(pp.User, ":", 2)
		if len(user) > 1 {
			gid, err := strconv.Atoi(user[1])
			if err != nil {
				return nil, fmt.Errorf("failed to parse %s as int for uid: %w", user[1], err)
			}

			p.User.GID = uint32(gid)
		}

		uid, err := strconv.Atoi(user[0])
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s as int for gid: %w", user[0], err)
		}

		p.User.UID = uint32(uid)
	}

	for _, gid := range pp.AdditionalGids {
		if gid < 0 {
			return nil, fmt.Errorf("provided gid value must be a positive number %d", gid)
		}

		p.User.AdditionalGids = append(p.User.AdditionalGids, uint32(gid))
	}

	return p, validateProcess(p)
}

func (r *Runner) destoy() {
	if r.ShouldDestroy {
		r.container.Destroy()
	}
}

func (r *Runner) terminate(process *libcontainer.Process) {
	_ = process.Signal(unix.SIGKILL)
	_, _ = process.Wait()
}

func (r *Runner) checkTerminal(config *specs.Process) error {
	detach := r.Detach || (r.action == ACT_CREATE)

	if detach && config.Terminal && r.ConsoleSocket == "" {
		return errors.New("cannot allocate tty without setting console socket")
	}

	if (!detach || !config.Terminal) && r.ConsoleSocket != "" {
		return errors.New("cannot use console socket if kase will not detach or allocate tty")
	}

	return nil
}

func validateProcess(proc *specs.Process) error {
	if proc == nil {
		return errors.New("process property must not be empty")
	}

	if proc.Cwd == "" {
		return errors.New("cwd property must not be empty")
	}

	if !filepath.IsAbs(proc.Cwd) {
		return errors.New("cwd must be an absolute path")
	}

	if len(proc.Args) == 0 {
		return errors.New("args must not be empty")
	}

	if proc.SelinuxLabel != "" && selinux.GetEnabled() {
		return errors.New("selinux enabled in config file, but selinux not supported or enabled")
	}

	return nil
}

func ShouldHonorXDGRuntimeDir() bool {
	if os.Geteuid() != 0 {
		return true
	}

	if !userns.RunningInUserNS() {
		return false
	}

	u, ok := os.LookupEnv("USER")

	return !ok || u != "root"
}

func ReviseStateDir(state string) (path string, err error) {
	path, err = filepath.Abs(state)
	if err != nil {
		return "", err
	}

	if path == "/" {
		return "", errors.New("state directory cannot be set to /")
	}

	return path, nil
}

func NewProcess(p specs.Process) (*libcontainer.Process, error) {
	lp := &libcontainer.Process{
		Args:            p.Args,
		Env:             p.Env,
		User:            fmt.Sprintf("%d:%d", p.User.UID, p.User.GID),
		Cwd:             p.Cwd,
		Label:           p.SelinuxLabel,
		NoNewPrivileges: &p.NoNewPrivileges,
		AppArmorProfile: p.ApparmorProfile,
	}

	// console size
	if p.ConsoleSize != nil {
		lp.ConsoleWidth = uint16(p.ConsoleSize.Width)
		lp.ConsoleHeight = uint16(p.ConsoleSize.Height)
	}

	// capability
	if p.Capabilities != nil {
		lp.Capabilities = &configs.Capabilities{}
		lp.Capabilities.Bounding = p.Capabilities.Bounding
		lp.Capabilities.Effective = p.Capabilities.Effective
		lp.Capabilities.Inheritable = p.Capabilities.Inheritable
		lp.Capabilities.Ambient = p.Capabilities.Ambient
		lp.Capabilities.Permitted = p.Capabilities.Permitted
	}

	// additional gids
	for _, gid := range p.User.AdditionalGids {
		lp.AdditionalGroups = append(lp.AdditionalGroups, strconv.FormatUint(uint64(gid), 10))
	}

	for _, rlimit := range p.Rlimits {
		rl, err := createLibContainerRlimit(rlimit)
		if err != nil {
			return nil, err
		}

		lp.Rlimits = append(lp.Rlimits, rl)
	}

	return lp, nil

}

func GetSubCgroupPaths(args []string) (map[string]string, error) {
	if len(args) == 0 {
		return nil, nil
	}

	paths := make(map[string]string, len(args))
	for _, c := range args {
		cs := strings.SplitN(c, ":", 3)
		if len(cs) > 2 {
			return nil, fmt.Errorf("invalid --cgroup argument: %s", c)
		}

		if len(cs) == 1 {
			if len(args) != 1 {
				return nil, fmt.Errorf("invalid --cgroup argument: %s (missing <controller>: prefix)", c)
			}

			paths[""] = c
		} else {
			for _, ctrl := range strings.Split(cs[0], ",") {
				paths[ctrl] = cs[1]
			}
		}
	}
	return paths, nil
}

func setupIO(process *libcontainer.Process, rootuid, rootgid int, createTty, detach bool, sockpath string) (*tty, error) {
	if createTty {
		process.Stdin = nil
		process.Stdout = nil
		process.Stderr = nil
		t := &tty{}
		if !detach {
			err := t.initHostConsole()
			if err != nil {
				return nil, err
			}

			parent, child, err := utils.NewSockPair("console")
			if err != nil {
				return nil, err
			}

			process.ConsoleSocket = child
			t.postStart = append(t.postStart, parent, child)
			t.consoleC = make(chan error, 1)
			go func() {
				t.consoleC <- t.recvtty(parent)
			}()
		} else {
			conn, err := net.Dial("unix", sockpath)
			if err != nil {
				return nil, err
			}

			uc, ok := conn.(*net.UnixConn)
			if !ok {
				return nil, errors.New("error casting to unix conn")
			}

			t.postStart = append(t.postStart, uc)

			socket, err := uc.File()
			if err != nil {
				return nil, err
			}

			t.postStart = append(t.postStart, socket)
			process.ConsoleSocket = socket
		}

		return t, nil
	}

	if detach {
		inheritStdio(process)
		return &tty{}, nil
	}

	return setupProcessPipes(process, rootuid, rootgid)
}

func createPidFile(path string, process *libcontainer.Process) error {
	pid, err := process.Pid()
	if err != nil {
		return err
	}

	var (
		tmpDir  = filepath.Dir(path)
		tmpName = filepath.Join(tmpDir, "."+filepath.Base(path))
	)

	f, err := os.OpenFile(tmpName, os.O_RDWR|os.O_CREATE|os.O_SYNC|os.O_EXCL, 0o666)
	if err != nil {
		return err
	}

	_, err = f.WriteString(strconv.Itoa(pid))
	f.Close()
	if err != nil {
		return err
	}

	return os.Rename(tmpName, path)
}

func loadfactory(root string) (libcontainer.Factory, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	intelRdtManaget := libcontainer.IntelRdtFs

	newuidmap, err := exec.LookPath("newuidmap")
	if err != nil {
		return nil, err
	}

	newgidmap, err := exec.LookPath("newgidmap")
	if err != nil {
		return nil, err
	}

	return libcontainer.New(
		abs,
		intelRdtManaget,
		libcontainer.NewuidmapPath(newuidmap),
		libcontainer.NewgidmapPath(newgidmap),
	)
}

func createLibContainerRlimit(rlimit specs.POSIXRlimit) (configs.Rlimit, error) {
	lr, err := strToRlimit(rlimit.Type)
	if err != nil {
		return configs.Rlimit{}, err
	}

	return configs.Rlimit{
		Type: lr,
		Hard: rlimit.Hard,
		Soft: rlimit.Soft,
	}, err
}

func parseBoolOrAuto(rootless string) (*bool, error) {
	var b bool

	switch rootless {
	case "1", "t", "T", "True", "true", "TRUE":
		b = true
	case "0", "f", "F", "false", "False", "FALSE":
		b = false
	case "auto":
		return nil, nil
	default:
		return nil, errors.New("invalid input, please provide \"true\", \"false\" or \"auto\"")
	}

	return &b, nil
}

func ShouldUseRootlessCgroups(rootless string, systemdCg bool) (bool, error) {
	if rootless != "" {
		b, err := parseBoolOrAuto(rootless)
		if err != nil {
			return false, err
		}

		if b != nil {
			return *b, nil
		}
	}

	if os.Geteuid() != 0 {
		return true, nil
	}

	if !userns.RunningInUserNS() {
		return false, nil
	}

	if systemdCg {
		ownerUID, err := systemd.DetectUID()
		if err != nil {
			logrus.WithError(err).Debug("failed t get owner UID, assuming the value to be 0")
			ownerUID = 0
		}

		return ownerUID != 0, nil
	}

	return true, nil
}

func ParseSignal(sigstr string) (unix.Signal, error) {
	s, err := strconv.Atoi(sigstr)
	if err == nil {
		return unix.Signal(s), nil
	}

	sig := strings.ToUpper(sigstr)
	if !strings.HasPrefix(sig, "SIG") {
		sig = "SIG" + sig
	}

	signal := unix.SignalNum(sig)
	if signal == 0 {
		return -1, fmt.Errorf("unknown signal: %q", sigstr)
	}

	return signal, nil
}
