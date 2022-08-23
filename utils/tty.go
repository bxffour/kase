package utils

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"

	"github.com/containerd/console"
	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/utils"
)

type tty struct {
	epoller     *console.Epoller
	console     *console.EpollConsole
	hostConsole console.Console
	postStart   []io.Closer
	closers     []io.Closer
	wg          sync.WaitGroup
	consoleC    chan error
}

func (t *tty) copyIO(w io.Writer, r io.ReadCloser) {
	defer t.wg.Done()
	_, _ = io.Copy(w, r)
	_ = r.Close()
}

func setupProcessPipes(p *libcontainer.Process, rootuid, rootgid int) (*tty, error) {
	i, err := p.InitializeIO(rootuid, rootuid)
	if err != nil {
		return nil, err
	}

	t := &tty{
		closers: []io.Closer{
			i.Stdin,
			i.Stdout,
			i.Stderr,
		},
	}

	processIO := []interface{}{
		p.Stdin,
		p.Stdout,
		p.Stderr,
	}

	for _, cc := range processIO {
		if c, ok := cc.(io.Closer); ok {
			t.postStart = append(t.postStart, c)
		}
	}

	go func() {
		_, _ = io.Copy(i.Stdin, os.Stdin)
		_ = i.Stdin.Close()
	}()

	t.wg.Add(2)

	go t.copyIO(os.Stdout, i.Stdout)
	go t.copyIO(os.Stderr, i.Stderr)

	return t, err
}

func inheritStdio(p *libcontainer.Process) {
	p.Stdin = os.Stdin
	p.Stdout = os.Stdout
	p.Stderr = os.Stderr
}

func (t *tty) initHostConsole() error {
	hostStdio := []*os.File{os.Stdin, os.Stdout, os.Stderr}

	for _, s := range hostStdio {
		c, err := console.ConsoleFromFile(s)
		if err == nil {
			t.hostConsole = c
			return nil
		}

		if errors.Is(err, console.ErrNotAConsole) {
			continue
		}

		return fmt.Errorf("unable to return a console: %w", err)
	}

	tty, err := os.Open("/dev/tty")
	if err != nil {
		return err
	}

	c, err := console.ConsoleFromFile(tty)
	if err != nil {
		return fmt.Errorf("unable to return a console: %w", err)
	}

	t.hostConsole = c
	return nil
}

func (t *tty) recvtty(socket *os.File) (Err error) {
	f, err := utils.RecvFd(socket)
	if err != nil {
		return err
	}

	cons, err := console.ConsoleFromFile(f)
	if err != nil {
		return err
	}

	err = console.ClearONLCR(cons.Fd())
	if err != nil {
		return err
	}

	epoller, err := console.NewEpoller()
	if err != nil {
		return err
	}

	epollConsole, err := epoller.Add(cons)
	if err != nil {
		return err
	}

	defer func() {
		if Err != nil {
			_ = epollConsole.Console
		}
	}()

	go func() { _ = epoller.Wait() }()
	go func() { _, _ = io.Copy(epollConsole, os.Stdin) }()

	t.wg.Add(1)
	go t.copyIO(os.Stdout, epollConsole)

	if err := t.hostConsole.SetRaw(); err != nil {
		return fmt.Errorf("unable to set terminal from the stdin: %w", err)
	}

	go handleInterrupt(t.hostConsole)

	t.epoller = epoller
	t.console = epollConsole
	t.closers = []io.Closer{epollConsole}
	return nil
}

func handleInterrupt(c console.Console) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	<-sigChan
	_ = c.Reset()
	os.Exit(0)
}

func (t *tty) waitConsole() error {
	if t.consoleC != nil {
		return <-t.consoleC
	}
	return nil
}

func (t *tty) closePostStart() {
	for _, c := range t.postStart {
		_ = c.Close()
	}
}

func (t *tty) close() {
	t.closePostStart()

	if t.console != nil && t.epoller != nil {
		_ = t.console.Shutdown(t.epoller.CloseConsole)
	}

	t.wg.Wait()

	for _, c := range t.closers {
		_ = c.Close()
	}

	if t.hostConsole != nil {
		_ = t.hostConsole.Reset()
	}
}

func (t *tty) resize() error {
	if t.hostConsole == nil || t.console == nil {
		return nil
	}

	return t.console.ResizeFrom(t.hostConsole)
}
