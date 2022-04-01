package runcext

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/containerd/go-runc"
	"golang.org/x/sys/unix"
)

func NewSocketPair(name string) (*os.File, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_LOCAL, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}

	return os.NewFile(uintptr(fds[1]), name+"-parent"), os.NewFile(uintptr(fds[0]), name+"-child"), nil
}

// PidFile is used to read pid from file named by --pid-file option.
type PidFile struct {
	path string
}

func NewPidFile(p string) *PidFile {
	return &PidFile{
		path: p,
	}
}

func (p *PidFile) Path() string {
	return p.path
}

func (p *PidFile) Read() (int, error) {
	return runc.ReadPidFile(p.path)
}

// RuntimeCommand is based on github.com/containerd/go-runc@v1.0.0/command_linux.go
func RuntimeCommand(ctx context.Context, r *runc.Runc, args ...string) *exec.Cmd {
	command := r.Command
	if command == "" {
		command = runc.DefaultCommand
	}

	cmd := exec.CommandContext(ctx, command, append(runtimeArgs(r), args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: r.Setpgid,
	}

	// NOTIFY_SOCKET introduces a special behavior in runc but should only be set if invoked from systemd
	cmd.Env = filterEnv(os.Environ(), "NOTIFY_SOCKET")
	if r.PdeathSignal != 0 {
		cmd.SysProcAttr.Pdeathsig = r.PdeathSignal
	}
	return cmd
}

func runtimeArgs(r *runc.Runc) (out []string) {
	if r.Root != "" {
		out = append(out, "--root", r.Root)
	}
	if r.Debug {
		out = append(out, "--debug")
	}
	if r.Log != "" {
		out = append(out, "--log", r.Log)
	}
	if r.LogFormat != "" {
		out = append(out, "--log-format", string(r.LogFormat))
	}
	if r.Criu != "" {
		out = append(out, "--criu", r.Criu)
	}
	if r.SystemdCgroup {
		out = append(out, "--systemd-cgroup")
	}
	if r.Rootless != nil {
		// nil stands for "auto" (differs from explicit "false")
		out = append(out, "--rootless="+strconv.FormatBool(*r.Rootless))
	}
	return out
}

// filterEnv is copied from github.com/containerd/go-runc@v1.0.0/command_linux.go
func filterEnv(in []string, names ...string) []string {
	out := make([]string, 0, len(in))
loop0:
	for _, v := range in {
		for _, k := range names {
			if strings.HasPrefix(v, k+"=") {
				continue loop0
			}
		}
		out = append(out, v)
	}
	return out
}
