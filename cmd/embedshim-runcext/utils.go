package main

import (
	"path/filepath"

	"github.com/containerd/go-runc"
	"github.com/urfave/cli"
	"golang.org/x/sys/unix"
)

func newRuntime(clicontext *cli.Context) *runc.Runc {
	return &runc.Runc{
		Command:       clicontext.GlobalString("command"),
		Log:           clicontext.GlobalString("log"),
		LogFormat:     runc.Format(clicontext.GlobalString("log-format")),
		PdeathSignal:  unix.SIGKILL,
		Root:          clicontext.GlobalString("root"),
		SystemdCgroup: clicontext.GlobalBool("systemd-cgroup"),
	}
}

func getExecArgs(clicontext *cli.Context, cid string) (out []string, err error) {
	out = append(out, "exec")
	if skt := clicontext.String("console-socket"); skt != "" {
		out = append(out, "--console-socket", skt)
	}
	if detach := clicontext.Bool("detach"); detach {
		out = append(out, "--detach")
	}
	if processJSON := clicontext.String("process"); processJSON != "" {
		abs, err := filepath.Abs(processJSON)
		if err != nil {
			return nil, err
		}
		out = append(out, "--process", abs)
	}
	if pidFilePath := clicontext.String("pid-file"); pidFilePath != "" {
		abs, err := filepath.Abs(pidFilePath)
		if err != nil {
			return nil, err
		}
		out = append(out, "--pid-file", abs)
	}
	out = append(out, cid)
	return out, nil
}
