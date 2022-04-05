package main

import (
	"os"

	"github.com/containerd/containerd/pkg/userns"
	"github.com/containerd/containerd/sys/reaper"
	"github.com/urfave/cli"
)

// newApp is based on https://github.com/opencontainers/runc/blob/899342b5d49434611635d64f64c343e2a1aeee0a/main.go.
//
// NOTE: newApp only extends functionality about runc-exec command.
func newApp() *cli.App {
	app := cli.NewApp()
	app.Name = "runcext"
	app.EnableBashCompletion = true
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "command",
			Usage: "set the command as runtime",
			Value: "runc",
		},
		cli.BoolFlag{
			Name:  "debug",
			Usage: "enable debug logging",
		},
		cli.StringFlag{
			Name:  "log",
			Value: "",
			Usage: "set the log file to write runc logs to (default is '/dev/stderr')",
		},
		cli.StringFlag{
			Name:  "log-format",
			Value: "text",
			Usage: "set the log format ('text' (default), or 'json')",
		},
		cli.StringFlag{
			Name:  "root",
			Value: defaultRuncRoot(),
			Usage: "root directory for storage of container state (this should be located in tmpfs)",
		},
		cli.BoolFlag{
			Name:  "systemd-cgroup",
			Usage: "enable systemd cgroup support, expects cgroupsPath to be of form \"slice:prefix:name\" for e.g. \"system.slice:runc:434234\"",
		},
		cli.StringFlag{
			Name:  "rootless",
			Value: "auto",
			Usage: "ignore cgroup permission errors ('true', 'false', or 'auto')",
		},
	}
	app.Commands = append(app.Commands, execCommand)
	app.Before = func(_ *cli.Context) error {
		if err := reaper.SetSubreaper(1); err != nil {
			return err
		}
		return nil
	}
	return app
}

func defaultRuncRoot() string {
	root := "/run/runc"
	if shouldHonorXDGRuntimeDir() {
		if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
			root = runtimeDir + "/runc"
		}
	}
	return root
}

// shouldHonorXDGRuntimeDir is copied from https://github.com/opencontainers/runc/blob/899342b5d49434611635d64f64c343e2a1aeee0a/rootless_linux.go#L54.
func shouldHonorXDGRuntimeDir() bool {
	if os.Geteuid() != 0 {
		return true
	}
	if !userns.RunningInUserNS() {
		// euid == 0 , in the initial ns (i.e. the real root)
		// in this case, we should use /run/runc and ignore
		// $XDG_RUNTIME_DIR (e.g. /run/user/0) for backward
		// compatibility.
		return false
	}
	// euid = 0, in a userns.
	u, ok := os.LookupEnv("USER")
	return !ok || u != "root"
}
