package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/fuweid/embedshim/pkg/pidfd"
	"github.com/fuweid/embedshim/pkg/runcext"
	"github.com/urfave/cli"
	"golang.org/x/sys/unix"
)

// execCommand is based on https://github.com/opencontainers/runc/blob/899342b5d49434611635d64f64c343e2a1aeee0a/exec.go.
var execCommand = cli.Command{
	Name:  "exec",
	Usage: "execute new process inside the container",
	ArgsUsage: `<container-id> <command> [command options]  || -p process.json <container-id>

Where "<container-id>" is the name for the instance of the container and
"<command>" is the command to be executed in the container.
"<command>" can't be empty unless a "-p" flag provided.

EXAMPLE:
For example, if the container is configured to run the linux ps command the
following will output a list of processes running in the container:

       # runc exec <container-id> ps`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "console-socket",
			Usage: "path to an AF_UNIX socket which will receive a file descriptor referencing the master end of the console's pseudoterminal",
		},
		cli.StringFlag{
			Name:  "cwd",
			Usage: "current working directory in the container",
		},
		cli.StringSliceFlag{
			Name:  "env, e",
			Usage: "set environment variables",
		},
		cli.BoolFlag{
			Name:  "tty, t",
			Usage: "allocate a pseudo-TTY",
		},
		cli.StringFlag{
			Name:  "user, u",
			Usage: "UID (format: <uid>[:<gid>])",
		},
		cli.Int64SliceFlag{
			Name:  "additional-gids, g",
			Usage: "additional gids",
		},
		cli.StringFlag{
			Name:  "process, p",
			Usage: "path to the process.json",
		},
		cli.BoolFlag{
			Name:  "detach,d",
			Usage: "detach from the container's process",
		},
		cli.StringFlag{
			Name:  "pid-file",
			Value: "",
			Usage: "specify the file to write the process id to",
		},
		cli.StringFlag{
			Name:  "process-label",
			Usage: "set the asm process label for the process commonly used with selinux",
		},
		cli.StringFlag{
			Name:  "apparmor",
			Usage: "set the apparmor profile for the process",
		},
		cli.BoolFlag{
			Name:  "no-new-privs",
			Usage: "set the no new privileges value for the process",
		},
		cli.StringSliceFlag{
			Name:  "cap, c",
			Value: &cli.StringSlice{},
			Usage: "add a capability to the bounding set for the process",
		},
		cli.IntFlag{
			Name:  "preserve-fds",
			Usage: "Pass N additional file descriptors to the container (stdio + $LISTEN_FDS + N in total)",
		},
		cli.StringSliceFlag{
			Name:  "cgroup",
			Usage: "run the process in an (existing) sub-cgroup(s). Format is [<controller>:]<cgroup>.",
		},
		cli.BoolFlag{
			Name:  "ignore-paused",
			Usage: "allow exec in a paused container",
		},
	},
	Action: func(clicontext *cli.Context) error {
		return runExec(clicontext)
	},
	SkipArgReorder: true,
}

func runExec(clicontext *cli.Context) (retErr error) {
	ctx := context.Background()
	cid := clicontext.Args().First()

	execPidfile, err := getExecPidFilePath(clicontext)
	if err != nil {
		return err
	}

	syncPipe, err := getProcSyncPipe()
	if err != nil {
		return err
	}

	deferCloseSyncPipe := true
	defer func() {
		if retErr != nil && deferCloseSyncPipe {
			syncPipe.Close()
			deferCloseSyncPipe = false
		}
	}()

	runErr := func() (retErr error) {
		r := newRuntime(clicontext)

		execArgs, err := getExecArgs(clicontext, cid)
		if err != nil {
			return fmt.Errorf("failed to get exec arguments: %w", err)
		}

		execCmd := runcext.RuntimeCommand(ctx, r, execArgs...)

		// NOTE: Just by-pass the standard IO
		execCmd.Stdin = os.Stdin
		execCmd.Stdout = os.Stdout
		execCmd.Stderr = os.Stderr

		if err := execCmd.Run(); err != nil {
			return fmt.Errorf("failed to run: %w", err)
		}

		execPid, err := execPidfile.Read()
		if err != nil {
			return fmt.Errorf("failed to read exec pid from file: %w", err)
		}
		defer func() {
			if retErr != nil {
				unix.Kill(execPid, unix.SIGKILL)
			}
		}()

		pidFD, err := pidfd.Open(uint32(execPid), 0)
		if err != nil {
			return fmt.Errorf("failed to open pidfd on exec process: %w", err)
		}

		if err := syncParentExecPid(syncPipe, uint32(execPid)); err != nil {
			return err
		}

		if err := syncParentExecStatus(syncPipe, pidFD, execPid); err != nil {
			return err
		}

		syncPipe.Close()
		deferCloseSyncPipe = false
		return nil
	}()
	if runErr != nil {
		return runcext.WriteProcSyncMessage(syncPipe, runcext.NewProcSyncErrorMessage(runErr))
	}
	return nil
}

func syncParentExecPid(syncPipe *os.File, execPid uint32) error {
	msg := runcext.NewProcSyncExecPidMessage(execPid)

	if err := runcext.WriteProcSyncMessage(syncPipe, msg); err != nil {
		return fmt.Errorf("failed to sync %v: %w", msg, err)
	}

	return runcext.ReadProcSync(syncPipe, runcext.ProcSyncExecPidDone)
}

func syncParentExecStatus(syncPipe *os.File, fd pidfd.FD, execPid int) error {
	info := &pidfd.Siginfo{}

	err := fd.Waitid(info, unix.WNOHANG|unix.WNOWAIT|unix.WEXITED, nil)
	if err != nil {
		return fmt.Errorf("failed to check exec process status: %w", err)
	}

	exited := false
	exitedStatus := uint32(0)

	if info.Pid != 0 {
		var status unix.WaitStatus

		for {
			_, err = unix.Wait4(execPid, &status, 0, nil)
			if err != syscall.EINTR {
				break
			}
		}
		if err != nil {
			return fmt.Errorf("failed to reap the exit process status: %w", err)
		}

		exited = true
		exitedStatus = uint32(status)
	}

	msg := runcext.NewProcSyncExecStatusMessage(exited, exitedStatus)
	if err := runcext.WriteProcSyncMessage(syncPipe, msg); err != nil {
		return fmt.Errorf("failed to sync %v: %w", msg, err)
	}

	return runcext.ReadProcSync(syncPipe, runcext.ProcSyncExecStatusDone)
}

func getProcSyncPipe() (*os.File, error) {
	key := runcext.EnvNameProcSyncPipe

	pipeFD, err := strconv.Atoi(os.Getenv(key))
	if err != nil {
		return nil, fmt.Errorf("failed to get env %v: %w", key, err)
	}
	return os.NewFile(uintptr(pipeFD), key), nil
}

func getExecPidFilePath(clicontext *cli.Context) (*runcext.PidFile, error) {
	pidFilePath := clicontext.String("pid-file")
	if pidFilePath == "" {
		return nil, fmt.Errorf("pid-file is required")
	}

	abs, err := filepath.Abs(pidFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for --pid-file: %w", err)
	}
	return runcext.NewPidFile(abs), nil
}
