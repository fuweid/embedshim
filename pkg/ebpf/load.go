package ebpf

import (
	"bytes"
	_ "embed"
	"os"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/containerd/containerd/mount"
)

//go:generate cp ../../bpf/.output/monitor.bpf.o pid_monitor.bpf.o
var (
	//go:embed pid_monitor.bpf.o
	progByteCode []byte

	// bpffsMagic is bpf filesystem magic number.
	//
	// https://github.com/torvalds/linux/blob/master/include/uapi/linux/magic.h
	bpffsMagic = int64(0xcafe4a11)

	pinnedDir = ".pid_monitor"

	bpfProgSchedProcessExit = "monitor"
)

func EnsurePidMonitorRunning(bpffsRoot string) error {
	rootDir := filepath.Join(bpffsRoot, pinnedDir)

	if err := ensureBPFFsMount(rootDir); err != nil {
		return err
	}

	_, err := os.Stat(filepath.Join(rootDir, bpfProgSchedProcessExit))
	if err == nil {
		return nil
	}

	if err != nil && !os.IsNotExist(err) {
		return err
	}

	// remove the possible leaky pinned obj
	if err := cleanupLeakyObjs(rootDir); err != nil {
		return err
	}

	if err := os.MkdirAll(rootDir, 0755); err != nil {
		return err
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(progByteCode))
	if err != nil {
		return err
	}

	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return err
	}
	defer func() {
		for _, m := range collection.Maps {
			m.Close()
		}
		for _, p := range collection.Programs {
			p.Close()
		}
	}()

	l, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_exit",
		Program: collection.Programs[bpfProgSchedProcessExit],
	})
	if err != nil {
		return err
	}

	for _, pinnable := range []struct {
		name string
		obj  interface {
			Pin(string) error
		}
	}{
		{bpfMapRunningTasks, collection.Maps[bpfMapRunningTasks]},
		{bpfMapExitedTasks, collection.Maps[bpfMapExitedTasks]},
		{bpfProgSchedProcessExit, l},
	} {
		if err := pinnable.obj.Pin(filepath.Join(rootDir, pinnable.name)); err != nil {
			return err
		}
	}
	return err
}

func ensureBPFFsMount(bpffsRoot string) error {
	if err := os.MkdirAll(bpffsRoot, 0700); err != nil {
		return err
	}

	stat := syscall.Statfs_t{}
	if err := syscall.Statfs(bpffsRoot, &stat); err != nil {
		return err
	}

	switch stat.Type {
	case bpffsMagic:
		return nil
	default:
		opt := mount.Mount{
			Type:   "bpf",
			Source: "bpf",
			Options: []string{
				"rw", "nosuid", "nodev", "noexec", "relatime", "mode=700",
			},
		}
		return mount.All([]mount.Mount{opt}, bpffsRoot)
	}
}

func cleanupLeakyObjs(rootDir string) error {
	for _, name := range []string{
		bpfProgSchedProcessExit,
		bpfMapExitedTasks,
		bpfMapRunningTasks,
	} {
		if err := os.Remove(filepath.Join(rootDir, name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
