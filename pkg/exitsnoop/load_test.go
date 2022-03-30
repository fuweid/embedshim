package exitsnoop

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

func TestStoreBasic(t *testing.T) {
	store, err := NewStoreFromAttach()
	if err != nil {
		t.Fatalf("failed to new store from attach: %v", err)
	}
	defer store.Close()

	cmd := exec.Command("sleep", "1d")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start sleep command: %v", err)
	}

	pid := uint32(cmd.Process.Pid)

	nsInfo, err := getPidnsInfo(pid)
	if err != nil {
		t.Fatalf("failed to get pidns info: %v", err)
	}

	traceID := uint64(1)

	if err := store.Trace(pid, &TaskInfo{
		TraceID:   traceID,
		PidnsInfo: nsInfo,
	}); err != nil {
		t.Fatalf("failed to trace: %v", err)
	}

	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("failed to kill sleep: %v", err)
	}

	if err := cmd.Wait(); err == nil {
		t.Fatal("expected error(killed) but got nil")
	}

	event, err := store.GetExitedEvent(traceID)
	if err != nil {
		t.Fatalf("expected no error, but got: %v", err)
	}
	if event.Pid != pid {
		t.Fatalf("expected %v, but got %v", pid, event.Pid)
	}
}

func getPidnsInfo(pid uint32) (PidnsInfo, error) {
	f, err := os.Stat(filepath.Join("/proc", strconv.Itoa(int(pid)), "ns", "pid"))
	if err != nil {
		return PidnsInfo{}, err
	}

	return PidnsInfo{
		Dev: (f.Sys().(*syscall.Stat_t)).Dev,
		Ino: (f.Sys().(*syscall.Stat_t)).Ino,
	}, nil
}
