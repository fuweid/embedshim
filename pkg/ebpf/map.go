package ebpf

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
)

var (
	DefaultBPFFs = "/sys/fs/bpf"

	bpfMapRunningTasks = "running_tasks"
	bpfMapExitedTasks  = "exited_tasks"
)

// TaskInfo is the value of running_tasks bpf map.
type TaskInfo struct {
	ID        uint64
	PidnsInfo PidnsInfo
}

type PidnsInfo struct {
	Dev uint64
	Ino uint64
}

// TaskExitStatus is the value of exited_tasks bpf map.
type TaskExitStatus struct {
	Pid           uint32
	ExitCode      int32
	StartBoottime uint64
	ExittedTime   uint64
}

func NewSchedProcessExitStore(pinnedPath string) (*SchedProcessExitStore, error) {
	runningTasks, err := loadPinnedMap(filepath.Join(pinnedPath, bpfMapRunningTasks))
	if err != nil {
		return nil, fmt.Errorf("faild to load bpf map %s: %w", bpfMapRunningTasks, err)
	}

	exitedTasks, err := loadPinnedMap(filepath.Join(pinnedPath, bpfMapExitedTasks))
	if err != nil {
		return nil, fmt.Errorf("faild to load bpf map %s: %w", bpfMapExitedTasks, err)
	}

	return &SchedProcessExitStore{
		runningTasks: runningTasks,
		exitedTasks:  exitedTasks,
	}, nil
}

type SchedProcessExitStore struct {
	runningTasks *ebpf.Map
	exitedTasks  *ebpf.Map
}

func (store *SchedProcessExitStore) InsertRunningTask(pid uint32, taskInfo *TaskInfo) error {
	return store.runningTasks.Update(pid, taskInfo, ebpf.UpdateNoExist)
}

func (store *SchedProcessExitStore) GetRunningTask(pid uint32) (*TaskInfo, error) {
	info := &TaskInfo{}

	if err := store.runningTasks.Lookup(pid, info); err != nil {
		return nil, fmt.Errorf("failed to get task with given pid %v: %w", pid, err)
	}
	return info, nil
}

func (store *SchedProcessExitStore) DelRunningTask(pid uint32) error {
	return store.runningTasks.Delete(pid)
}

func (store *SchedProcessExitStore) GetExitedTask(id uint64) (*TaskExitStatus, error) {
	info := &TaskExitStatus{}

	if err := store.exitedTasks.Lookup(id, info); err != nil {
		return nil, fmt.Errorf("failed to get task exited status with given id %v: %w", id, err)
	}
	return info, nil
}

func (store *SchedProcessExitStore) DelExitedTask(id uint64) error {
	return store.exitedTasks.Delete(id)
}

func (store *SchedProcessExitStore) Close() error {
	store.runningTasks.Close()
	store.exitedTasks.Close()
	return nil
}

func loadPinnedMap(target string) (*ebpf.Map, error) {
	return ebpf.LoadPinnedMap(target, nil)
}
