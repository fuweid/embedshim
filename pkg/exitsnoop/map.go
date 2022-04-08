package exitsnoop

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// TaskInfo is used to trace the target task.
type TaskInfo struct {
	// TraceID is allocated by userspace to identity the pid of task.
	TraceID uint64
	// PidnsInfo is used to check the pid namespace.
	PidnsInfo PidnsInfo
}

type PidnsInfo struct {
	Dev uint64
	Ino uint64
}

// ExitStatus is used to record the exit event when the target task exits.
type ExitStatus struct {
	Pid           uint32
	ExitCode      int32
	StartBoottime uint64
	ExittedTime   uint64
}

func NewStore(bpffsRoot string) (*Store, error) {
	pinnedPath := filepath.Join(bpffsRoot, pinnedDir)

	tracingTasks, err := loadPinnedMap(filepath.Join(pinnedPath, bpfMapTracingTasks))
	if err != nil {
		return nil, fmt.Errorf("faild to load bpf map %s: %w", bpfMapTracingTasks, err)
	}

	exitedEvents, err := loadPinnedMap(filepath.Join(pinnedPath, bpfMapExitedEvents))
	if err != nil {
		return nil, fmt.Errorf("faild to load bpf map %s: %w", bpfMapExitedEvents, err)
	}

	return &Store{
		tracingTasks: tracingTasks,
		exitedEvents: exitedEvents,
	}, nil
}

// Store is used to trace target task and receive the exited event by trace ID.
type Store struct {
	tracingTasks *ebpf.Map
	exitedEvents *ebpf.Map

	// NOTE: It is only used to prevent the memory-type prog from go runtime
	// GC. For the persisted-type, the field is nil.
	link link.Link
}

func (store *Store) Trace(pid uint32, taskInfo *TaskInfo) error {
	return store.tracingTasks.Update(pid, taskInfo, ebpf.UpdateNoExist)
}

func (store *Store) GetTracingTask(pid uint32) (*TaskInfo, error) {
	info := &TaskInfo{}

	if err := store.tracingTasks.Lookup(pid, info); err != nil {
		return nil, fmt.Errorf("failed to get task with given pid %v: %w", pid, err)
	}
	return info, nil
}

func (store *Store) DeleteTracingTask(pid uint32) error {
	return store.tracingTasks.Delete(pid)
}

func (store *Store) ExitedEventFromWaitStatus(traceEventID uint64, pid uint32, status uint32) error {
	info := ExitStatus{
		Pid:      pid,
		ExitCode: int32(status),
	}

	return store.exitedEvents.Update(traceEventID, &info, ebpf.UpdateNoExist)
}

func (store *Store) GetExitedEvent(traceEventID uint64) (*ExitStatus, error) {
	info := &ExitStatus{}

	if err := store.exitedEvents.Lookup(traceEventID, info); err != nil {
		return nil, fmt.Errorf("failed to get task exited status with given id %v: %w", traceEventID, err)
	}
	return info, nil
}

func (store *Store) DeleteExitedEvent(traceEventID uint64) error {
	return store.exitedEvents.Delete(traceEventID)
}

func (store *Store) Close() error {
	store.tracingTasks.Close()
	store.exitedEvents.Close()
	if store.link != nil {
		store.link.Close()
	}
	return nil
}

func loadPinnedMap(target string) (*ebpf.Map, error) {
	return ebpf.LoadPinnedMap(target, nil)
}
