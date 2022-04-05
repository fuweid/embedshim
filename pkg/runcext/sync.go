package runcext

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

var EnvNameProcSyncPipe = "_RUNCEXT_PROC_SYNC_PIPE"

// ProcSyncType is used for synchronisation between parent and child process
// during setup containers exec processes.
//
// Since the exec process doesn't like container init which has two-steps
// to setup, we need a wrapper runc-exec commandline to setup pidfd exit event
// monitor like what we does for runc-init.
//
// NOTE: The design is based on runc's syncType from commit[1].
//
// [1] https://github.com/opencontainers/runc/blob/899342b5d49434611635d64f64c343e2a1aeee0a/libcontainer/sync.go
type ProcSyncType string

const (
	ProcSyncError ProcSyncType = "error"

	// [ runc-exec-ext(child)]		     [     parent     ]
	//
	// 	SyncExecPid		-->	           read pid
	//
	//				<--             SyncExecPidDone
	//
	//    SyncExecPidStatus		-->	      exec current status
	//
	//				<--	       SyncExecPidStatusDone
	//
	// NOTE:
	//
	// The commit[1] only supports pidfd type on waitid, not including
	// the non-parent support. We need one extra step to check exec process
	// is still alive. In the future, pidfd_wait[2] API can support waitid
	// by non-parent process.
	//
	// [1] https://github.com/torvalds/linux/commit/3695eae5fee0605f316fbaad0b9e3de791d7dfaf
	// [2] https://lwn.net/Articles/794707/
	ProcSyncExecPid        ProcSyncType = "execPid"
	ProcSyncExecPidDone    ProcSyncType = "execPidDone"
	ProcSyncExecStatus     ProcSyncType = "execStatus"
	ProcSyncExecStatusDone ProcSyncType = "execStatusDone"
)

type ProcSync struct {
	Type         ProcSyncType `json:"type"`
	Pid          uint32       `json:"pid"`
	Exited       bool         `json:"exited"`
	ExitedStatus uint32       `json:"exited_status"`
	Message      string       `json:"message,omitempty"`
}

func NewProcSyncExecPidMessage(pid uint32) ProcSync {
	return ProcSync{
		Type: ProcSyncExecPid,
		Pid:  pid,
	}
}

func NewProcSyncExecPidDoneMessage() ProcSync {
	return ProcSync{
		Type: ProcSyncExecPidDone,
	}
}

func NewProcSyncExecStatusMessage(exited bool, status uint32) ProcSync {
	return ProcSync{
		Type:         ProcSyncExecStatus,
		Exited:       exited,
		ExitedStatus: status,
	}
}

func NewProcSyncExecStatusDoneMessage() ProcSync {
	return ProcSync{
		Type: ProcSyncExecStatusDone,
	}
}

func NewProcSyncErrorMessage(err error) ProcSync {
	return ProcSync{
		Type:    ProcSyncError,
		Message: fmt.Errorf("error: %v", err).Error(),
	}
}

func WriteProcSyncMessage(w io.Writer, msg ProcSync) error {
	return writeJSON(w, msg)
}

func ReadProcSync(r io.Reader, expected ProcSyncType) error {
	var msg ProcSync

	if err := json.NewDecoder(r).Decode(&msg); err != nil {
		return fmt.Errorf("failed reading error during sync: %w", err)
	}

	if msg.Type != expected {
		return fmt.Errorf("expected type %v, but got %+v", expected, msg)
	}
	return nil
}

func ParseProcSync(pipe io.Reader, fn func(*ProcSync) error) error {
	dec := json.NewDecoder(pipe)
	for {
		var msg ProcSync
		if err := dec.Decode(&msg); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}

		if msg.Type == ProcSyncError {
			return fmt.Errorf("unexpected error: %v", msg.Message)
		}

		if err := fn(&msg); err != nil {
			return err
		}
	}
	return nil
}

func writeJSON(w io.Writer, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}
