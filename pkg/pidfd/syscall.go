package pidfd

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// PPIDFD is the first argument to waitid for pidfd.
const PPIDFD int = 3

// Siginfo extends the unix.Siginfo with Pid, which used to check the process
// state.
//
// From https://man7.org/linux/man-pages/man2/waitid.2.html:
//
// If WNOHANG was specified in options and there were no children in a waitable
// state, then waitid() returns 0 immediately and the state of the siginfo_t
// structure pointed to by infop depends on the implementation. To (portably)
// distinguish this case from that where a child was in a waitable state, zero
// out the si_pid field before the call and check for a nonzero value in this
// field after the call returns.
type Siginfo struct {
	Signo int32
	Errno int32
	Code  int32
	_     int32
	Pid   uint32
	_     [108]byte
}

type Rusage = unix.Rusage

type FD int

// Open creates a file descriptor that refers to the process whose PID is
// specified in pid. The file descriptor is returned as the function result;
// the close-on-exec flag is set on the file descriptor.
//
// https://man7.org/linux/man-pages/man2/pidfd_open.2.html
func Open(pid uint32, flags int) (FD, error) {
	rawFD, err := unix.PidfdOpen(int(pid), flags)
	if err != nil {
		return 0, err
	}
	return FD(rawFD), nil
}

// SendSignal sends a signal to a process specified by a file descriptor.
//
// The flags argument is reserved for future use; currently, this argument must
// be specified as 0.
func (fd FD) SendSignal(signal unix.Signal, flags int) error {
	// From https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html.
	//
	// If the info argument is a NULL pointer, this is equivalent to
	// specifying a pointer to a siginfo_t buffer whose fields match the
	// values that are implicitly supplied when a signal is sent using
	// kill(2).
	return unix.PidfdSendSignal(int(fd), signal, nil, flags)
}

// Waitid provides more precise control over which child state changes to wait for.
func (fd FD) Waitid(info *Siginfo, options int, rusage *Rusage) error {
	_, _, e1 := unix.Syscall6(unix.SYS_WAITID,
		uintptr(PPIDFD),
		uintptr(fd),
		uintptr(unsafe.Pointer(info)),
		uintptr(options),
		uintptr(unsafe.Pointer(rusage)), 0)
	if e1 != 0 {
		return e1
	}
	return nil
}
