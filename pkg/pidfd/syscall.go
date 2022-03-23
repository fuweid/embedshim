package pidfd

import (
	"golang.org/x/sys/unix"
)

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
