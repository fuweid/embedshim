package pidfd

import (
	"syscall"
)

const (
	sysPidfdOpen       = 434
	sysPidfdSendSignal = 438
)

type FD int

func Open(pid uint32, flags int) (FD, error) {
	rawFD, _, errno := syscall.RawSyscall(sysPidfdOpen, uintptr(pid), uintptr(flags), 0)
	if errno != 0 {
		return 0, errno
	}
	return FD(rawFD), nil
}

func (fd FD) SendSignal(signal syscall.Signal, flags int) error {
	_, _, errno := syscall.Syscall6(sysPidfdSendSignal, uintptr(fd), uintptr(signal), 0, uintptr(flags), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
