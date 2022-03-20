package pidfd

import (
	"golang.org/x/sys/unix"
)

type FD int

func Open(pid uint32, flags int) (FD, error) {
	rawFD, err := unix.PidfdOpen(int(pid), flags)
	if err != nil {
		return 0, err
	}
	return FD(rawFD), nil
}

func (fd FD) SendSignal(signal unix.Signal, flags int) error {
	return unix.PidfdSendSignal(int(fd), signal, nil, flags)
}
