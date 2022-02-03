package pidfd

import (
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
)

type CallbackFn func() error

type Epoller struct {
	efd       int
	closeOnce sync.Once

	mu  sync.Mutex
	cbs map[FD]CallbackFn
}

func NewEpoller() (*Epoller, error) {
	efd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, err
	}

	return &Epoller{
		efd: efd,
		cbs: make(map[FD]CallbackFn),
	}, nil
}

func (e *Epoller) Add(fd FD, cb CallbackFn) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	ev := unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(fd),
	}

	if err := unix.EpollCtl(e.efd, unix.EPOLL_CTL_ADD, int(fd), &ev); err != nil {
		return fmt.Errorf("failed to epoll_ctl_add: %w", err)
	}
	e.cbs[fd] = cb
	return nil
}

func (e *Epoller) Run() error {
	events := make([]unix.EpollEvent, 128)

	for {
		n, err := unix.EpollWait(e.efd, events, -1)
		if err != nil {
			// EINTR: The call was interrupted by a signal handler before either
			// any of the requested events occurred or the timeout expired
			if err == unix.EINTR {
				continue
			}
			return err
		}

		for i := 0; i < n; i++ {
			ev := events[i]

			e.mu.Lock()
			cbFn := e.cbs[FD(ev.Fd)]
			delete(e.cbs, FD(ev.Fd))
			e.mu.Unlock()

			unix.EpollCtl(e.efd, unix.EPOLL_CTL_DEL, int(ev.Fd), &unix.EpollEvent{})
			unix.Close(int(ev.Fd))
			cbFn()
		}
	}
}

func (e *Epoller) Close() error {
	var err error
	e.closeOnce.Do(func() {
		err = unix.Close(e.efd)
	})
	return err
}
