/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package embedshim

import (
	"context"
	"fmt"
	"io"
	"sync"
	"syscall"

	"github.com/containerd/console"
	"github.com/containerd/containerd/pkg/stdio"
	"github.com/containerd/fifo"
)

// NewPlatform returns a linux platform for use with I/O operations
func NewPlatform() (stdio.Platform, error) {
	epoller, err := console.NewEpoller()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize epoller: %w", err)
	}

	go epoller.Wait()
	return &linuxPlatform{
		epoller: epoller,
	}, nil
}

type linuxPlatform struct {
	epoller *console.Epoller
}

func (p *linuxPlatform) CopyConsole(ctx context.Context, console console.Console, _, stdin, stdout, _ string, wg *sync.WaitGroup) (cons console.Console, retErr error) {
	if p.epoller == nil {
		return nil, fmt.Errorf("uninitialized epoller")
	}

	epollConsole, err := p.epoller.Add(console)
	if err != nil {
		return nil, err
	}

	var cwg sync.WaitGroup
	if stdin != "" {
		in, err := fifo.OpenFifo(context.Background(), stdin, syscall.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, err
		}

		cwg.Add(1)
		go func() {
			cwg.Done()
			bp := bufPool.Get().(*[]byte)
			defer bufPool.Put(bp)
			io.CopyBuffer(epollConsole, in, *bp)
			// we need to shutdown epollConsole when pipe broken
			epollConsole.Shutdown(p.epoller.CloseConsole)
			epollConsole.Close()
		}()
	}

	out, err := fifo.OpenFifo(ctx, stdout, syscall.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	wg.Add(1)
	cwg.Add(1)
	go func() {
		cwg.Done()
		buf := bufPool.Get().(*[]byte)
		defer bufPool.Put(buf)
		io.CopyBuffer(out, epollConsole, *buf)

		out.Close()
		wg.Done()
	}()
	cwg.Wait()

	return epollConsole, nil
}

func (p *linuxPlatform) ShutdownConsole(_ context.Context, cons console.Console) error {
	if p.epoller == nil {
		return fmt.Errorf("uninitialized epoller")
	}
	epollConsole, ok := cons.(*console.EpollConsole)
	if !ok {
		return fmt.Errorf("expected EpollConsole, got %#v", cons)
	}
	return epollConsole.Shutdown(p.epoller.CloseConsole)
}

func (p *linuxPlatform) Close() error {
	return p.epoller.Close()
}
