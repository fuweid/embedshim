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
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"sync"
	"syscall"

	"github.com/containerd/containerd/pkg/stdio"
	"github.com/containerd/fifo"
	"github.com/containerd/go-runc"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

var bufPool = sync.Pool{
	New: func() interface{} {
		// setting to 4096 to align with PIPE_BUF
		// http://man7.org/linux/man-pages/man7/pipe.7.html
		buffer := make([]byte, 4096)
		return &buffer
	},
}

func newPipe() (*pipe, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	return &pipe{
		r: r,
		w: w,
	}, nil
}

type pipe struct {
	r *os.File
	w *os.File
}

func (p *pipe) Close() error {
	err := p.w.Close()
	if rerr := p.r.Close(); err == nil {
		err = rerr
	}
	return err
}

type pipeIO struct {
	in  *pipe
	out *os.File
	err *os.File
}

func (i *pipeIO) Stdin() io.WriteCloser {
	if i.in == nil {
		return nil
	}
	return i.in.w
}

func (i *pipeIO) Stdout() io.ReadCloser {
	if i.out == nil {
		return nil
	}
	return i.out
}

func (i *pipeIO) Stderr() io.ReadCloser {
	if i.err == nil {
		return nil
	}
	return i.err
}

func (i *pipeIO) Close() error {
	var err error
	for _, v := range []io.Closer{
		i.in,
		i.out,
		i.err,
	} {
		if !reflect.ValueOf(v).IsNil() {
			if cerr := v.Close(); err == nil {
				err = cerr
			}
		}
	}
	return err
}

func (i *pipeIO) CloseAfterStart() error {
	for _, f := range []*os.File{
		i.out,
		i.err,
	} {
		if f != nil {
			f.Close()
		}
	}
	return nil
}

// Set sets the io to the exec.Cmd
func (i *pipeIO) Set(cmd *exec.Cmd) {
	if i.in != nil {
		cmd.Stdin = i.in.r
	}
	if i.out != nil {
		cmd.Stdout = i.out
	}
	if i.err != nil {
		cmd.Stderr = i.err
	}
}

type processIO struct {
	io    runc.IO
	stdio stdio.Stdio
}

func (p *processIO) Close() error {
	if p.io != nil {
		return p.io.Close()
	}
	return nil
}

func (p *processIO) IO() runc.IO {
	return p.io
}

func (p *processIO) CopyStdin() error {
	if p.stdio.Stdin == "" {
		return nil
	}

	f, err := fifo.OpenFifo(context.Background(), p.stdio.Stdin, syscall.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("opening %s failed: %w", p.stdio.Stdin, err)
	}

	var cwg sync.WaitGroup
	cwg.Add(1)
	go func() {
		cwg.Done()
		buf := bufPool.Get().(*[]byte)
		defer bufPool.Put(buf)

		io.CopyBuffer(p.io.Stdin(), f, *buf)
		p.io.Stdin().Close()
		f.Close()
	}()
	cwg.Wait()
	return nil
}

func createIO(_ context.Context, _ string, ioUID, ioGID int, stdio stdio.Stdio) (*processIO, error) {
	pio := &processIO{
		stdio: stdio,
	}

	if stdio.IsNull() {
		i, err := runc.NewNullIO()
		if err != nil {
			return nil, err
		}
		pio.io = i
		return pio, nil
	}

	u, err := url.Parse(stdio.Stdout)
	if err != nil {
		return nil, fmt.Errorf("unable to parse stdout uri: %w", err)
	}

	if u.Scheme == "" {
		u.Scheme = "fifo"
	}
	switch u.Scheme {
	case "fifo":
		pio.io, err = newRuncPipeIO(ioUID, ioGID, stdio)
	default:
		return nil, fmt.Errorf("unknown STDIO scheme %s", u.Scheme)
	}
	if err != nil {
		return nil, err
	}
	return pio, nil
}

// newRuncPipeIO creates stdin pipe pairs and RW-mode fifo to be used with runc.
func newRuncPipeIO(uid, gid int, stdio stdio.Stdio) (_ runc.IO, err error) {
	option := defaultIOOption()

	withConditionalIO(stdio)(option)

	var (
		pipes          []io.Closer
		stdin          *pipe
		stdout, stderr *os.File
	)

	// cleanup in case of an error
	defer func() {
		if err != nil {
			for _, p := range pipes {
				p.Close()
			}
		}
	}()

	if option.OpenStdin {
		if stdin, err = newPipe(); err != nil {
			return nil, err
		}

		pipes = append(pipes, stdin)
		if err = unix.Fchown(int(stdin.r.Fd()), uid, gid); err != nil {
			return nil, errors.Wrap(err, "failed to chown stdin")
		}
	}

	if option.OpenStdout {
		stdout, err = openRWFifo(context.TODO(), stdio.Stdout, 0700)
		if err != nil {
			return nil, err
		}

		pipes = append(pipes, stdout)
		if err = unix.Fchown(int(stdout.Fd()), uid, gid); err != nil {
			return nil, errors.Wrap(err, "failed to chown stdout")
		}
	}

	if option.OpenStderr {
		stderr, err = openRWFifo(context.TODO(), stdio.Stderr, 0700)
		if err != nil {
			return nil, err
		}

		pipes = append(pipes, stderr)
		if err = unix.Fchown(int(stderr.Fd()), uid, gid); err != nil {
			return nil, errors.Wrap(err, "failed to chown stderr")
		}
	}

	return &pipeIO{
		in:  stdin,
		out: stdout,
		err: stderr,
	}, nil
}

func defaultIOOption() *runc.IOOption {
	return &runc.IOOption{
		OpenStdin:  true,
		OpenStdout: true,
		OpenStderr: true,
	}
}

func withConditionalIO(c stdio.Stdio) runc.IOOpt {
	return func(o *runc.IOOption) {
		o.OpenStdin = c.Stdin != ""
		o.OpenStdout = c.Stdout != ""
		o.OpenStderr = c.Stderr != ""
	}
}

func openRWFifo(_ context.Context, fn string, perm os.FileMode) (*os.File, error) {
	if _, err := os.Stat(fn); err != nil {
		if os.IsNotExist(err) {
			if err := syscall.Mkfifo(fn, uint32(perm&os.ModePerm)); err != nil && !os.IsExist(err) {
				return nil, fmt.Errorf("error creating fifo %v: %w", fn, err)
			}
		} else {
			return nil, err
		}
	}
	return os.OpenFile(fn, syscall.O_RDWR, perm)
}
