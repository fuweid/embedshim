package embedshim

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	pkgbundle "github.com/fuweid/embedshim/pkg/bundle"
	"github.com/fuweid/embedshim/pkg/runcext"

	"github.com/containerd/containerd/runtime"
	"github.com/containerd/containerd/runtime/v2/runc/options"
	"github.com/gogo/protobuf/types"
)

var (
	// bundleFileKeyTraceEventID is the filename about bpf trace event ID,
	// which is used to receive the init's exit event from bpf MAP.
	bundleFileKeyTraceEventID = "trace_event_id.binary"

	// bundleFileKeyOCISpec is the filename about OCI spec which used by
	// runC-like command.
	bundleFileKeyOCISpec = "config.json"

	// bundleFileKeyOptions is the filename about runtime or task options
	// which used to get options, like runc-like command name.
	bundleFileKeyOptions = "options.pb"

	// bundleFileKeyStio is the filename about init's stdio settings which
	// used to determine how to reload the init task.
	//
	// NOTE: For the init task running with stdin or terminal, the plugin
	// might kill-9 init when recover.
	bundleFileKeyStio = "stdio.json"

	// bundleInitPidFile name of the file that contains the init pid
	bundleInitPidFile = "init.pid"
)

func newInitPidFile(bundle *pkgbundle.Bundle) *runcext.PidFile {
	return runcext.NewPidFile(filepath.Join(bundle.Path, bundleInitPidFile))
}

func readInitTraceEventID(b *pkgbundle.Bundle) (uint64, error) {
	pathname := filepath.Join(b.Path, bundleFileKeyTraceEventID)

	value, err := os.ReadFile(pathname)
	if err != nil {
		return 0, fmt.Errorf("failed to read %v: %w", pathname, err)
	}
	return binary.LittleEndian.Uint64(value), nil
}

// withBundleApplyInitTraceEventID applies the bpf eventID with little-endian
// binary into bundle.
func withBundleApplyInitTraceEventID(eventID uint64) pkgbundle.ApplyOpts {
	return func(b *pkgbundle.Bundle) error {
		var value [8]byte
		binary.LittleEndian.PutUint64(value[:], eventID)

		pathname := filepath.Join(b.Path, bundleFileKeyTraceEventID)
		if err := os.WriteFile(pathname, value[:], 0666); err != nil {
			return fmt.Errorf("failed to store in %v: %w", pathname, err)
		}
		return nil
	}
}

// withBundleApplyInitOCISpec applies the init OCI spec into bundle.
func withBundleApplyInitOCISpec(spec *types.Any) pkgbundle.ApplyOpts {
	return func(b *pkgbundle.Bundle) error {
		pathname := filepath.Join(b.Path, bundleFileKeyOCISpec)
		if err := os.WriteFile(pathname, spec.Value, 0666); err != nil {
			return fmt.Errorf("failed to store in %v: %w", pathname, err)
		}
		return nil
	}
}

func readInitOptions(b *pkgbundle.Bundle) (*options.Options, error) {
	pathname := filepath.Join(b.Path, bundleFileKeyOptions)

	value, err := os.ReadFile(pathname)
	if err != nil {
		return nil, fmt.Errorf("failed to read %v: %w", pathname, err)
	}

	opt := &options.Options{}
	if err = opt.Unmarshal(value); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pb into options: %w", err)
	}
	return opt, nil
}

// withBundleApplyInitOptions applies the init's options into bundle.
func withBundleApplyInitOptions(opt *options.Options) pkgbundle.ApplyOpts {
	return func(b *pkgbundle.Bundle) error {
		value, err := opt.Marshal()
		if err != nil {
			return fmt.Errorf("failed to marshal %+v into pb: %w", opt, err)
		}

		pathname := filepath.Join(b.Path, bundleFileKeyOptions)
		if err := os.WriteFile(pathname, value, 0666); err != nil {
			return fmt.Errorf("failed to store in %v: %w", pathname, err)
		}
		return nil
	}
}

func readInitStdio(b *pkgbundle.Bundle) (runtime.IO, error) {
	stdio := runtime.IO{}
	pathname := filepath.Join(b.Path, bundleFileKeyStio)

	value, err := os.ReadFile(pathname)
	if err != nil {
		return stdio, fmt.Errorf("failed to read %v: %w", pathname, err)
	}

	if err := json.Unmarshal(value, &stdio); err != nil {
		return stdio, fmt.Errorf("failed to unmarshal json into stdio: %w", err)
	}
	return stdio, nil
}

// withBundleApplyInitStdio applies the init's stdio settings into bundle.
func withBundleApplyInitStdio(stdio runtime.IO) pkgbundle.ApplyOpts {
	return func(b *pkgbundle.Bundle) error {
		value, err := json.Marshal(stdio)
		if err != nil {
			return fmt.Errorf("failed to marshal %+v into json: %w", stdio, err)
		}

		pathname := filepath.Join(b.Path, bundleFileKeyStio)
		if err := os.WriteFile(pathname, value, 0666); err != nil {
			return fmt.Errorf("failed to store in %v: %w", pathname, err)
		}
		return nil
	}
}
