package embedshim

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/containerd/containerd/runtime"
	"github.com/containerd/containerd/runtime/v2/runc/options"
	"github.com/gogo/protobuf/types"
)

var (
	// bundleFileKeyEventID is the filename about bpf event ID, which
	// is used to receive the init's exit event from bpf MAP.
	bundleFileKeyEventID = "event_id.binary"

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
)

func (b *bundle) readInitEventID() (uint64, error) {
	pathname := filepath.Join(b.path, bundleFileKeyEventID)

	value, err := os.ReadFile(pathname)
	if err != nil {
		return 0, fmt.Errorf("failed to read event ID from %v: %w", b.path, err)
	}
	return binary.LittleEndian.Uint64(value), nil
}

// withBundleApplyInitEventID applies the bpf eventID with little-endian binary
// into bundle.
func withBundleApplyInitEventID(eventID uint64) bundleApplyOpts {
	return func(b *bundle) error {
		var value [8]byte
		binary.LittleEndian.PutUint64(value[:], eventID)

		pathname := filepath.Join(b.path, bundleFileKeyEventID)
		if err := os.WriteFile(pathname, value[:], 0666); err != nil {
			return fmt.Errorf("failed to store %v in %v: %w", bundleFileKeyEventID, b.path, err)
		}
		return nil
	}
}

// withBundleApplyInitOCISpec applies the init OCI spec into bundle.
func withBundleApplyInitOCISpec(spec *types.Any) bundleApplyOpts {
	return func(b *bundle) error {
		pathname := filepath.Join(b.path, bundleFileKeyOCISpec)
		if err := os.WriteFile(pathname, spec.Value, 0666); err != nil {
			return fmt.Errorf("failed to store %v in %v: %w", bundleFileKeyOCISpec, b.path, err)
		}
		return nil
	}
}

func (b *bundle) readInitOptions() (*options.Options, error) {
	pathname := filepath.Join(b.path, bundleFileKeyOptions)

	value, err := os.ReadFile(pathname)
	if err != nil {
		return nil, fmt.Errorf("failed to read init options from %v: %w", b.path, err)
	}

	opt := &options.Options{}
	if err = opt.Unmarshal(value); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pb into options: %w", err)
	}
	return opt, nil
}

// withBundleApplyInitOptions applies the init's options into bundle.
func withBundleApplyInitOptions(opt *options.Options) bundleApplyOpts {
	return func(b *bundle) error {
		value, err := opt.Marshal()
		if err != nil {
			return fmt.Errorf("failed to marshal %+v into pb: %w", opt, err)
		}

		pathname := filepath.Join(b.path, bundleFileKeyOptions)
		if err := os.WriteFile(pathname, value, 0666); err != nil {
			return fmt.Errorf("failed to store %v in %v: %w", bundleFileKeyOptions, b.path, err)
		}
		return nil
	}
}

func (b *bundle) readInitStdio() (runtime.IO, error) {
	stdio := runtime.IO{}
	pathname := filepath.Join(b.path, bundleFileKeyStio)

	value, err := os.ReadFile(pathname)
	if err != nil {
		return stdio, fmt.Errorf("failed to read init's stdio from %v: %w", b.path, err)
	}

	if err := json.Unmarshal(value, &stdio); err != nil {
		return stdio, fmt.Errorf("failed to unmarshal json into stdio: %w", err)
	}
	return stdio, nil
}

// withBundleApplyInitStdio applies the init's stdio settings into bundle.
func withBundleApplyInitStdio(stdio runtime.IO) bundleApplyOpts {
	return func(b *bundle) error {
		value, err := json.Marshal(stdio)
		if err != nil {
			return fmt.Errorf("failed to marshal %+v into json: %w", stdio, err)
		}

		pathname := filepath.Join(b.path, bundleFileKeyStio)
		if err := os.WriteFile(pathname, value, 0666); err != nil {
			return fmt.Errorf("failed to store %v in %v: %w", bundleFileKeyStio, b.path, err)
		}
		return nil
	}
}
