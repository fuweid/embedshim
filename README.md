# embedshim

The embedshim is the kind of task runtime implementation, which can be used as
plugin in containerd.

With current shim design, it is used to manage the lifecycle of container
process and allow to be reconnected after containerd restart. The one of the
key design elements of a small shim is to be a container process monitoring,
at least it is important to containerd created by runC-like runtime.

Without pidfd and ebpf trace point feature, it is unlikely to receive exit
notification in time and receive exit code correctly as non-parents after shim
dies. And in kubernetes infra, even if the containers in pod can share one
shim, the VmRSS of shim(Go Runtime) is still about 8MB.

So, this plugin aims to provide task runtime implementation with pidfd and
eBPF sched_process_exit tracepoint to manage deamonless container with
low overhead.

![embedshim-overview](docs/images/embedshim-overview.svg)

## Demos(TODO)

## TODO-List

* [ ] Handle Stdin/Terminal
* [ ] Support Exec/Pause/Resume
* [ ] Metrics Support
* [ ] Event support
