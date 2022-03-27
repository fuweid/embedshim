#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct pidns_info {
	__u64 dev;
	__u64 ino;
};

struct task_info {
	__u64 trace_id;
	struct pidns_info pidns;
};

struct exit_status {
	__u32 pid;
	int exit_code;
	__u64 start_boottime;
	__u64 exited_time;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, pid_t);
    __type(value, struct task_info);
} tracing_tasks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, __u64);
    __type(value, struct exit_status);
} exited_events SEC(".maps");

SEC("raw_tracepoint/sched_process_exit")
int handle_sched_process_exit(void* ctx) {
    struct task_struct *task;
    struct task_info *rt;
    struct exit_status status;
    struct bpf_pidns_info nsdata;
    struct pidns_info *pidns;
    u64 id;
    pid_t pid, tid;
    int err;

    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    tid = (u32)id;

    if (pid != tid)
        return 0;

    rt = (struct task_info *)bpf_map_lookup_elem(&tracing_tasks, &pid);
    if (!rt) 
        return 0;

    // check pid namespace
    err = bpf_get_ns_current_pid_tgid(
		    rt->pidns.dev,
		    rt->pidns.ino, 
		    &nsdata,
		    sizeof(struct bpf_pidns_info));
    if (err != 0)
	return 0;

    __builtin_memset(&status, 0, sizeof(struct exit_status));
    task = (struct task_struct *)bpf_get_current_task();
    status.pid = pid;
    status.exit_code = BPF_CORE_READ(task, exit_code);
    status.start_boottime = BPF_CORE_READ(task, start_boottime);
    status.exited_time = bpf_ktime_get_ns();
    bpf_map_update_elem(&exited_events, &rt->trace_id, &status, BPF_NOEXIST);
    bpf_map_delete_elem(&tracing_tasks, &pid);
    return 0;
}
