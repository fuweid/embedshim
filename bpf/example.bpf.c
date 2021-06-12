#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("iter/task")
int dump_task(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;

	if (task == NULL) {
		return 0;
	}

	BPF_SEQ_PRINTF(seq, "%8d %20d\n",
		task->pid,
		BPF_CORE_READ(task, start_boottime));
        return 0;
}
