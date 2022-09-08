// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"
//#include <linux/bpf.h>
char LICENSE[] SEC("license") = "Dual BSD/GPL";

//#define PATH_LEN 512
//struct event {
//	int pid;
//	char path_name[PATH_LEN];
//};

/* BPF ringbuf map */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct event);
} heap SEC(".maps");

#if 0
SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
	pid_t pid;
	const char *filename;

	pid = bpf_get_current_pid_tgid() >> 32;
	filename = BPF_CORE_READ(name, name);
	bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
	return 0;
}

SEC("kprobe/do_open_dir")
int BPF_KPROBE(do_open_dir, int dfd, struct filename *name)
{
	pid_t pid;
	const char *filename;

	pid = bpf_get_current_pid_tgid() >> 32;
	filename = BPF_CORE_READ(name, name);
	bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
	bpf_printk("hello\n");
	return 0;
}
#endif
SEC("kprobe/do_sys_openat2")
int trace_open(struct pt_regs *ctx) {
	const int dirfd = PT_REGS_PARM1(ctx);
	char *pathname = (char *)PT_REGS_PARM2(ctx);
	struct event *e;
	int zero = 0;
	e = bpf_map_lookup_elem(&heap, &zero);
	if (!e) {
		bpf_printk ( "bpf map fail\n");
		//bpf_trace_printk("bpf map fail\n");
		return 0;
	}
	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_probe_read_str(&e->path_name, sizeof (e->path_name), pathname);
	bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
	char fmt[] = "@dirfd='%d' @pathname='%s'";
	//if (__builtin_memcmp(pathname, "/home/nigel/Music", 17) == 0)
	bpf_trace_printk(fmt, sizeof(fmt), dirfd, pathname);

	return 0;
}


#if 0
SEC("kretprobe/do_unlinkat")
int BPF_KRETPROBE(do_unlinkat_exit, long ret)
{
	pid_t pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("KPROBE EXIT: pid = %d, ret = %ld\n", pid, ret);
	return 0;
}
#endif
