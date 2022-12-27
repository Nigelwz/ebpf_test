// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Sartura
 * Based on minimal.c by Facebook */
#include <stdio.h>
//#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "bpf_h_file/sys_sensor.skel.h"
#include <stdint.h>
#include <iostream>
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

//#include "vmlinux_test.h"
//#include "missing_definitions.h""

//#include "vmlinux.h"
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
	stop = 1;
}
void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

#define TASK_COMM_LEN 16
typedef struct task_context {
    u64 start_time; // 8
    u32 pid; // 4
    u32 tid; //4
    u32 ppid; // 4
    u32 sid; // 4
    // TODO namespace
    u32 host_pid; // 4
    u32 host_tid; // 4
    u32 host_ppid; // 4
    /***************/ 
    u32 uid; // 4
    u32 mnt_id; // 4
    u32 pid_id; // 4
    char comm[TASK_COMM_LEN]; //16
    char uts_name[TASK_COMM_LEN];//16
    u32 flags; // 4
//char proc_name[32];
} task_context_t;

typedef struct  event_context {
    u64 ts; // 8
    task_context_t task; // 84
    u32 eventid;//4
 //   u32 padding;//4
    u64 retval; //8
    u32 stack_id;//4
    u16 processor_id; // 2
    u8 argnum; //1
//	u32 ts2; // 8
//   u8 padding;
} event_context_t;

typedef struct args {
	unsigned long args[6];
} args_t;
typedef struct syscall_data {
	unsigned int id;
	args_t args;
	unsigned long ts;
	unsigned long ret;
} syscall_data_t;


typedef struct task_info {
    event_context_t context;
    syscall_data_t syscall_data;
    bool syscall_traced;
    bool recompute_scope;
    bool new_task;
    bool follow;
    int should_trace;
} task_info_t;
void handle_event(void *ctx,int cpu, void *data, unsigned int data_sz)
{

}
int main(int argc, char **argv)
{
	struct perf_buffer *pb = NULL;
	int err;
	std::cout << "jj" << std::endl;
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);
	/* Open load and verify BPF application */
	struct sys_sensor_bpf*   skel = sys_sensor_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}
	/* Attach tracepoint handler */
	struct bpf_link* linkk = bpf_program__attach( skel->progs.tracepoint__raw_syscalls__sys_enter );
	//err = kprobe_bpf__attach(skel);
	if (!linkk) {
		fprintf(stderr, "failed attached");
	}
	struct bpf_link* link = bpf_program__attach(skel->progs.do_exec_binprm);
	//struct bpf_link* link = bpf_program__attach( skel->progs.tracepoint__raw_syscalls__sys_enter );
	if (!link) {
		fprintf(stderr, "failed attached");
	}
	
	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}
	//pb_opts.sample_cb = handle_event;
	pb = perf_buffer__new(bpf_map__fd(skel->maps.events), (1<<15),handle_event, NULL,NULL, NULL);
	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");
	while (!stop) {
		err = perf_buffer__poll(pb, 100);
		if (err < 0 && err != -EINTR) {
			goto cleanup;
		}
		
	}
cleanup:
	perf_buffer__free(pb);
 sys_sensor_bpf__destroy(skel);
	return -err;
}
