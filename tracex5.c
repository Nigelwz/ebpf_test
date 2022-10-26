// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include "tracex5.skel.h"
//#include <tracex5.skel.h>
//#include "trace_helpers.h"
//#include "bpf_util.h"

#ifdef __mips__
#define	MAX_ENTRIES  6000 /* MIPS n64 syscalls start at 5000 */
#else
#define	MAX_ENTRIES  1024
#endif

enum {
	SYS__NR_read = 3,
	SYS__NR_write = 4,
	SYS__NR_open = 5,
};
 
struct bpf_progs_desc {
	char name[256];
	enum bpf_prog_type type;
	int map_prog_idx;
	struct bpf_program *prog;
	char func_name[256];
};
 static struct bpf_progs_desc progs[] = {
	{"kprobe/__seccomp_filter", BPF_PROG_TYPE_KPROBE, -1, NULL, "__seccomp_filter"},
	{"kprobe/SYS__NR_read", BPF_PROG_TYPE_KPROBE, SYS__NR_read, NULL, "bpf_func_SYS__NR_write"},
	{"kprobe/SYS__NR_write", BPF_PROG_TYPE_KPROBE, SYS__NR_write, NULL, "bpf_func_SYS__NR_read"},
	{"kprobe/SYS__NR_open", BPF_PROG_TYPE_KPROBE, SYS__NR_open, NULL, "bpf_func_SYS__NR_open"},
 };
 
 static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
 {
	return vfprintf(stderr, format, args);
 }
 
 static volatile bool exiting = false;
 
 static void sig_handler(int sig)
 {
	exiting = true;
 }
 
 int main(int argc, char **argv)
 {
	struct tracex5_bpf *skel;
	//int map_progs_fd, main_prog_fd, prog_count;
	int map_progs_fd, prog_count;

	int err;
 
 // 設置一些debug信息的回調
	libbpf_set_print(libbpf_print_fn);
 
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
 
 // Load and verify BPF application
	skel = tracex5_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
	return 1;
	}
 
 // Load and verify BPF programs
	err = tracex5_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}
 
	map_progs_fd = bpf_object__find_map_fd_by_name(skel->obj, "progs");
	const char* section;	
	struct bpf_program *prog;
	int key = 0;
	int fd = 0;
	
	bpf_object__for_each_program(prog, skel->obj) {
		section = bpf_program__section_name(prog);
		if (sscanf(section, "kprobe/%d",&key) != 1)
			continue;
		fd = bpf_program__fd(prog);
		//printf("fd = %d\n", fd);
		bpf_map_update_elem(map_progs_fd, &key, &fd, BPF_ANY);
	}

#if 0
	prog_count = sizeof(progs) / sizeof(progs[0]);
	for (int i = 0; i < prog_count; i++) {
		//progs[i].prog = bpf_object__find_program_by_name(skel->obj, progs[i].name);
		
		//progs[i].prog = bpf_object__find_program_by_name(skel->obj, progs[i].name);
		progs[i].prog = bpf_object__find_program_by_name(skel->obj, progs[i].func_name);

		if (!progs[i].prog) {
			fprintf(stderr, "Error: bpf_object__find_program_by_titleeee failed\n");
			return 1;
		}
		bpf_program__set_type(progs[i].prog, progs[i].type);
	}
 
	for (int i = 0; i < prog_count; i++) {
		int prog_fd = bpf_program__fd(progs[i].prog);
		if (prog_fd < 0) {
			fprintf(stderr, "Error: Couldn't get file descriptor for program %s\n", progs[i].name);
			return 1;
		}
         
         // -1指的是主程序
		if (progs[i].map_prog_idx != -1) {
			unsigned int map_prog_idx = progs[i].map_prog_idx;
			if (map_prog_idx < 0) {
				fprintf(stderr, "Error: Cannot get prog fd for bpf program %s\n", progs[i].name);
				return 1;
		}
             // 給 progs map 的 map_prog_idx 插入 prog_fd
		err = bpf_map_update_elem(map_progs_fd, &map_prog_idx, &prog_fd, 0);
			if (err) {
				fprintf(stderr, "Error: bpf_map_update_elem failed for prog array map\n");
				return 1;
			}
		}
	}
#endif
 // 只載入主程序，尾調用不載入，所以不可以調用trace_bpf__attach
	struct bpf_link* link = bpf_program__attach(skel->progs.__seccomp_filter);
	if (link == NULL) {
		fprintf(stderr, "Error: bpf_program__attach failed\n");
		return 1;
	}
 
	while(!exiting){
	// 寫個裸循環會喫巨多CPU的
		sleep(1);
	}
 
	cleanup:
	// Clean up
		tracex5_bpf__destroy(skel);
 
 return err < 0 ? -err : 0;
 }


#if 0
/* install fake seccomp program to enable seccomp code path inside the kernel,
 * so that our kprobe attached to seccomp_phase1() can be triggered
 */
static void install_accept_all_seccomp(void)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)ARRAY_SIZE(filter),
		.filter = filter,
	};
	if (prctl(PR_SET_SECCOMP, 2, &prog))
		perror("prctl");
}

int main(int ac, char **argv)
{
	struct bpf_link *link = NULL;
	struct bpf_program *prog;
	struct bpf_object *obj;
	int key, fd, progs_fd;
	const char *section;
	char filename[256];
	FILE *f;

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		return 0;
	}

	prog = bpf_object__find_program_by_name(obj, "bpf_prog1");
	if (!prog) {
		printf("finding a prog in obj file failed\n");
		goto cleanup;
	}

	/* load BPF program */
	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(prog);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "ERROR: bpf_program__attach failed\n");
		link = NULL;
		goto cleanup;
	}

	progs_fd = bpf_object__find_map_fd_by_name(obj, "progs");
	if (progs_fd < 0) {
		fprintf(stderr, "ERROR: finding a map in obj file failed\n");
		goto cleanup;
	}

	bpf_object__for_each_program(prog, obj) {
		section = bpf_program__section_name(prog);
		/* register only syscalls to PROG_ARRAY */
		if (sscanf(section, "kprobe/%d", &key) != 1)
			continue;

		fd = bpf_program__fd(prog);
		bpf_map_update_elem(progs_fd, &key, &fd, BPF_ANY);
	}

	install_accept_all_seccomp();

	f = popen("dd if=/dev/zero of=/dev/null count=5", "r");
	(void) f;

	//read_trace_pipe();

cleanup:
	bpf_link__destroy(link);
	bpf_object__close(obj);
	return 0;
}
#endif
