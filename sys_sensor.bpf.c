// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "include/vmlinux.h"
#include "include/missing_definitions.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "include/data_define.hpp"
#include "include/syscall.hpp"
char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* BPF ringbuf map */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} rb SEC(".maps");

// EBPF MAP MACROS ---------------------------------------------------------------------------------

#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries)                                \
    struct {                                                                                       \
        __uint(type, _type);                                                                       \
        __uint(max_entries, _max_entries);                                                         \
        __type(key, _key_type);                                                                    \
        __type(value, _value_type);                                                                \
    } _name SEC(".maps");

#define BPF_HASH(_name, _key_type, _value_type, _max_entries)                                      \
    BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, _max_entries)

#define BPF_LRU_HASH(_name, _key_type, _value_type, _max_entries)                                  \
    BPF_MAP(_name, BPF_MAP_TYPE_LRU_HASH, _key_type, _value_type, _max_entries)

#define BPF_ARRAY(_name, _value_type, _max_entries)                                                \
    BPF_MAP(_name, BPF_MAP_TYPE_ARRAY, u32, _value_type, _max_entries)

#define BPF_PERCPU_ARRAY(_name, _value_type, _max_entries)                                         \
    BPF_MAP(_name, BPF_MAP_TYPE_PERCPU_ARRAY, u32, _value_type, _max_entries)

#define BPF_PROG_ARRAY(_name, _max_entries)                                                        \
    BPF_MAP(_name, BPF_MAP_TYPE_PROG_ARRAY, u32, u32, _max_entries)

#define BPF_PERF_OUTPUT(_name, _max_entries)                                                       \
    BPF_MAP(_name, BPF_MAP_TYPE_PERF_EVENT_ARRAY, int, __u32, _max_entries)

#ifndef CORE
#else
	#define GET_FIELD_ADDR(field) __builtin_preserve_access_index(&field)
	#define READ_KERN(ptr)					    \
	({							    \
		typeof(ptr) _val;				    \
		__builtin_memset((void*) &_val, 0, sizeof(_val));    \
		bpf_core_read ((void *) &_val, sizeof(_val), &ptr); \
		_val;						    \
	 })

	#define READ_USER(ptr)						\
	({								\
		typeof(ptr) _val;					\
		__builtin_memset((void*) &_val, 0, sizeof(_val));	\
		bpf_core_read_user((void*) &_val, sizeof(_val), &ptr);  \
		_val;							\
	})
#endif
// HELPERS namespace
static __always_inline u32 get_task_pid_vnr_sid(struct task_struct *task)
{
    unsigned int level = 0;
    struct pid *pid = NULL;

#ifndef CORE
    #if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) && !defined(RHEL_RELEASE_GT_8_0))
    pid = READ_KERN(task->pids[PIDTYPE_PID].pid);
    #else
    pid = READ_KERN(task->thread_pid);
    #endif
#else
    if (bpf_core_type_exists(struct pid_link)) {
        struct task_struct___older_v50 *t = (void *) task;
        pid = READ_KERN(t->pids[PIDTYPE_SID].pid);
    } else {
        pid = READ_KERN(task->thread_pid);
    }
#endif

    level = READ_KERN(pid->level);
    return READ_KERN(pid->numbers[level].nr);
}


static __always_inline u32 get_task_pid_vnr(struct task_struct *task)
{
    unsigned int level = 0;
    struct pid *pid = NULL;

#ifndef CORE
    #if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) && !defined(RHEL_RELEASE_GT_8_0))
    pid = READ_KERN(task->pids[PIDTYPE_PID].pid);
    #else
    pid = READ_KERN(task->thread_pid);
    #endif
#else
    if (bpf_core_type_exists(struct pid_link)) {
        struct task_struct___older_v50 *t = (void *) task;
        pid = READ_KERN(t->pids[PIDTYPE_PID].pid);
    } else {
        pid = READ_KERN(task->thread_pid);
    }
#endif

    level = READ_KERN(pid->level);
    return READ_KERN(pid->numbers[level].nr);
}



static __always_inline u32 get_task_pid_ns_id(struct task_struct *task)
{
    unsigned int level = 0;
    struct pid *pid = NULL;
    struct pid_namespace *ns = NULL;

#ifndef CORE
    #if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) && !defined(RHEL_RELEASE_GT_8_0))
    pid = READ_KERN(task->pids[PIDTYPE_PID].pid);
    #else
    pid = READ_KERN(task->thread_pid);
    #endif
#else
    //if (bpf_core_type_exists(struct pid_link)) {
    //    struct task_struct___older_v50 *t = (void *) task;
    //    pid = READ_KERN(t->pids[PIDTYPE_PID].pid);
    //} else {
        pid = READ_KERN(task->thread_pid);
    //}
#endif

    level = READ_KERN(pid->level);
    ns = READ_KERN(pid->numbers[level].ns);
    return READ_KERN(ns->ns.inum);
}

static __always_inline u32 get_mnt_ns_id(struct nsproxy *ns)
{
    struct mnt_namespace *mntns = READ_KERN(ns->mnt_ns);
    return READ_KERN(mntns->ns.inum);
}
// HELPERS: TASKS ----------------------------------------------------------------------------------

static __always_inline char *get_task_uts_name(struct task_struct *task)
{
    struct nsproxy *np = READ_KERN(task->nsproxy);
    struct uts_namespace *uts_ns = READ_KERN(np->uts_ns);
    return READ_KERN(uts_ns->name.nodename);
}

static __always_inline u32 get_task_ppid(struct task_struct *task)
{
    struct task_struct *parent = READ_KERN(task->real_parent);
    return READ_KERN(parent->tgid);
}

static __always_inline u64 get_task_start_time(struct task_struct *task)
{
    return READ_KERN(task->start_time);
}

static __always_inline u32 get_task_host_pid(struct task_struct *task)
{
    return READ_KERN(task->pid);
}

static __always_inline u32 get_task_host_tgid(struct task_struct *task)
{
    return READ_KERN(task->tgid);
}

static __always_inline struct task_struct *get_parent_task(struct task_struct *task)
{
    return READ_KERN(task->real_parent);
}

static __always_inline u32 get_task_exit_code(struct task_struct *task)
{
    return READ_KERN(task->exit_code);
}

static __always_inline int get_task_parent_flags(struct task_struct *task)
{
    struct task_struct *parent = READ_KERN(task->real_parent);
    return READ_KERN(parent->flags);
}

static __always_inline const struct cred *get_task_real_cred(struct task_struct *task)
{
    return READ_KERN(task->real_cred);
}

static __always_inline u32 get_task_ns_pid(struct task_struct *task)
{
    return get_task_pid_vnr(task);
}

static __always_inline u32 get_task_ns_tgid(struct task_struct *task)
{
    struct task_struct *group_leader = READ_KERN(task->group_leader);
    return get_task_pid_vnr(group_leader);
}

static __always_inline u32 get_task_ns_ppid(struct task_struct *task)
{
    struct task_struct *real_parent = READ_KERN(task->real_parent);
    return get_task_pid_vnr(real_parent);
}

static __always_inline u32 get_task_mnt_ns_id(struct task_struct *task)
{
    return get_mnt_ns_id(READ_KERN(task->nsproxy));
}

// memory

static __always_inline struct mm_struct* get_mm_from_task(struct task_struct* task)
{
    return READ_KERN(task->mm);
}

static __always_inline unsigned long get_arg_start_from_mm(struct mm_struct* mm)
{
    return READ_KERN(mm->arg_start);
}

static __always_inline unsigned long get_arg_end_from_mm(struct mm_struct* mm)
{
    return READ_KERN(mm->arg_end);
}

static __always_inline struct file* get_file_from_mm(struct mm_struct* mm)
{
    return READ_KERN(mm->exe_file);
}

static __always_inline u64 get_ctime_nanosec_from_inode(struct inode *inode)
{
    struct timespec64 ts = READ_KERN(inode->i_ctime);
    time64_t sec = READ_KERN(ts.tv_sec);
    if (sec < 0)
        return 0;
    long ns = READ_KERN(ts.tv_nsec);
    return (sec * 1000000000L) + ns;
}

static __always_inline u64 get_ctime_nanosec_from_file(struct file *file)
{
    struct inode *f_inode = READ_KERN(file->f_inode);
    return get_ctime_nanosec_from_inode(f_inode);
}
static __always_inline u64 get_mtime_nanosec_from_inode(struct inode *inode)
{
    struct timespec64 ts = READ_KERN(inode->i_mtime);
    time64_t sec = READ_KERN(ts.tv_sec);
    if (sec < 0)
        return 0;
    long ns = READ_KERN(ts.tv_nsec);
    return (sec * 1000000000L) + ns;
}

static __always_inline u64 get_mtime_nanosec_from_file(struct file *file)
{
    struct inode *f_inode = READ_KERN(file->f_inode);
    return get_ctime_nanosec_from_inode(f_inode);
}
// vfs
static inline struct mount *real_mount(struct vfsmount *mnt)
{
    return container_of(mnt, struct mount, mnt);
}

BPF_HASH(kconfig_map, u32, u32, 10240);                            // kernel config variables
BPF_HASH(interpreter_map, u32, file_info_t, 10240);                // interpreter file used for each process
BPF_HASH(containers_map, u32, u8, 10240);                          // map cgroup id to container status {EXISTED, CREATED, STARTED}
BPF_HASH(args_map, u64, args_t, 1024);                             // persist args between function entry and return
BPF_HASH(uid_filter, u32, u32, 256);                               // filter events by UID, for specific UIDs either by == or !=
BPF_HASH(pid_filter, u32, u32, 256);                               // filter events by PID
BPF_HASH(mnt_ns_filter, u64, u32, 256);                            // filter events by mount namespace id
BPF_HASH(pid_ns_filter, u64, u32, 256);                            // filter events by pid namespace id
BPF_HASH(uts_ns_filter, string_filter_t, u32, 256);                // filter events by uts namespace name
BPF_HASH(comm_filter, string_filter_t, u32, 256);                  // filter events by command name
BPF_HASH(cgroup_id_filter, u32, u32, 256);                         // filter events by cgroup id
BPF_HASH(bin_args_map, u64, bin_args_t, 256);                      // persist args for send_bin funtion
BPF_HASH(sys_32_to_64_map, u32, u32, 1024);                        // map 32bit to 64bit syscalls
BPF_HASH(params_types_map, u32, u64, 1024);                        // encoded parameters types for event
BPF_HASH(process_tree_map, u32, u32, 10240);                       // filter events by the ancestry of the traced process
BPF_LRU_HASH(task_info_map, u32, task_info_t, 10240);              // holds data for every task
// BPF_HASH(network_config, u32, int, 1024);                          // holds the network config for each iface
BPF_HASH(ksymbols_map, ksym_name_t, u64, 1024);                    // holds the addresses of some kernel symbols
BPF_HASH(syscalls_to_check_map, int, u64, 256);                    // syscalls to discover
// BPF_LRU_HASH(sock_ctx_map, u64, net_ctx_ext_t, 10240);             // socket address to process context
// BPF_LRU_HASH(network_map, net_id_t, net_ctx_t, 10240);             // network identifier to process context
// BPF_ARRAY(config_map, config_entry_t, 1);                          // various configurations
BPF_ARRAY(file_filter, path_filter_t, 3);                          // filter vfs_write events
BPF_PERCPU_ARRAY(bufs, buf_t, MAX_BUFFERS);                        // percpu global buffer variables
BPF_PROG_ARRAY(prog_array, MAX_TAIL_CALL);                         // store programs for tail calls
BPF_PROG_ARRAY(prog_array_tp, MAX_TAIL_CALL);                      // store programs for tail calls
BPF_PROG_ARRAY(sys_enter_tails, MAX_EVENT_ID);                     // store syscall specific programs for tail calls from sys_enter
BPF_PROG_ARRAY(sys_exit_tails, MAX_EVENT_ID);                      // store syscall specific programs for tail calls from sys_exit
BPF_PROG_ARRAY(sys_enter_submit_tail, MAX_EVENT_ID);               // store program for submitting syscalls from sys_enter
BPF_PROG_ARRAY(sys_exit_submit_tail, MAX_EVENT_ID);                // store program for submitting syscalls from sys_exit
BPF_PROG_ARRAY(sys_enter_init_tail, MAX_EVENT_ID);                 // store program for performing syscall tracking logic in sys_enter
BPF_PROG_ARRAY(sys_exit_init_tail, MAX_EVENT_ID);                  // store program for performing syscall tracking logic in sys_exits
//BPF_STACK_TRACE(stack_addresses, MAX_STACK_ADDRESSES);             // store stack traces
// BPF_HASH(module_init_map, u32, kmod_data_t, 256);                  // holds module information between
BPF_LRU_HASH(fd_arg_path_map, fd_arg_task_t, fd_arg_path_t, 1024); // store fds paths by task
// clang-format on
// EBPF PERF BUFFERS -------------------------------------------------------------------------------
BPF_PERF_OUTPUT(events, 1024);      // events submission
BPF_PERF_OUTPUT(file_writes, 1024); // file writes events submission
BPF_PERF_OUTPUT(net_events, 1024);  // network events submission
// INTERNAL: BUFFERS -------------------------------------------------------------------------------
static __always_inline buf_t *get_buf(int idx)
{
    return bpf_map_lookup_elem(&bufs, &idx);
}
// vfs
static __always_inline struct dentry *get_mnt_root_ptr_from_vfsmnt(struct vfsmount *vfsmnt)
{
    return READ_KERN(vfsmnt->mnt_root);
}
static __always_inline struct dentry *get_d_parent_ptr_from_dentry(struct dentry *dentry)
{
    return READ_KERN(dentry->d_parent);
}
static __always_inline struct qstr get_d_name_from_dentry(struct dentry *dentry)
{
    return READ_KERN(dentry->d_name);
}
static __always_inline int init_context(event_context_t *context, struct task_struct *task)
{
    u64 id = bpf_get_current_pid_tgid();
    context->task.start_time = get_task_start_time(task);
    context->task.host_tid = id;
    context->task.host_pid = id >> 32;
    context->task.host_ppid = get_task_ppid(task);
    context->task.tid = get_task_ns_pid(task);
    context->task.pid = get_task_ns_tgid(task);
    context->task.ppid = get_task_ns_ppid(task);
    context->task.mnt_id = get_task_mnt_ns_id (task);
    context->task.pid_id = get_task_pid_ns_id (task);
    context->task.uid = bpf_get_current_uid_gid();
    context->task.sid = get_task_pid_vnr(task);

    bpf_get_current_comm(&context->task.comm, sizeof(context->task.comm));
    char* uts_name = get_task_uts_name(task);
    if (uts_name)
	bpf_probe_read_str(&context->task.uts_name, TASK_COMM_LEN, uts_name);
    context->ts = bpf_ktime_get_ns();
    context->argnum = 0;
    return 0;
}
static __always_inline task_info_t *init_task_info(u32 key, bool* initialized) 
{
    task_info_t *task_info = bpf_map_lookup_elem(&task_info_map, &key);
    if (initialized) {
	*initialized = task_info == NULL;
    }
    if (unlikely(task_info == NULL)) {
	// unlikely code path - possibly optimize with unlikely macro later

        // get the submit buffer to fill the task_info_t in the map
        // this is done because allocating the stack space for task_info_t usually
        // crosses the verifier limit.
        int buf_idx = SUBMIT_BUF_IDX;
        void *submit_buffer = bpf_map_lookup_elem(&bufs, &buf_idx);
	if (unlikely(submit_buffer == NULL))
            return NULL;
        bpf_map_update_elem(&task_info_map, &key, submit_buffer, BPF_NOEXIST);
        task_info = bpf_map_lookup_elem(&task_info_map, &key);
        // appease the verifier
        if (unlikely(task_info == NULL)) {
            return NULL;
        }
        task_info->syscall_traced = false;
        task_info->new_task = false;
        task_info->follow = false;
        task_info->recompute_scope = true;
    }
    return task_info;
}
static __always_inline int save_str_to_buf(event_data_t *data, void *ptr, u8 index)
{
    if (data->buf_off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE -sizeof(int))
	return 0;

    data->submit_p->buf[(data->buf_off) & (MAX_PERCPU_BUFSIZE - 1)] = index;
    //bpf_printk("buf_off = %d, str = %s", data->buf_off, ptr);
    if ((data->buf_off + 1) <= MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int)) {
	int sz = bpf_probe_read_str (&(data->submit_p->buf[data->buf_off + 1 + sizeof(int)]), MAX_STRING_SIZE, ptr);
        if (sz > 0) {
	    if ((data->buf_off + 1) > MAX_PERCPU_BUFSIZE - sizeof(int)) {
		return 0;
	    }
	    __builtin_memcpy(& (data->submit_p->buf[data->buf_off + 1]), &sz, sizeof(int));
	    data->buf_off += sz + sizeof(int) + 1;
	    data->context.argnum++;
	    return 1;
	}
    }
    return 0;
}
static __always_inline int save_str_arr_to_buf(event_data_t *data, const char __user *const __user *ptr, u8 index) 
{
    // Data saved to submit buf: [index][string count][str1 size][str1][str2 size][str2]...
    u8 elem_num = 0;
    // Save argument index
    data->submit_p->buf[(data->buf_off) & (MAX_PERCPU_BUFSIZE - 1)] = index;
    // Save space for number of elements (1 byte)
    u32 orig_off = data->buf_off + 1;
    data->buf_off += 2;
#pragma unroll
    for (int i = 0; i < MAX_STR_ARR_ELEM; i++) {
        const char *argp = NULL;
        bpf_probe_read(&argp, sizeof(argp), &ptr[i]);
        if (!argp)
            goto out;

        if (data->buf_off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
            // not enough space - return
            goto out;

        // Read into buffer
        int sz = bpf_probe_read_str(
            &(data->submit_p->buf[data->buf_off + sizeof(int)]), MAX_STRING_SIZE, argp);
        if (sz > 0) {
            if (data->buf_off > MAX_PERCPU_BUFSIZE - sizeof(int))
                // Satisfy validator
                goto out;
            bpf_probe_read(&(data->submit_p->buf[data->buf_off]), sizeof(int), &sz);
            data->buf_off += sz + sizeof(int);
            elem_num++;
            continue;
        } else {
            goto out;
        }
    }
    // handle truncated argument list
    char ellipsis[] = "...";
    if (data->buf_off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
        // not enough space - return
        goto out;
    // Read into buffer
    int sz = bpf_probe_read_str(
        &(data->submit_p->buf[data->buf_off + sizeof(int)]), MAX_STRING_SIZE, ellipsis);
    if (sz > 0) {
        if (data->buf_off > MAX_PERCPU_BUFSIZE - sizeof(int))
            // Satisfy validator
            goto out;
        bpf_probe_read(&(data->submit_p->buf[data->buf_off]), sizeof(int), &sz);
        data->buf_off += sz + sizeof(int);
        elem_num++;
    }
out:
    // save number of elements in the array
    data->submit_p->buf[orig_off & (MAX_PERCPU_BUFSIZE - 1)] = elem_num;
    data->context.argnum++;
    return 1;

}
// INTERNAL: PERF BUFFER ---------------------------------------------------------------------------
static __always_inline int events_perf_submit(event_data_t *data, u32 id, long ret)
{
    data->context.eventid = id;
    data->context.retval = ret;
    bpf_probe_read(&(data->submit_p->buf[0]), sizeof(event_context_t), &data->context);
    // satisfy validator by setting buffer bounds
    //bpf_printk("buff2 =%d",data->buf_off);
    int size = data->buf_off & (MAX_PERCPU_BUFSIZE - 1);
    //bpf_printk("buff3 =%d",data->buf_off);
    //bpf_printk("off_size = %d, size: %d\n", data->buf_off, size); 
    void *output_data = data->submit_p->buf;
    return bpf_perf_event_output(data->ctx, &events, BPF_F_CURRENT_CPU, output_data, size);
}
static __always_inline int 
init_event_data (event_data_t *data, void *ctx)
{
    data->task = (struct task_struct *) bpf_get_current_task();
    init_context(&data->context, data->task);
    data->ctx = ctx;
    data->buf_off = sizeof(event_context_t);
    //bpf_printk("sz: %d", data->buf_off);
    int buf_idx = SUBMIT_BUF_IDX;
    data->submit_p = bpf_map_lookup_elem(&bufs, &buf_idx);
    if (unlikely(data->submit_p == NULL)) {
	return 0;
    }
    // check if task_info was initialized in this call
    bool task_info_initalized = false;
    data->task_info = init_task_info(data->context.task.host_tid, &task_info_initalized);
    if (unlikely(data->task_info == NULL)) {
	return 0;
    }
   // update task_info with the new context
    bpf_probe_read(&data->task_info->context, sizeof(task_context_t), &data->context.task);
    return 1;
}
static __always_inline bool is_x86_compat(struct task_struct *task)
{
#if defined(bpf_target_x86)
    return READ_KERN(task->thread_info.status) & 0x0002;
#else
    return false;
#endif
}
static __always_inline bool is_compat(struct task_struct *task)
{
#if defined(bpf_target_x86)
    return is_x86_compat(task);
#elif defined(bpf_target_arm64)
    return is_arm64_compat(task);
#else
    return false;
#endif
}
static __always_inline int get_kconfig_val(u32 key)
{
    u32 *config = bpf_map_lookup_elem(&kconfig_map, &key);

    if (config == NULL)
        return 0;

    return *config;
}
#if defined(bpf_target_x86)
    #define PT_REGS_PARM6(ctx) ((ctx)->r9)
#elif defined(bpf_target_arm64)
    #define PT_REGS_PARM6(x) ((x)->regs[5])
#endif

#ifdef CORE
    #define get_kconfig(x) get_kconfig_val(x)
#else
    #define get_kconfig(x) CONFIG_##x
#endif
#ifdef CORE
enum kconfig_key_e
{
    ARCH_HAS_SYSCALL_WRAPPER = 1000U
};
#else
    #ifndef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
        #define CONFIG_ARCH_HAS_SYSCALL_WRAPPER 0
    #endif
#endif // CORE
// trace/events/syscalls.h: TP_PROTO(struct pt_regs *regs, long id)
// initial entry for sys_enter syscall logic
SEC("raw_tracepoint/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    int id = ctx->args[1];
    u32 task_id = bpf_get_current_pid_tgid(); // get the tid only
    task_info_t *task_info = init_task_info(task_id, NULL);
    if (unlikely(task_info == NULL)) {
        return 0;
    }
    syscall_data_t *sys = &(task_info->syscall_data);
   
    if (is_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls, so we can send to the correct handler
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &id);
        if (id_64 == 0)
            return 0;

        id = *id_64;
    }
      struct pt_regs *regs = (struct pt_regs *) ctx->args[0];

        if (is_x86_compat(task)) {
#if defined(bpf_target_x86)
            sys->args.args[0] = READ_KERN(regs->bx);
            sys->args.args[1] = READ_KERN(regs->cx);
            sys->args.args[2] = READ_KERN(regs->dx);
            sys->args.args[3] = READ_KERN(regs->si);
            sys->args.args[4] = READ_KERN(regs->di);
            sys->args.args[5] = READ_KERN(regs->bp);
#endif // bpf_target_x86
        } else {
            sys->args.args[0] = READ_KERN(PT_REGS_PARM1(regs));
            sys->args.args[1] = READ_KERN(PT_REGS_PARM2(regs));
            sys->args.args[2] = READ_KERN(PT_REGS_PARM3(regs));
#if defined(bpf_target_x86)
            // x86-64: r10 used instead of rcx (4th param to a syscall)
            sys->args.args[3] = READ_KERN(regs->r10);
#else
            sys->args.args[3] = READ_KERN(PT_REGS_PARM4(regs));
#endif
            sys->args.args[4] = READ_KERN(PT_REGS_PARM5(regs));
            sys->args.args[5] = READ_KERN(PT_REGS_PARM6(regs));
        }
    if (is_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls, so we can send to the correct handler
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &sys->id);
        if (id_64 == 0)
            return 0;

        sys->id = *id_64;
    }
    bpf_tail_call(ctx, &sys_enter_init_tail, id);
    return 0;
}
// HELPERS: VFS ------------------------------------------------------------------------------------
static __always_inline void *get_path_str(struct path *path)
{
    struct path f_path;
    bpf_probe_read(&f_path, sizeof(struct path), path);
    char slash = '/';
    int zero = 0;
    struct dentry *dentry = f_path.dentry;
    struct vfsmount *vfsmnt = f_path.mnt;
    struct mount *mnt_parent_p;

    struct mount *mnt_p = real_mount(vfsmnt);
    bpf_probe_read(&mnt_parent_p, sizeof(struct mount *), &mnt_p->mnt_parent);

    u32 buf_off = (MAX_PERCPU_BUFSIZE >> 1);
    struct dentry *mnt_root;
    struct dentry *d_parent;
    struct qstr d_name;
    unsigned int len;
    unsigned int off;
    int sz;

    // Get per-cpu string buffer
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return NULL;
/**
 *                get_dentry member     
 * file->f_path  -------------------> struct dentry
 *                                         
 *
 *
 * */
#pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
        mnt_root = get_mnt_root_ptr_from_vfsmnt(vfsmnt);
        d_parent = get_d_parent_ptr_from_dentry(dentry);
        if (dentry == mnt_root || dentry == d_parent) {
            if (dentry != mnt_root) {
                // We reached root, but not mount root - escaped?
                break;
            }
            if (mnt_p != mnt_parent_p) {
                // We reached root, but not global root - continue with mount point path
                bpf_probe_read(&dentry, sizeof(struct dentry *), &mnt_p->mnt_mountpoint);
                bpf_probe_read(&mnt_p, sizeof(struct mount *), &mnt_p->mnt_parent);
                bpf_probe_read(&mnt_parent_p, sizeof(struct mount *), &mnt_p->mnt_parent);
                vfsmnt = &mnt_p->mnt;
                continue;
            }
            // Global root - path fully parsed
            break;
        }
        // Add this dentry name to path
        d_name = get_d_name_from_dentry(dentry);
        len = (d_name.len + 1) & (MAX_STRING_SIZE - 1);
        off = buf_off - len;

        // Is string buffer big enough for dentry name?
        sz = 0;
        if (off <= buf_off) { // verify no wrap occurred
            len = len & ((MAX_PERCPU_BUFSIZE >> 1) - 1);
            sz = bpf_probe_read_str(
                &(string_p->buf[off & ((MAX_PERCPU_BUFSIZE >> 1) - 1)]), len, (void *) d_name.name);
        } else
            break;
        if (sz > 1) {
            buf_off -= 1; // remove null byte termination with slash sign
            bpf_probe_read(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &slash);
            buf_off -= sz - 1;
        } else {
            // If sz is 0 or 1 we have an error (path can't be null nor an empty string)
            break;
        }
        dentry = d_parent;
    }

    if (buf_off == (MAX_PERCPU_BUFSIZE >> 1)) {
        // memfd files have no path in the filesystem -> extract their name
        buf_off = 0;
        d_name = get_d_name_from_dentry(dentry);
        bpf_probe_read_str(&(string_p->buf[0]), MAX_STRING_SIZE, (void *) d_name.name);
    } else {
        // Add leading slash
        buf_off -= 1;
        bpf_probe_read(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &slash);
        // Null terminate the path string
        bpf_probe_read(&(string_p->buf[(MAX_PERCPU_BUFSIZE >> 1) - 1]), 1, &zero);
    }

    return &string_p->buf[buf_off];
}

#define MAX_ARR_LEN 8192
#define MAX_ELEMENT_SIZE sizeof(struct sockaddr_un)
static __always_inline int save_to_submit_buf(event_data_t *data, void *ptr, u32 size, u8 index)
{
    // Data saved to submit buf: [index][ ... buffer[size] ... ]
    if (size == 0)
        return 0;
    // If we don't have enough space - return
    if (data->buf_off > MAX_PERCPU_BUFSIZE - (size + 1))
        return 0;
    // Save argument index
    volatile int buf_off = data->buf_off;
    data->submit_p->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)] = index;
    // Satisfy validator for probe read
    if ((data->buf_off + 1) <= MAX_PERCPU_BUFSIZE - MAX_ELEMENT_SIZE) {
        // Read into buffer
        if (bpf_probe_read(&(data->submit_p->buf[data->buf_off + 1]), size, ptr) == 0) {
            // We update buf_off only if all writes were successful
            data->buf_off += size + 1;
            data->context.argnum++;
            return 1;
        }
    }
    return 0;
}
static __always_inline int save_args_str_arr_to_buf(
    event_data_t *data, const char *start, const char *end, int elem_num, u8 index)
{
    // Data saved to submit buf: [index][len][arg #][null delimited string array]
    // Note: This helper saves null (0x00) delimited string array into buf
    if (start >= end)
        return 0;
    int len = end - start;
    bpf_printk("len:: %d", len);
       bpf_printk("ele:: %d", elem_num);
  
    if (len > (MAX_ARR_LEN - 1))
        len = MAX_ARR_LEN - 1;
    // Save argument index
    data->submit_p->buf[(data->buf_off) & (MAX_PERCPU_BUFSIZE - 1)] = index;
    // Satisfy validator for probe read
    if ((data->buf_off + 1) > MAX_PERCPU_BUFSIZE - sizeof(int))
        return 0;
    // Save array length
    bpf_probe_read(&(data->submit_p->buf[data->buf_off + 1]), sizeof(int), &len);
    // Satisfy validator for probe read
    if ((data->buf_off + 5) > MAX_PERCPU_BUFSIZE - sizeof(int))
        return 0;
    // Save number of arguments
    bpf_probe_read(&(data->submit_p->buf[data->buf_off + 5]), sizeof(int), &elem_num);
    // Satisfy validator for probe read
    if ((data->buf_off + 9) > MAX_PERCPU_BUFSIZE - MAX_ARR_LEN)
        return 0;
    // Read into buffer
    if (bpf_probe_read(&(data->submit_p->buf[data->buf_off + 9]), len & (MAX_ARR_LEN - 1), start) ==
        0) {
        // We update buf_off only if all writes were successful
        data->buf_off += len + 9;
        data->context.argnum++;
        return 1;
    }
    return 0;
}
SEC("kprobe/security_file_open")
int BPF_KPROBE(do_open)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
	return 0;
    
    struct file* f = (struct file*) PT_REGS_PARM1(ctx);
    void* filee = get_path_str(&f->f_path);
     //bpf_printk("f1: %s", filee);
    unsigned int flag = READ_KERN(f->f_flags);
    struct mm_struct* p_mm = get_mm_from_task(data.task);
    struct file* p_file = get_file_from_mm(p_mm);
    void* strr2 = get_path_str(&p_file->f_path);
   //  bpf_printk("f2: %d", flag);
     if (flag & 00000100)
     {
	bpf_printk("create, %s", filee);
	bpf_printk("ps: %s",strr2);
     }
     else if ( (flag & 00000002) == 00000002 || (flag & 00000001) == 00000001)
     {
	 bpf_printk("modify %s", filee);
	bpf_printk("ps: %s",strr2);
     }
    struct inode * i_node = READ_KERN(f->f_inode);
    u64 file_sz = READ_KERN(i_node->i_size);
   // bpf_printk("buf_off: %d", data.buf_off);
    save_to_submit_buf(&data, &file_sz, sizeof(u64), 0);
    // - m_time
    u64 mtime = get_mtime_nanosec_from_file(f);
    save_to_submit_buf(&data, &mtime, sizeof(u64), 1);
    // - c time
    u64 ctime = get_ctime_nanosec_from_file(f);
    save_to_submit_buf(&data, &ctime, sizeof(u64), 2);
    // - owner_sid
    kuid_t owner_sid =  READ_KERN(i_node->i_uid);
    save_to_submit_buf(&data, &owner_sid.val, sizeof(uid_t), 3);
    // owner g_sid
    kgid_t owner_g_sid =  READ_KERN(i_node->i_gid);
    save_to_submit_buf(&data, &owner_g_sid.val, sizeof(uid_t), 4);
    save_str_to_buf (&data, (void*) filee, 5);//file path
     // process name
    save_str_to_buf (&data, (void*) strr2, 6);//file path
    return events_perf_submit(&data, SYSCALL_EXECVE, 0);
}
#define MAX_ARR_LEN 8192
SEC("kprobe/exec_binprm")
int BPF_KPROBE(do_exec_binprm)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
	return 0;
    struct linux_binprm* b = (struct linux_binprm*) PT_REGS_PARM1(ctx);
    if (!b)
	return 0;
    // file meta
    struct file* f = READ_KERN(b->file);
   
    if (!f)
	return 0;
    // - first_seen
    // - file size
    struct inode * i_node = READ_KERN(f->f_inode);
    u64 file_sz = READ_KERN(i_node->i_size);
    bpf_printk("buf_off: %d", data.buf_off);
    save_to_submit_buf(&data, &file_sz, sizeof(u64), 0);
    // - m_time
    u64 mtime = get_mtime_nanosec_from_file(f);
    save_to_submit_buf(&data, &mtime, sizeof(u64), 1);
    // - c time
    u64 ctime = get_ctime_nanosec_from_file(f);
    save_to_submit_buf(&data, &ctime, sizeof(u64), 2);
    // - owner_sid
    kuid_t owner_sid =  READ_KERN(i_node->i_uid);
    save_to_submit_buf(&data, &owner_sid.val, sizeof(uid_t), 3);
    // owner g_sid
    kgid_t owner_g_sid =  READ_KERN(i_node->i_gid);
    save_to_submit_buf(&data, &owner_g_sid.val, sizeof(uid_t), 4);
    void* strr = get_path_str(&f->f_path);
    bpf_printk("file: %s",strr);
  // process name
    struct mm_struct* p_mm = get_mm_from_task(data.task);
    struct file* p_file = get_file_from_mm(p_mm);
    void* strr2 = get_path_str(&p_file->f_path);
    bpf_printk("s: %s",strr2);
    save_str_to_buf (&data, (void*) strr2, 5);//file path
    // filename
    const char* filename = READ_KERN(b->filename);
    bpf_printk("f: %s", filename);
     save_str_to_buf (&data, (void*) filename, 6);//file path
     void* filee = get_path_str(&f->f_path);
     bpf_printk("f1: %s", filee);
      save_str_to_buf (&data, (void*) filee, 7);//file path
    return events_perf_submit(&data, SYSCALL_EXECVE, 0);
 //   return 0;
}
#if 1
//SEC("tracepoint/syscalls/sys_enter_execve")
//int syscall__execve(void *ctx) 
SEC("raw_tracepoint/sys_execve")
int syscall__execve(void* ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
	return 0;
   struct mm_struct* p_mm = get_mm_from_task(data.task);
    struct file* p_file = get_file_from_mm(p_mm);
    u64 ctime = get_ctime_nanosec_from_file(p_file);
    // first_seen
    // file size
    struct inode * i_node = READ_KERN(p_file->f_inode);
    
    long long int file_sz = READ_KERN(i_node->i_size);
    // m_time
    u64 mtime = get_mtime_nanosec_from_file(p_file);
 
    // owner_sid
    kuid_t owner_sid =  READ_KERN(i_node->i_uid);
    // owner g_sid
    kgid_t owner_g_sid =  READ_KERN(i_node->i_gid);
    void* strr = get_path_str(GET_FIELD_ADDR(p_file->f_path));
   return events_perf_submit(&data, SYSCALL_EXECVE, 0);
}
#endif
