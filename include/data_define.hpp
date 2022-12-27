// clang-format off
#define MAX_PERCPU_BUFSIZE  (1 << 15) // set by the kernel as an upper bound
#define MAX_STRING_SIZE     4096      // same as PATH_MAX
#define MAX_BYTES_ARR_SIZE  4096      // max size of bytes array (arbitrarily chosen)
#define MAX_STACK_ADDRESSES 1024      // max amount of diff stack trace addrs to buffer
#define MAX_STACK_DEPTH     20        // max depth of each stack trace to track
#define MAX_STR_FILTER_SIZE 16        // bounded to size of the compared values (comm)
#define FILE_MAGIC_HDR_SIZE 32        // magic_write: bytes to save from a file's header
#define FILE_MAGIC_MASK     31        // magic_write: mask used for verifier boundaries
#define NET_SEQ_OPS_SIZE    4         // print_net_seq_ops: struct size - TODO: replace with uprobe argument
#define NET_SEQ_OPS_TYPES   6         // print_net_seq_ops: argument size - TODO: replace with uprobe argument
#define MAX_KSYM_NAME_SIZE  64
#define UPROBE_MAGIC_NUMBER 20220829
// clang-format on


#ifndef likely
    #define likely(x) __builtin_expect((x), 1)
#endif

#ifndef unlikely
    #define unlikely(x) __builtin_expect((x), 0)
#endif

enum buf_idx_e
{
    SUBMIT_BUF_IDX,
    STRING_BUF_IDX,
    FILE_BUF_IDX,
    MAX_BUFFERS
};

enum bin_type_e
{
    SEND_VFS_WRITE = 1,
    SEND_MPROTECT,
    SEND_KERNEL_MODULE,
};

enum tail_call_id_e
{
    TAIL_VFS_WRITE,
    TAIL_VFS_WRITEV,
    TAIL_SEND_BIN,
    TAIL_SEND_BIN_TP,
    TAIL_KERNEL_WRITE,
    MAX_TAIL_CALL
};

enum event_id_e
{
    // Net events IDs
    NET_PACKET = 700,
    DNS_REQUEST,
    DNS_RESPONSE,
    MAX_NET_EVENT_ID,
    // Common event IDs
    RAW_SYS_ENTER,
    RAW_SYS_EXIT,
    SCHED_PROCESS_FORK,
    SCHED_PROCESS_EXEC,
    SCHED_PROCESS_EXIT,
    SCHED_SWITCH,
    DO_EXIT,
    CAP_CAPABLE,
    VFS_WRITE,
    VFS_WRITEV,
    MEM_PROT_ALERT,
    COMMIT_CREDS,
    SWITCH_TASK_NS,
    MAGIC_WRITE,
    CGROUP_ATTACH_TASK,
    CGROUP_MKDIR,
    CGROUP_RMDIR,
    SECURITY_BPRM_CHECK,
    SECURITY_FILE_OPEN,
    SECURITY_INODE_UNLINK,
    SECURITY_SOCKET_CREATE,
    SECURITY_SOCKET_LISTEN,
    SECURITY_SOCKET_CONNECT,
    SECURITY_SOCKET_ACCEPT,
    SECURITY_SOCKET_BIND,
    SECURITY_SOCKET_SETSOCKOPT,
    SECURITY_SB_MOUNT,
    SECURITY_BPF,
    SECURITY_BPF_MAP,
    SECURITY_KERNEL_READ_FILE,
    SECURITY_INODE_MKNOD,
    SECURITY_POST_READ_FILE,
    SECURITY_INODE_SYMLINK,
    SECURITY_MMAP_FILE,
    SECURITY_FILE_MPROTECT,
    SOCKET_DUP,
    HIDDEN_INODES,
    __KERNEL_WRITE,
    PROC_CREATE,
    KPROBE_ATTACH,
    CALL_USERMODE_HELPER,
    DIRTY_PIPE_SPLICE,
    DEBUGFS_CREATE_FILE,
    PRINT_SYSCALL_TABLE,
    DEBUGFS_CREATE_DIR,
    DEVICE_ADD,
    REGISTER_CHRDEV,
    SHARED_OBJECT_LOADED,
    DO_INIT_MODULE,
    SOCKET_ACCEPT,
    LOAD_ELF_PHDRS,
    HOOKED_PROC_FOPS,
    PRINT_NET_SEQ_OPS,
    TASK_RENAME,
    SECURITY_INODE_RENAME,
    MAX_EVENT_ID,
};
#define SEND_META_SIZE 24
#ifndef CORE
    #if LINUX_VERSION_CODE <                                                                       \
        KERNEL_VERSION(5, 2, 0) // lower values in old kernels (instr lim is 4096)
        #define MAX_STR_ARR_ELEM      40
        #define MAX_ARGS_STR_ARR_ELEM 15
        #define MAX_PATH_PREF_SIZE    64
        #define MAX_PATH_COMPONENTS   20
        #define MAX_BIN_CHUNKS        110
    #else // complexity limit of 1M verified instructions
        #define MAX_STR_ARR_ELEM      128
        #define MAX_ARGS_STR_ARR_ELEM 128
        #define MAX_PATH_PREF_SIZE    128
        #define MAX_PATH_COMPONENTS   48
        #define MAX_BIN_CHUNKS        256
    #endif
#else                                // CORE
    #define MAX_STR_ARR_ELEM      40 // TODO: turn this into global variables set w/ libbpfgo
    #define MAX_ARGS_STR_ARR_ELEM 15
    #define MAX_PATH_PREF_SIZE    64
    #define MAX_PATH_COMPONENTS   20
    #define MAX_BIN_CHUNKS        110
#endif


#define MAX_CACHED_PATH_SIZE 64

#define TASK_COMM_LEN 16
typedef struct task_context {
    u64 start_time;// 8
    u32 pid; //4
    u32 tid; // 4
    u32 ppid; // 4
    u32 sid;          //4
    // TODO namespace
    u32 host_pid; // 4
    u32 host_tid; // 4
    u32 host_ppid; // 4
    /***************/
    u32 uid; // 4
    u32 mnt_id; // 4
    u32 pid_id; //4
    char comm[TASK_COMM_LEN]; // 16
    char uts_name[TASK_COMM_LEN]; //16 
    u32 flags; // 4
} task_context_t;

typedef struct event_contest {
    u64 ts; // 8
    task_context_t task; // 84
    u32 eventid; // 4
    u32 padding; // 4
    u64 retval; // 8
    u32 stack_id;// 4
    u16 processor_id;// 2
    u8 argnum; // 1
} event_context_t;

typedef struct fd_arg_task {
    u32 pid;
    u32 tid;
    int fd;
} fd_arg_task_t;

typedef struct fd_arg_path {
    char path[MAX_CACHED_PATH_SIZE];
} fd_arg_path_t;

typedef struct args {
    unsigned long args[6];
} args_t;

typedef struct syscall_data {
    uint id;
    args_t args;
    unsigned long ts;
    unsigned long ret; 
} syscall_data_t;

typedef struct task_info {
    task_context_t context;
    syscall_data_t syscall_data;
    bool syscall_traced;
    bool recompute_scope;
    bool new_task;
    bool follow;
    int should_trace;
} task_info_t;

typedef struct simple_buf {
    u8 buf[1 << 15];// 65535
} buf_t;

typedef struct event_data {
    event_context_t context;
    struct task_struct *task;
    task_info_t *task_info;
    void *ctx;
    buf_t *submit_p;
    u32 buf_off;
} event_data_t;

// #define MAX_CACHED_PATH_SIZE 64
typedef struct file_info {
    char pathname[MAX_CACHED_PATH_SIZE];
    dev_t device;
    unsigned long inode;
    u64 ctime;
} file_info_t;

typedef struct path_filter {
    char path[MAX_PATH_PREF_SIZE];
} path_filter_t;

typedef struct string_filter {
    char str[MAX_STR_FILTER_SIZE];
} string_filter_t;

typedef struct ksym_name {
    char str[MAX_KSYM_NAME_SIZE];
} ksym_name_t;

typedef struct bin_args {
    u8 type;
    u8 metadata[SEND_META_SIZE];
    char *ptr;
    loff_t start_off;
    unsigned int full_size;
    u8 iov_idx;
    u8 iov_len;
    struct iovec *vec;
} bin_args_t;


