#include "get_path.h"
#include <linux/errno.h>
/*#include <linux/bpf.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/types.h>*/

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "event_utils.h"

#define TASK_COMM_LEN  16
#define MAX_PATH_LEN 128

#define MAX_RESTRICTED_FILE_NUM 10
#define MAX_RESTRICTED_EXEC_NUM_PER_FILE 10

#define MAY_WRITE		0x00000002

#define X86_64_WRITE_SYSCALL 1
#define WRITE_SYSCALL X86_64_WRITE_SYSCALL

#define MAX_TYPE_LEN 10
#define MAX_RESTRICTED_OBJECT_TYPE_NUM 10
#define MAX_TYPE_NUM_PER_FILE 5
#define MAX_FILE_NUM_WITH_OBJECT_TYPE (2 * MAX_RESTRICTED_FILE_NUM)
#define MAX_FILE_NUM_WITH_SUBJECT_TYPE 10
#define MAX_RESTRICTED_SUBJECT_TYPE_NUM_PER_OBJECT_TYPE 10

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RESTRICTED_FILE_NUM);
	__type(key, char[MAX_PATH_LEN]);
	__type(value, char);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} default_allow_files_exec SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RESTRICTED_FILE_NUM);
	__type(key, char[MAX_PATH_LEN]);
	__type(value, char);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} default_deny_files_exec SEC(".maps");

struct exec_list {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RESTRICTED_EXEC_NUM_PER_FILE);
	__type(key, char[MAX_PATH_LEN]);
	__type(value, char);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} exec_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, MAX_RESTRICTED_FILE_NUM);
    __uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, char[MAX_PATH_LEN]);
	__array(values, struct exec_list);
} deny_exec_write_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, MAX_RESTRICTED_FILE_NUM);
    __uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, char[MAX_PATH_LEN]);
	__array(values, struct exec_list);
} allow_exec_write_map SEC(".maps");

// type enforcement
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RESTRICTED_OBJECT_TYPE_NUM);
	__type(key, char[MAX_TYPE_LEN]);
	__type(value, char);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} default_allow_object_types_exec SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RESTRICTED_OBJECT_TYPE_NUM);
	__type(key, char[MAX_TYPE_LEN]);
	__type(value, char);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} default_deny_object_types_exec SEC(".maps");

struct file_types {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_TYPE_NUM_PER_FILE);
	__type(key, char[MAX_TYPE_LEN]);
	__type(value, char);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} temp1 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, MAX_FILE_NUM_WITH_OBJECT_TYPE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, char[MAX_PATH_LEN]);
	__array(values, struct file_types);
} path_to_object_types_exec SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, MAX_FILE_NUM_WITH_SUBJECT_TYPE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, char[MAX_PATH_LEN]);
	__array(values, struct file_types);
} path_to_subject_types SEC(".maps");

struct subject_types {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RESTRICTED_SUBJECT_TYPE_NUM_PER_OBJECT_TYPE);
	__type(key, char[MAX_TYPE_LEN]);
	__type(value, char);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} temp2 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, MAX_RESTRICTED_OBJECT_TYPE_NUM);
    __uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, char[MAX_TYPE_LEN]);
	__array(values, struct subject_types);
} deny_type_write_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, MAX_RESTRICTED_OBJECT_TYPE_NUM);
    __uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, char[MAX_TYPE_LEN]);
	__array(values, struct subject_types);
} allow_type_write_map SEC(".maps");

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
} event_buf SEC(".maps");

/*struct pt_regs {
	long unsigned int orig_ax;
} __attribute__((preserve_access_index));

struct qstr {
    unsigned char *name;
} __attribute__((preserve_access_index));

struct dentry {
    struct qstr d_name;
} __attribute__((preserve_access_index));

struct path {
    struct dentry *dentry;
} __attribute__((preserve_access_index));

struct file {
    struct path f_path;
} __attribute__((preserve_access_index));

typedef struct {
	unsigned int val;
} kuid_t;

typedef struct {
	unsigned int val;
} kgid_t;

struct cred {
    kuid_t uid;		
    kgid_t gid;			
    kuid_t euid;		
    kgid_t egid;
} __attribute__((preserve_access_index));

struct task_struct {
    struct cred *real_cred;
    struct cred *cred;
    char comm[TASK_COMM_LEN];
} __attribute__((preserve_access_index));*/

char LICENSE[] SEC("license") = "GPL";

static inline int mystrcmp(const char *cs, const char *ct)
{
    unsigned char c1, c2;

    for(int i = 0; i < MAX_PATH_LEN; i++) {
        c1 = *cs++;
        c2 = *ct++;
        if (c1 != c2)
            return c1 < c2 ? -1 : 1;
        if (!c1 || !c2)
            break;
    }
    return 0;
}

struct callback_ctx {
    struct bpf_map *subject_types;
    char *object_type;
    char *subject_type;
	int find;
};

static long check_all_restricted_subject_types(struct bpf_map *map, char *key, char *val, struct callback_ctx *data) {
    char *v = bpf_map_lookup_elem(data->subject_types, key);
    if(v) {
        data->find = 1;
        data->subject_type = key;
        return 1;
    }
    return 0;
}

static long check_allow_type_map(struct bpf_map *map, char *key, char *val, struct callback_ctx *data) {
    struct bpf_map *restricted_subject_types = bpf_map_lookup_elem(&allow_type_write_map, key);
    if(restricted_subject_types == NULL)
    	return 0;
    	
    bpf_for_each_map_elem(restricted_subject_types, check_all_restricted_subject_types, data, 0);
    if(data->find) {
    	data->object_type = key;
    	return 1;
    }
    return 0;
}

static long check_deny_type_map(struct bpf_map *map, char *key, char *val, struct callback_ctx *data) {
    struct bpf_map *restricted_subject_types = bpf_map_lookup_elem(&deny_type_write_map, key);
    if(restricted_subject_types == NULL)
    	return 0;
    	
    bpf_for_each_map_elem(restricted_subject_types, check_all_restricted_subject_types, data, 0);
    if(data->find) {
    	data->object_type = key;
    	return 1;
    }
    return 0;
}


SEC("lsm/file_permission")
int BPF_PROG(restrict_exec_write, struct file *file, int mask, int ret)
{
    struct pt_regs *regs;
    struct task_struct *task;
    int syscall;

    // If previous hooks already denied, go ahead and deny this one
    if (ret) {
        return ret;
    }

    // If not write syscall, skip following steps
    if((mask & MAY_WRITE) == 0)
        return 0;

    task = bpf_get_current_task_btf();
    regs = (struct pt_regs *) bpf_task_pt_regs(task);
    // In x86_64 orig_ax has the syscall interrupt stored here
    syscall = regs->orig_ax;


    // Only process WRITE syscall, ignore all others
    /*if (syscall != WRITE_SYSCALL) {
        return 0;
    }*/
    struct event *e;
    int zero = 0;
    e = bpf_map_lookup_elem(&event_buf, &zero);
    if (!e) /* can't happen */
        return 0;
    e->syscall = WRITE;  
    e->euid = task->cred->euid.val;
	e->exec_path[0] = '\0';
	e->file_path[0] = '\0';
	e->subject_type[0] = '\0';
	e->object_type[0] = '\0';
	e->user_group[0] = '\0';

    char file_path[32] = "";
    bpf_probe_read_str(&file_path, sizeof(file_path), (void *)file->f_path.dentry->d_name.name);
    if(mystrcmp(file_path, "a.txt") != 0 && mystrcmp(file_path, "b.txt") != 0)
        return 0;
    //bpf_probe_read_str(&file_path, sizeof(file_path), (void *)file->f_path.dentry->d_name.name);

    get_path(file, e->file_path);

    struct bpf_map *object_types = NULL;
    object_types = bpf_map_lookup_elem(&path_to_object_types_exec, e->file_path); 

    struct mm_struct *mm;
    bpf_probe_read_kernel(&mm, sizeof(mm), &task->mm);

    struct file *exe_file;    
    bpf_probe_read_kernel(&exe_file, sizeof(exe_file), &mm->exe_file);

    char *default_allow = NULL;
    default_allow = bpf_map_lookup_elem(&default_allow_files_exec, e->file_path);

    char *default_deny = NULL;
    default_deny = bpf_map_lookup_elem(&default_deny_files_exec, e->file_path);

    int get_exec_path = 0;

    if(default_allow) {
        //bpf_printk("%s is default allow\n", file_path);
        struct bpf_map *denied_execs = NULL;
        denied_execs = bpf_map_lookup_elem(&deny_exec_write_map, e->file_path);

        if(denied_execs) {
            get_path(exe_file, e->exec_path);
            get_exec_path = 1;

            char *v = NULL;
            v = bpf_map_lookup_elem(denied_execs, e->exec_path);
            if(v) {
                /*bpf_printk("block %s write ", file_path);
                get_path(file, file_path);
                bpf_printk("%s\n", file_path);*/
                e->permission_type = DENY;
                e->restricted_target = EXEC;
                bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
                return -EPERM;
            }
        }
    }
    else if(default_deny) {
        //bpf_printk("%s is default deny\n", file_path);
        struct bpf_map *allowed_execs = NULL;
        allowed_execs = bpf_map_lookup_elem(&allow_exec_write_map, e->file_path);

        if(allowed_execs) {
            get_path(exe_file,e->exec_path);
            get_exec_path = 1;

            char *v = NULL;
            v = bpf_map_lookup_elem(allowed_execs, e->exec_path);
            if(v) {
                e->permission_type = ALLOW;
                e->restricted_target = EXEC;
                bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
                return 0;      
            }
        }        
    }

    // type restriction
    if(!get_exec_path)
        get_path(exe_file,e->exec_path);

    struct bpf_map *subject_types = NULL;
    subject_types = bpf_map_lookup_elem(&path_to_subject_types, e->exec_path);

    if(default_allow) {
        if(object_types == NULL || subject_types == NULL)
            return 0;

        struct callback_ctx data = {
            .subject_types = subject_types,
	        .find = 0
        };

        bpf_for_each_map_elem(object_types, check_deny_type_map, &data, 0);
        
        if(data.find) {
            /*bpf_printk("block %s write ", file_path);
            get_path(file, file_path);
            bpf_printk("%s\n", file_path);
            bpf_printk("subject type:%s can't write object type:%s\n", data.subject_type, data.object_type);*/
            e->permission_type = DENY;
            e->restricted_target = SUBJECT;
            bpf_probe_read_str(e->subject_type, sizeof(e->subject_type), data.subject_type);
            bpf_probe_read_str(e->object_type, sizeof(e->object_type), data.object_type);
            bpf_ringbuf_output(&rb, e, sizeof(*e), 0);  
            return -EPERM;            
        }
    }
    else if(default_deny) {
        if(object_types == NULL || subject_types == NULL) {
            /*bpf_printk("block %s write ", file_path);
            get_path(file, file_path);
            bpf_printk("%s\n", file_path);*/
            return -EPERM;            
        }
        struct callback_ctx data = {
            .subject_types = subject_types,
	        .find = 0
        };

        bpf_for_each_map_elem(object_types, check_allow_type_map, &data, 0);
        
        if(data.find) {
            //bpf_printk("subject type:%s can write object type:%s !!!!!\n", data.subject_type, data.object_type);
            e->permission_type = ALLOW;
            e->restricted_target = SUBJECT;
            bpf_probe_read_str(e->subject_type, sizeof(e->subject_type), data.subject_type);
            bpf_probe_read_str(e->object_type, sizeof(e->object_type), data.object_type);
            bpf_ringbuf_output(&rb, e, sizeof(*e), 0); 
            return 0;            
        }
        /*bpf_printk("block %s write\n", file_path);
        get_path(file, file_path);
        bpf_printk("%s\n", file_path);*/
        return -EPERM;   
    }    
    return 0;
}
