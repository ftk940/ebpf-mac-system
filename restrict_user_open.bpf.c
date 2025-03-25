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

#define X86_64_OPEN_SYSCALL 2
#define OPEN_SYSCALL X86_64_OPEN_SYSCALL

#define TASK_COMM_LEN  16
#define MAX_PATH_LEN 128

#define MAX_RESTRICTED_FILE_NUM 10
#define MAX_RESTRICTED_UID_NUM 10

#define MAX_TYPE_LEN 10
#define MAX_RESTRICTED_OBJECT_TYPE_NUM 10
#define MAX_TYPE_NUM_PER_FILE 5
#define MAX_FILE_NUM_WITH_OBJECT_TYPE (2 * MAX_RESTRICTED_FILE_NUM)

#define MAX_GROUP_LEN 10
#define MAX_GROUP_NUM_PER_USER 5
#define MAX_UID_NUM_WITH_GROUP 10
#define MAX_RESTRICTED_GROUP_NUM_PER_OBJECT_TYPE 10

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RESTRICTED_FILE_NUM);
	__type(key, char[MAX_PATH_LEN]);
	__type(value, char);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} default_allow_files_user SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RESTRICTED_FILE_NUM);
	__type(key, char[MAX_PATH_LEN]);
	__type(value, char);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} default_deny_files_user SEC(".maps");

struct uid_list {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RESTRICTED_UID_NUM);
	__type(key, int);
	__type(value, char);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} uid_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, MAX_RESTRICTED_FILE_NUM);
    __uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, char[MAX_PATH_LEN]);
	__array(values, struct uid_list);
} deny_user_open_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, MAX_RESTRICTED_FILE_NUM);
    __uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, char[MAX_PATH_LEN]);
	__array(values, struct uid_list);
} allow_user_open_map SEC(".maps");

// type enforcement
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RESTRICTED_OBJECT_TYPE_NUM);
	__type(key, char[MAX_TYPE_LEN]);
	__type(value, char);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} default_allow_object_types_user SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RESTRICTED_OBJECT_TYPE_NUM);
	__type(key, char[MAX_TYPE_LEN]);
	__type(value, char);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} default_deny_object_types_user SEC(".maps");

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
} path_to_object_types_user SEC(".maps");

struct user_groups {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_GROUP_NUM_PER_USER);
	__type(key, char[MAX_GROUP_LEN]);
	__type(value, char);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} temp2 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, MAX_UID_NUM_WITH_GROUP);
    __uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__array(values, struct user_groups);
} uid_to_groups SEC(".maps");

struct restricted_groups {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RESTRICTED_GROUP_NUM_PER_OBJECT_TYPE);
	__type(key, char[MAX_GROUP_LEN]);
	__type(value, char);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} temp3 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, MAX_RESTRICTED_OBJECT_TYPE_NUM);
    __uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, char[MAX_TYPE_LEN]);
	__array(values, struct restricted_groups);
} deny_group_open_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, MAX_RESTRICTED_OBJECT_TYPE_NUM);
    __uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, char[MAX_TYPE_LEN]);
	__array(values, struct restricted_groups);
} allow_group_open_map SEC(".maps");

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
    struct bpf_map *user_groups;
    char *object_type;
    char *user_group;
	int find;
};

static long check_all_restricted_groups(struct bpf_map *map, char *key, char *val, struct callback_ctx *data) {
    char *v = bpf_map_lookup_elem(data->user_groups, key);
    if(v) {
        data->find = 1;
        data->user_group = key;
        return 1;
    }
    return 0;
}

static long check_allow_group_map(struct bpf_map *map, char *key, char *val, struct callback_ctx *data) {
    struct bpf_map *all_restricted_groups = bpf_map_lookup_elem(&allow_group_open_map, key);
    if(all_restricted_groups == NULL)
    	return 0;
    	
    bpf_for_each_map_elem(all_restricted_groups, check_all_restricted_groups, data, 0);
    if(data->find) {
    	data->object_type = key;
    	return 1;
    }
    return 0;
}

static long check_deny_group_map(struct bpf_map *map, char *key, char *val, struct callback_ctx *data) {
    struct bpf_map *all_restricted_groups = bpf_map_lookup_elem(&deny_group_open_map, key);
    if(all_restricted_groups == NULL)
    	return 0;
    	
    bpf_for_each_map_elem(all_restricted_groups, check_all_restricted_groups, data, 0);
    if(data->find) {
    	data->object_type = key;
    	return 1;
    }
    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(restrict_user_open, struct file *file, int ret)
{
    struct pt_regs *regs;
    struct task_struct *task;
    int syscall;

    // If previous hooks already denied, go ahead and deny this one
    if (ret) {
        return ret;
    }


    task = bpf_get_current_task_btf();
    regs = (struct pt_regs *) bpf_task_pt_regs(task);
    // In x86_64 orig_ax has the syscall interrupt stored here
    syscall = regs->orig_ax;


    struct event *e;
    int zero = 0;
    e = bpf_map_lookup_elem(&event_buf, &zero);
    if (!e) /* can't happen */
        return 0;
    e->syscall = OPEN;
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
    
    get_path(file, e->file_path);

    char *default_allow = NULL;
    default_allow = bpf_map_lookup_elem(&default_allow_files_user, e->file_path);
    
    char *default_deny = NULL;
    default_deny = bpf_map_lookup_elem(&default_deny_files_user, e->file_path);

    if(default_allow) {
        struct bpf_map *denied_uids = NULL;
        denied_uids = bpf_map_lookup_elem(&deny_user_open_map, e->file_path);

        if(denied_uids) {
            char *v = NULL;
            v = bpf_map_lookup_elem(denied_uids, &(e->euid));
            if(v) {
                e->permission_type = DENY;
                e->restricted_target = USER;
                bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
                return -EPERM;
            }
        }
    }
    else if(default_deny) {
        struct bpf_map *allowed_uids = NULL;
        allowed_uids = bpf_map_lookup_elem(&allow_user_open_map, e->file_path);

        if(allowed_uids) {
            char *v = NULL;
            v = bpf_map_lookup_elem(allowed_uids, &(e->euid));
            if(v) {
                e->permission_type = ALLOW;
                e->restricted_target = USER;
                bpf_ringbuf_output(&rb, e, sizeof(*e), 0);                  
                return 0;
            }         
        }     
    }

    // type restriction
    struct bpf_map *object_types = NULL;
    object_types = bpf_map_lookup_elem(&path_to_object_types_user, e->file_path);

    struct bpf_map *user_groups = NULL;
    user_groups = bpf_map_lookup_elem(&uid_to_groups, &(e->euid));

    if(default_allow) {
        if(object_types == NULL || user_groups == NULL)
            return 0;

        struct callback_ctx data = {
            .user_groups = user_groups,
	        .find = 0
        };

        bpf_for_each_map_elem(object_types, check_deny_group_map, &data, 0);
        
        if(data.find) {
            e->permission_type = DENY;
            e->restricted_target = GROUP;
            bpf_probe_read_str(e->user_group, sizeof(e->user_group), data.user_group);
            bpf_probe_read_str(e->object_type, sizeof(e->object_type), data.object_type);
            bpf_ringbuf_output(&rb, e, sizeof(*e), 0);  
            return -EPERM;            
        }
    }
    else if(default_deny) {
        if(object_types == NULL || user_groups == NULL) {
            return -EPERM;            
        }
        struct callback_ctx data = {
            .user_groups = user_groups,
	        .find = 0
        };

        bpf_for_each_map_elem(object_types, check_allow_group_map, &data, 0);
        
        if(data.find) {
            e->permission_type = ALLOW;
            e->restricted_target = GROUP;
            bpf_probe_read_str(e->user_group, sizeof(e->user_group), data.user_group);
            bpf_probe_read_str(e->object_type, sizeof(e->object_type), data.object_type);
            bpf_ringbuf_output(&rb, e, sizeof(*e), 0);  
            return 0;            
        }
        return -EPERM;   
    } 

    return 0;
}
