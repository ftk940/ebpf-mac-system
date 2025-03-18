/*#include <linux/bpf.h>
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/types.h>
*/
#include "vmlinux.h"

typedef unsigned int u32;
typedef long long unsigned int u64;


#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define MAX_PATH_LEN 128
#define MAX_PATH_COMPONENTS 10
#define LIMIT_PATH_LEN(x) ((x) & (MAX_PATH_LEN - 1))
#define LIMIT_LEN(x) ((x) & (256 - 1))
#define TASK_COMM_LEN  16

/* The hash is always the low bits of hash_len */
/*struct qstr {
	union {
		struct {
			u32 hash; 
            u32 len;
		};
		u64 hash_len;
	};
	const unsigned char *name;
} __attribute__((preserve_access_index));

struct dentry {
	struct dentry *d_parent;	// parent directory 
	struct qstr d_name;
} __attribute__((preserve_access_index));

struct vfsmount {
	struct dentry *mnt_root;	// root of the mounted tree 
} __attribute__((preserve_access_index));

struct ns_common {
	unsigned int inum;
} __attribute__((preserve_access_index));

struct mnt_namespace {
	struct ns_common	ns;
} __attribute__((preserve_access_index));

struct mount {
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
	struct mnt_namespace *mnt_ns;	// containing namespace 
} __attribute__((preserve_access_index));

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
} __attribute__((preserve_access_index));

struct file {
    struct path		f_path;
} __attribute__((preserve_access_index));

struct nsproxy {
    struct mnt_namespace *mnt_ns;
} __attribute__((preserve_access_index));

struct mm_struct {
    struct file  *exe_file;
} __attribute__((preserve_access_index));

struct task_struct {
    struct nsproxy			*nsproxy;
    char comm[TASK_COMM_LEN];
    struct mm_struct		*mm;
} __attribute__((preserve_access_index));
*/
//char LICENSE[] SEC("license") = "GPL";

/*static inline int mystrcmp(const char *cs, const char *ct);
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
}*/

static inline int get_path(struct file *file, char file_path[MAX_PATH_LEN * 2])
{   
    int err = 0;

    struct path f_path;
    err = bpf_probe_read_kernel(&f_path, sizeof(f_path), &file->f_path); // use BPF_CORE_READ()?

    struct vfsmount *vfs_mnt;
    err = bpf_probe_read_kernel(&vfs_mnt, sizeof(vfs_mnt), &f_path.mnt);

    struct dentry *mnt_root;
    err = bpf_probe_read_kernel(&mnt_root, sizeof(mnt_root), &vfs_mnt->mnt_root);

    struct mount *mnt = container_of(vfs_mnt, struct mount, mnt); // in bpf_helpers.h

    struct mnt_namespace *mnt_ns;
    err = bpf_probe_read_kernel(&mnt_ns, sizeof(mnt_ns), &mnt->mnt_ns);

    struct ns_common ns;
    err = bpf_probe_read_kernel(&ns, sizeof(ns), &mnt_ns->ns);
    //bpf_printk("mnt namespace: %u\n", ns.inum);

    /*struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct nsproxy *nsproxy;
    bpf_probe_read(&nsproxy, sizeof(nsproxy), &task->nsproxy);
    bpf_probe_read(&mnt_ns, sizeof(mnt_ns), &nsproxy->mnt_ns);
    bpf_probe_read(&ns, sizeof(ns), &mnt_ns->ns);
    bpf_printk("offsetof(struct task_struct, nsproxy): %d\n", offsetof(struct task_struct, nsproxy));
    bpf_printk("offsetof(struct nsproxy, mnt_ns): %d\n", offsetof(struct nsproxy, mnt_ns));
    bpf_printk("offsetof(struct mnt_namespace, ns): %d\n", offsetof(struct mnt_namespace, ns));
    bpf_printk("offsetof(struct ns_common, inum) %d\n", offsetof(struct ns_common, inum));
    bpf_printk("mnt namespace 2: %u\n", ns.inum);*/

    struct mount *mnt_parent;
    err = bpf_probe_read_kernel(&mnt_parent, sizeof(mnt_parent), &mnt->mnt_parent);
    
    struct dentry *dentry;
    err = bpf_probe_read_kernel(&dentry, sizeof(dentry), &f_path.dentry);

    int cur_offset = MAX_PATH_LEN - 1;
    file_path[cur_offset] = '\0';
    u32 name_len = 0;
    struct qstr d_name;
    int prev_offset = 0;
    int copy_offset = 0;

#pragma unroll
    for(int i = 0; i < MAX_PATH_COMPONENTS; i++) {
        struct dentry *d_parent;
        bpf_probe_read_kernel(&d_parent, sizeof(d_parent), &dentry->d_parent);
        if(dentry == mnt_root || dentry == d_parent) {
            // reach root of the current mounted fs
            if (dentry != mnt_root) {
                // We reached root, but not mount root - escaped?
                //bpf_printk("escaped!\n");
                break;
            }
            if(mnt != mnt_parent) {
                //bpf_printk("switch to parent mount!\n");
                bpf_probe_read_kernel(&dentry, sizeof(dentry), &mnt->mnt_mountpoint);
                mnt = mnt_parent;
                bpf_probe_read_kernel(&mnt_parent, sizeof(mnt_parent), &mnt->mnt_parent);
                vfs_mnt = &mnt->mnt;
                bpf_probe_read_kernel(&mnt_root, sizeof(mnt_root), &vfs_mnt->mnt_root);
                continue;
            }
            
            else { // reach global root
                //bpf_printk("reach global root!\n");
                break;
            }
                
        }

        bpf_probe_read_kernel(&name_len, sizeof(name_len), &dentry->d_name.len);
        name_len++;
        bpf_probe_read_kernel(&d_name, sizeof(d_name), &dentry->d_name);    
        
        prev_offset = cur_offset;
        cur_offset = cur_offset - name_len; // include '/'

        if(cur_offset < 0) {
            bpf_printk("path too long\n");
            break;
        }
        
        copy_offset = LIMIT_PATH_LEN(cur_offset + 1);
        name_len = LIMIT_PATH_LEN(name_len);
        //bpf_printk("copy_offset: %d, name_len: %d\n", copy_offset, name_len);
        //if(file_path + copy_offset + name_len + sizeof(char) < file_path + MAX_PATH_LEN)
        bpf_probe_read_str(file_path + copy_offset, name_len, d_name.name);
        // invalid unbounded variable-offset indirect access to stack R1

        cur_offset = LIMIT_PATH_LEN(cur_offset);
        file_path[cur_offset] = '/';
        //bpf_printk("current name = %s, len = %d\n", file_path + copy_offset, name_len - 1);
        file_path[prev_offset] = '/';
        //bpf_printk("cur path: %s\n", file_path + cur_offset);


        dentry = d_parent;
    }
    
    file_path[MAX_PATH_LEN - 1] = '\0';
    cur_offset = LIMIT_PATH_LEN(cur_offset); // value -2147483648 makes fp pointer be out of bounds
    //bpf_printk("full path: %s\n", file_path + cur_offset);
    int i = 0;
#pragma unroll
    for(; i < MAX_PATH_LEN; i++) {
        if(file_path[cur_offset + i] == '\0')
            break;
        file_path[i] = file_path[cur_offset + i];
    }
    
#pragma unroll
    for(;i < MAX_PATH_LEN; i++) {
        i = LIMIT_LEN(i);
        file_path[i] = '\0';
    }
        
    //bpf_printk("full path: %s\n", file_path);
    return 0;

}