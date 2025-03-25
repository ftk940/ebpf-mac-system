#ifndef EVENT_UTILS_H
#define EVENT_UTILS_H

#define MAX_PATH_LEN 128
#define MAX_TYPE_LEN 10
#define MAX_GROUP_LEN 10

typedef enum permission_t {
	DENY, ALLOW
} permission_t;

typedef enum restricted_target_t {
	EXEC, USER, SUBJECT, GROUP
} restricted_target_t;

typedef enum my_syscall_t {
	READ, WRITE, OPEN, EXECVE, LOCK, IOCTL, FCNTL, MMAP//, LINK, UNLINK, SETATTR, GETATTR
} my_syscall_t;

/* definition of a sample sent to user-space from BPF program */
struct event {
	permission_t permission_type;
    restricted_target_t restricted_target;
	my_syscall_t syscall;
	int euid;
	char exec_path[MAX_PATH_LEN * 2];
	char file_path[MAX_PATH_LEN * 2];
	char subject_type[MAX_TYPE_LEN];
	char object_type[MAX_TYPE_LEN];
	char user_group[MAX_GROUP_LEN];
};

#endif /* EVENT_UTILS_H */