#ifndef GENERAL_UTILS_H
#define GENERAL_UTILS_H

#include <bpf/bpf.h> 
#include <bpf/libbpf.h> 

#define NR_SYSCALLS 8
#define MAX_PATH_LEN 128
#define MAX_RESTRICTED_FILE_NUM 10
#define MAX_RESTRICTED_EXEC_NUM_PER_FILE 10
#define MAX_RESTRICTED_UID_NUM 10

#define MAX_CMD_LEN 512
#define MAX_LINE_LEN 512

#define NOT_REGISTERED 0
#define DEFAULT_ALLOW 1
#define DEFAULT_DENY  2

#define MAX_TYPE_LEN 10
#define MAX_RESTRICTED_OBJECT_TYPE_NUM 10
#define MAX_TYPE_NUM_PER_FILE 5
#define MAX_FILE_NUM_WITH_OBJECT_TYPE (2 * MAX_RESTRICTED_FILE_NUM)
#define MAX_FILE_NUM_WITH_SUBJECT_TYPE 10
#define MAX_RESTRICTED_SUBJECT_TYPE_NUM_PER_OBJECT_TYPE 10

#define MAX_UID_LEN 10
#define MAX_USERNAME_LEN 64

#define MAX_GROUP_LEN 10
#define MAX_GROUP_NUM_PER_USER 5
#define MAX_UID_NUM_WITH_GROUP 10
#define MAX_RESTRICTED_GROUP_NUM_PER_OBJECT_TYPE 10

#define MAX_TOKEN_NUM 10
#define MAX_ARG_LEN MAX_PATH_LEN


struct my_bpf_data {
    struct bpf_link *link;
    struct bpf_program *prog;
    struct bpf_object *obj;    
};

#endif /* GENERAL_UTILS_H */