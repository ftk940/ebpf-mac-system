#ifndef RESTRICT_USER_UTILS_H
#define RESTRICT_USER_UTILS_H

#include "general_utils.h"

void init_bpf_prog_user(char syscall_name[16], struct my_bpf_data *cur_bpf);
void addrule_user(char syscall_name[16], char file_path[MAX_PATH_LEN], char username[MAX_USERNAME_LEN]);
void delrule_user(char syscall_name[16], char file_path[MAX_PATH_LEN], char username[MAX_USERNAME_LEN]);

#endif /* RESTRICT_USER_UTILS_H */