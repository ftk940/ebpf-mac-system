#ifndef RESTRICT_EXEC_UTILS_H
#define RESTRICT_EXEC_UTILS_H

#include "general_utils.h"

void init_bpf_prog_exec(char syscall_name[16], struct my_bpf_data *cur_bpf);
void addrule_exec(char syscall_name[16], char file_path[MAX_PATH_LEN], char exec_path[MAX_PATH_LEN]);
void delrule_exec(char syscall_name[16], char file_path[MAX_PATH_LEN], char exec_path[MAX_PATH_LEN]);

#endif /* RESTRICT_EXEC_UTILS_H*/