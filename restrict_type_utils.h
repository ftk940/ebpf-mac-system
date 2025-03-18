#ifndef RESTRICT_TYPE_UTILS_H
#define RESTRICT_TYPE_UTILS_H

#include "general_utils.h"

void init_type_restriction_map_exec(char permission_type[6], char syscall_name[16], struct my_bpf_data *cur_bpf);
void addrule_type(char syscall_name[16], char object_type[MAX_TYPE_LEN], char subject_type[MAX_TYPE_LEN]);

#endif /* RESTRICT_TYPE_UTILS_H*/