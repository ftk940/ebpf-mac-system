#ifndef RESTRICT_GROUP_UTILS_H
#define RESTRICT_GROUP_UTILS_H

#include "general_utils.h"

int init_uid_to_groups();
void init_group_restriction_map(char permission_type[6], char syscall_name[16], struct my_bpf_data *cur_bpf);
void set_group(char username[MAX_USERNAME_LEN], char group[MAX_GROUP_LEN]);
void unset_group(char username[MAX_USERNAME_LEN], char group[MAX_GROUP_LEN]);
void addrule_group(char syscall_name[16], char object_type[MAX_TYPE_LEN], char group[MAX_GROUP_LEN]);
void delrule_group(char syscall_name[16], char object_type[MAX_TYPE_LEN], char group[MAX_GROUP_LEN]);

#endif /* RESTRICT_GROUP_UTILS_H */