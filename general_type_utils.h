#ifndef GENERAL_TYPE_UTILS_H
#define GENERAL_TYPE_UTILS_H

#include "general_utils.h"

int init_restricted_object_types(char default_type[6], char restricted_target[6]);
int init_path_to_types(char entity_type[10], char restricted_target[6]);
int get_type_default_setting(char object_type[MAX_TYPE_LEN], char restricted_target[6]);
void register_object_type(char object_type[MAX_TYPE_LEN], char restricted_target[6], char default_type[6]);
void unregister_object_type(char object_type[MAX_TYPE_LEN], char restricted_target[6]);
void set_type(char entity_type[10], char file_path[MAX_PATH_LEN], char type[MAX_TYPE_LEN], char restricted_target[6]);
void unset_type(char entity_type[10], char file_path[MAX_PATH_LEN], char type[MAX_TYPE_LEN], char restricted_target[6]);
#endif /* GENERAL_TYPE_UTILS_H */