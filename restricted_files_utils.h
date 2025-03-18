#ifndef RESTRICTED_FILES_UTILS_H
#define RESTRICTED_FILES_UTILS_H

#include "general_utils.h"

int get_file_default_setting(char file_path[MAX_PATH_LEN], char restricted_target[6]);
int init_restricted_files(char default_type[6], char restricted_target[6]);
void register_file(char file_path[MAX_PATH_LEN], char restricted_target[6], char default_type[6]);
void unregister_file(char file_path[MAX_PATH_LEN], char restricted_target[6]);
#endif /* RESTRICTED_FILES_UTILS_H */