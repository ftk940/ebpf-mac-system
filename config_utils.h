#ifndef CONFIG_UTILS_H
#define CONFIG_UTILS_H

#include "general_utils.h"

void delete_config_entry_matching_line(char config_file_path[MAX_PATH_LEN], char del_line[MAX_LINE_LEN]);
void delete_config_entry_matching_token(char config_file_path[MAX_PATH_LEN], char token[MAX_LINE_LEN], int token_idx);
#endif /* CONFIG_UTILS_H */