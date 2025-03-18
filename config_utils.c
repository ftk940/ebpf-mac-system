#include <stdio.h> // fdopen, fgets, fopen, snprintf
#include <fcntl.h> // open
#include <unistd.h> // close
#include <string.h>
#include <errno.h>
#include "general_utils.h"

#include "config_utils.h"

void delete_config_entry_matching_line(char config_file_path[MAX_PATH_LEN], char del_line[MAX_LINE_LEN]) {
    int rd_fd = open(config_file_path, O_RDONLY);
    FILE *rd_fp = fdopen(rd_fd, "r");
    int wr_fd = open(config_file_path, O_WRONLY);
    FILE *wr_fp = fdopen(wr_fd, "w"); // does not truncate the file

    char line_buf[MAX_LINE_LEN] = "";
    int find_entry = 0;
    while(fgets(line_buf, MAX_LINE_LEN, rd_fp) != NULL) {	
        if(strcmp(line_buf, del_line) == 0) {
            find_entry = 1;
            continue;
        }   
        if(find_entry) 
            fputs(line_buf, wr_fp);
        else {
            int offsets = ftell(rd_fp);
            fseek(wr_fp, offsets, SEEK_SET);
        }        
    }
    fflush(wr_fp);
    ftruncate(wr_fd, lseek(wr_fd, 0, SEEK_CUR)); 
}

void delete_config_entry_matching_token(char config_file_path[MAX_PATH_LEN], char token[MAX_LINE_LEN], int token_idx) {
    int rd_fd = open(config_file_path, O_RDONLY);
    FILE *rd_fp = fdopen(rd_fd, "r");
    int wr_fd = open(config_file_path, O_WRONLY);
    FILE *wr_fp = fdopen(wr_fd, "w"); // does not truncate the file

    char line_buf[MAX_LINE_LEN] = "";
    char line_copy[MAX_LINE_LEN] = "";
    int find_entry = 0;
    while(fgets(line_buf, MAX_LINE_LEN, rd_fp) != NULL) {
        strcpy(line_copy, line_buf);
        char *cur_token = strtok(line_buf, " \n");
        for(int i = 0; i < token_idx; i++)
            cur_token = strtok(NULL, " \n");
        if(strcmp(cur_token, token) == 0) {
            find_entry = 1;
            continue;
        }   
        if(find_entry) 
            fputs(line_copy, wr_fp);
        else {
            int offsets = ftell(rd_fp);
            fseek(wr_fp, offsets, SEEK_SET);
        }        
    }
    fflush(wr_fp);
    ftruncate(wr_fd, lseek(wr_fd, 0, SEEK_CUR)); 
}