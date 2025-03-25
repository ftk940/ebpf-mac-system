#include <bpf/bpf.h> // bpf_map_create
#include <bpf/libbpf.h> // bpf_map__reuse_fd
#include <stdio.h> // fdopen, fgets, fopen, snprintf
#include <fcntl.h> // open
#include <unistd.h> // close
#include <string.h>
#include <errno.h>
#include "general_utils.h"
#include "config_utils.h"
#include "restricted_files_utils.h"
#include "general_type_utils.h"

#include "restrict_type_utils.h"

extern FILE *err_fp;

static int update_type_restriction_map_exec(int outer_map_fd, char object_type[MAX_TYPE_LEN], char subject_type[MAX_TYPE_LEN]) {
    int err, inner_map_id, inner_map_fd;

    err = bpf_map_lookup_elem(outer_map_fd, object_type, &inner_map_id);

    if(err < 0) {
        fprintf(err_fp, "inner map for type:%s does not exist\n", object_type);
        LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = BPF_F_NO_PREALLOC);
        inner_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, NULL, sizeof(char[MAX_TYPE_LEN]), sizeof(char),
				                      MAX_RESTRICTED_SUBJECT_TYPE_NUM_PER_OBJECT_TYPE, &opts);
        if(inner_map_fd < 0) {
            fprintf(err_fp, "inner map creation fails\n");
            return -1;
        }

        err = bpf_map_update_elem(outer_map_fd, object_type, &inner_map_fd, BPF_ANY);
        if(err < 0) {
            if(errno == E2BIG) 
                fprintf(err_fp, "outer map is full, ");
            fprintf(err_fp, "fail to update outer map\n");
            return -1;
        }

        bpf_map_lookup_elem(outer_map_fd, object_type, &inner_map_id);
        fprintf(err_fp, "inner map for type:%s is created\n", object_type);
    }

    inner_map_fd = bpf_map_get_fd_by_id(inner_map_id);
    char val = 1;
    err = bpf_map_update_elem(inner_map_fd, subject_type, &val, BPF_ANY);
    if(err < 0) {
        if(errno == E2BIG) 
            fprintf(err_fp, "inner map is full, ");
        fprintf(err_fp, "fail to update inner map\n");
        return -1;
    }    
    return 0;
}

void init_type_restriction_map_exec(char permission_type[6], char syscall_name[16], struct my_bpf_data *cur_bpf) {
    char config_file_path[128] = "";
    snprintf(config_file_path, sizeof(config_file_path), "/home/qwerty/Desktop/bpf_config/%s_type_%s_map.config", permission_type, syscall_name);
    // S_IROTH | S_IWOTH for debugging
    int fd = open(config_file_path, O_RDONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH);
    FILE *fp = fdopen(fd, "r");

    char map_name[128] = "";
    snprintf(map_name, sizeof(map_name), "%s_type_%s_map", permission_type, syscall_name);
    struct bpf_map *map = bpf_object__find_map_by_name(cur_bpf->obj, map_name);
    int map_fd = bpf_map__fd(map);

    char pin_path[128] = "";
    snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/restrict_exec_%s/%s", syscall_name, map_name);
    int err = bpf_obj_pin(map_fd, pin_path);
    if (err) 
        fprintf(err_fp, "ERROR: failed to pin the map: %s\n", map_name);

    char line_buf[MAX_LINE_LEN] = "";
    char object_type[MAX_TYPE_LEN] = "";
    char subject_type[MAX_TYPE_LEN] = ""; 
    while(fgets(line_buf, MAX_LINE_LEN, fp) != NULL) {
    	int token_id = 0;
    	char *cur_string = strtok(line_buf, " \n");
    	while(cur_string != NULL) {
    	    if(token_id == 0)
    	    	strncpy(object_type, cur_string, MAX_TYPE_LEN);
    	    else
    	    	strncpy(subject_type, cur_string, MAX_TYPE_LEN);
    	    token_id++;
    	    cur_string = strtok(NULL, " \n");   
    	}
    	update_type_restriction_map_exec(map_fd, object_type, subject_type);
    }  
}

static void add_config_entry_restriction_map_type(char permission_type[6], char syscall_name[16], char object_type[MAX_TYPE_LEN], char subject_type[MAX_TYPE_LEN]) {
    char config_file_path[128] = "";
    snprintf(config_file_path, sizeof(config_file_path), "/home/qwerty/Desktop/bpf_config/%s_type_%s_map.config",permission_type, syscall_name);
    FILE *fp = fopen(config_file_path, "a");
    fprintf(fp, "%s %s\n", object_type, subject_type);
    fclose(fp);
}

void addrule_type(char syscall_name[16], char object_type[MAX_TYPE_LEN], char subject_type[MAX_TYPE_LEN]) {
    int default_setting = get_type_default_setting(object_type, "exec");
    char permission_type[6] = "";
    if(default_setting == DEFAULT_ALLOW)
        strcpy(permission_type, "deny");
    else if(default_setting == DEFAULT_DENY)
        strcpy(permission_type, "allow");
    else {
        fprintf(err_fp, "type: %s has not been registered yet\n", object_type);
        return;
    }
    
    //TODO: check subject type exist

    char map_name[128] = "";
    snprintf(map_name, sizeof(map_name), "%s_type_%s_map", permission_type, syscall_name);
    //struct bpf_map *map = NULL;

    char pin_path[128] = "";
    snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/restrict_exec_%s/%s", syscall_name, map_name);
    int map_fd = bpf_obj_get(pin_path);
    if (map_fd < 0) 
        fprintf(err_fp, "ERROR: failed to get the map: %s\n", map_name);

    int err = update_type_restriction_map_exec(map_fd, object_type, subject_type);
    if(err < 0)
        return;
    add_config_entry_restriction_map_type(permission_type, syscall_name, object_type, subject_type);       
}

static void delete_config_entry_restriction_map_type(char permission_type[6], char syscall_name[16], char object_type[MAX_TYPE_LEN], char subject_type[MAX_TYPE_LEN]) {
    char config_file_path[128] = "";
    snprintf(config_file_path, sizeof(config_file_path), "/home/qwerty/Desktop/bpf_config/%s_type_%s_map.config",permission_type, syscall_name);

    char del_line[MAX_LINE_LEN] = "";
    snprintf(del_line, sizeof(del_line), "%s %s\n", object_type, subject_type);

    delete_config_entry_matching_line(config_file_path, del_line);
}

void delrule_type(char syscall_name[16], char object_type[MAX_TYPE_LEN], char subject_type[MAX_TYPE_LEN]) {
    int default_setting = get_type_default_setting(object_type, "exec");
    char permission_type[6] = "";
    if(default_setting == DEFAULT_ALLOW)
        strcpy(permission_type, "deny");
    else if(default_setting == DEFAULT_DENY)
        strcpy(permission_type, "allow");
    else {
        fprintf(err_fp, "type: %s has not been registered yet\n", object_type);
        return;
    }
    
    //TODO: check subject type exist

    char map_name[128] = "";
    snprintf(map_name, sizeof(map_name), "%s_type_%s_map", permission_type, syscall_name);
    //struct bpf_map *map = NULL;

    char pin_path[128] = "";
    snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/restrict_exec_%s/%s", syscall_name, map_name);
    int outer_map_fd = bpf_obj_get(pin_path);
    if (outer_map_fd < 0) 
        fprintf(err_fp, "ERROR: failed to get the map: %s\n", map_name);
    
    int err, inner_map_id, inner_map_fd;
    err = bpf_map_lookup_elem(outer_map_fd, object_type, &inner_map_id);
    if(err < 0) {
        fprintf(err_fp, "inner map for %s does not exist\n", object_type);
        return;
    }

    inner_map_fd = bpf_map_get_fd_by_id(inner_map_id);
    err = bpf_map_delete_elem(inner_map_fd, subject_type);
    if(err < 0) {
        fprintf(err_fp, "subject type: %s is not restricted by the rule\n", subject_type);
        return;
    }

    delete_config_entry_restriction_map_type(permission_type, syscall_name, object_type, subject_type);
}