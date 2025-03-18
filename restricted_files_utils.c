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

extern FILE *err_fp;

extern int default_allow_files_exec_fd;
extern int default_deny_files_exec_fd;
extern int default_allow_files_user_fd;
extern int default_deny_files_user_fd;
extern char all_syscalls[NR_SYSCALLS][16];

int get_file_default_setting(char file_path[MAX_PATH_LEN], char restricted_target[6]) {
    int ret;
    char v;
    int default_allow_files_fd, default_deny_files_fd;
    if(strcmp(restricted_target, "exec") == 0) {
        default_allow_files_fd = default_allow_files_exec_fd;
        default_deny_files_fd = default_deny_files_exec_fd;
    }
    else {
        default_allow_files_fd = default_allow_files_user_fd;
        default_deny_files_fd = default_deny_files_user_fd;
    }

    ret = bpf_map_lookup_elem(default_allow_files_fd, file_path, &v);
    if(ret == 0)
        return DEFAULT_ALLOW;

    ret = bpf_map_lookup_elem(default_deny_files_fd, file_path, &v);
    if(ret == 0)
        return DEFAULT_DENY;
    
    return NOT_REGISTERED;
}


int init_restricted_files(char default_type[6], char restricted_target[6]) {
    char config_file_path[128] = "";
    snprintf(config_file_path, sizeof(config_file_path), "/home/qwerty/Desktop/bpf_config/default_%s_files_%s.config", default_type, restricted_target);
    // S_IROTH | S_IWOTH for debugging
    int fd = open(config_file_path, O_RDONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH);
    FILE *fp = fdopen(fd, "r");  

    char map_name[128] = "";
    snprintf(map_name, sizeof(map_name), "default_%s_files_%s", default_type, restricted_target);
    LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = BPF_F_NO_PREALLOC);
    int map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, map_name, sizeof(char[MAX_PATH_LEN]), sizeof(char),
				                      MAX_RESTRICTED_FILE_NUM, &opts);

    char pin_path[128] = "";
    snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/%s", map_name);
    int err = bpf_obj_pin(map_fd, pin_path);
    if (err) 
        fprintf(err_fp, "ERROR: failed to pin the map: %s\n", map_name);

    char line_buf[MAX_LINE_LEN] = "";
    char file_path[MAX_PATH_LEN] = "";
    char val = 1;
    while(fgets(line_buf, MAX_LINE_LEN, fp) != NULL) {
    	char *cur_path = strtok(line_buf, " \n");
    	strncpy(file_path, cur_path, MAX_PATH_LEN - 1);
        file_path[MAX_PATH_LEN - 1] = '\0';   
    	bpf_map_update_elem(map_fd, file_path, &val, BPF_ANY);
    }

    return map_fd;         
}

static void add_entry_to_config_file_default(char default_type[6], char restricted_target[6], char file_path[MAX_PATH_LEN]) {
    char config_file_path[128] = "";
    snprintf(config_file_path, sizeof(config_file_path), "/home/qwerty/Desktop/bpf_config/default_%s_files_%s.config",default_type, restricted_target);
    FILE *fp = fopen(config_file_path, "a");
    fprintf(fp, "%s\n", file_path);
    fclose(fp);
}


void register_file(char file_path[MAX_PATH_LEN], char restricted_target[6], char default_type[6]) {
    int default_setting = get_file_default_setting(file_path, restricted_target);
    if(default_setting == DEFAULT_ALLOW) {
        fprintf(err_fp, "file: %s has been registered in default_allow_files_%s\n", file_path, restricted_target);
        return;
    }
    if(default_setting == DEFAULT_DENY) {
        fprintf(err_fp, "file: %s has been registered in default_deny_files_%s\n", file_path, restricted_target);
        return;        
    }

    int map_fd;
    if(strcmp(restricted_target, "exec") == 0) {
        if(strcmp(default_type, "allow") == 0) 
            map_fd = default_allow_files_exec_fd;
        else 
            map_fd = default_deny_files_exec_fd;
    }
    else {
        if(strcmp(default_type, "allow") == 0) 
            map_fd = default_allow_files_user_fd;
        else 
            map_fd = default_deny_files_user_fd;                  
    }

    char val = 1;
    int err = bpf_map_update_elem(map_fd, file_path, &val, BPF_ANY);
    if(err < 0) {
        if(errno == E2BIG) 
            fprintf(err_fp, "default_%s_files_%s is full\n", default_type, restricted_target);
        return;
    } 
    add_entry_to_config_file_default(default_type, restricted_target, file_path);      
}

static void delete_file_from_config_default(char default_type[6], char restricted_target[6], char file_path[MAX_PATH_LEN]) {
    char config_file_path[128] = "";
    snprintf(config_file_path, sizeof(config_file_path), "/home/qwerty/Desktop/bpf_config/default_%s_files_%s.config",default_type, restricted_target);
    char del_line[MAX_LINE_LEN] = "";
    snprintf(del_line, sizeof(del_line), "%s\n", file_path);

    delete_config_entry_matching_line(config_file_path, del_line);
}

static void delete_file_from_config_restriction_map(char permission_type[6], char restricted_target[6], char syscall_name[16], char file_path[MAX_PATH_LEN]) {
    char config_file_path[128] = "";
    snprintf(config_file_path, sizeof(config_file_path), "/home/qwerty/Desktop/bpf_config/%s_%s_%s_map.config",
             permission_type, restricted_target, syscall_name);

    delete_config_entry_matching_token(config_file_path, file_path, 0);            
}

static void delete_file_from_config_path_to_types(char entity_type[10], char restricted_target[6], char file_path[MAX_PATH_LEN]) {
    char config_file_path[128] = "";
    snprintf(config_file_path, sizeof(config_file_path), "/home/qwerty/Desktop/bpf_config/path_to_%s_types_%s.config",
             entity_type, restricted_target);

    delete_config_entry_matching_token(config_file_path, file_path, 0);      
}

void unregister_file(char file_path[MAX_PATH_LEN], char restricted_target[6]) {
    int default_setting = get_file_default_setting(file_path, restricted_target);
    char default_type[6] = "";
    char permission_type[6] = "";
    if(default_setting == DEFAULT_ALLOW) {
        strcpy(default_type, "allow");
        strcpy(permission_type, "deny");
    }
    else if(default_setting == DEFAULT_DENY) {
        strcpy(default_type, "deny");
        strcpy(permission_type, "allow");
    }
    else {
        fprintf(err_fp, "file: %s has not been registered yet\n", file_path);
        return;
    }

    int err = 0;
    char map_path[128] = "";
    snprintf(map_path, sizeof(map_path), "/sys/fs/bpf/default_%s_files_%s", default_type, restricted_target);
    int map_fd = bpf_obj_get(map_path);
    if(map_fd != -1) {
        err = bpf_map_delete_elem(map_fd, file_path);
        if(err == 0) 
            delete_file_from_config_default(default_type, restricted_target, file_path);
    }

    for(int i = 0; i < NR_SYSCALLS; i++) {
        snprintf(map_path, sizeof(map_path), "/sys/fs/bpf/restrict_%s_%s/%s_%s_%s_map", 
                restricted_target, all_syscalls[i], permission_type, restricted_target, all_syscalls[i]);
        map_fd = bpf_obj_get(map_path);
        if(map_fd != -1) {
            err = bpf_map_delete_elem(map_fd, file_path);
            if(err == 0) 
                delete_file_from_config_restriction_map(permission_type, restricted_target, all_syscalls[i], file_path);
        }
    }

    snprintf(map_path, sizeof(map_path), "/sys/fs/bpf/path_to_object_types_%s", restricted_target);
    map_fd = bpf_obj_get(map_path);
    if(map_fd != -1) {
        err = bpf_map_delete_elem(map_fd, file_path);
        if(err == 0) 
            delete_file_from_config_path_to_types("object", restricted_target, file_path);
    }    
}