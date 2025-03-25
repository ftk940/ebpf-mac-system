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

extern FILE* err_fp;

extern int default_allow_object_types_exec_fd;
extern int default_deny_object_types_exec_fd;

extern int path_to_object_types_exec_fd;
extern int path_to_subject_types_fd;

extern int default_allow_object_types_user_fd;
extern int default_deny_object_types_user_fd;

extern int path_to_object_types_user_fd;

extern char all_syscalls[NR_SYSCALLS][16];

int init_restricted_object_types(char default_type[6], char restricted_target[6]) {
    char config_file_path[128] = "";
    snprintf(config_file_path, sizeof(config_file_path), "/home/qwerty/Desktop/bpf_config/default_%s_object_types_%s.config", default_type, restricted_target);
    // S_IROTH | S_IWOTH for debugging
    int fd = open(config_file_path, O_RDONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH);
    FILE *fp = fdopen(fd, "r");  

    char map_name[128] = "";
    snprintf(map_name, sizeof(map_name), "default_%s_object_types_%s", default_type, restricted_target);
    LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = BPF_F_NO_PREALLOC);
    int map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, map_name, sizeof(char[MAX_TYPE_LEN]), sizeof(char),
				                      MAX_RESTRICTED_OBJECT_TYPE_NUM, &opts);

    char pin_path[128] = "";
    snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/%s", map_name);
    int err = bpf_obj_pin(map_fd, pin_path);
    if (err) 
        fprintf(err_fp, "ERROR: failed to pin the map: %s\n", map_name);

    char line_buf[MAX_LINE_LEN] = "";
    char object_type[MAX_TYPE_LEN] = "";
    char val = 1;
    while(fgets(line_buf, MAX_LINE_LEN, fp) != NULL) {
    	char *cur_string = strtok(line_buf, " \n");
    	strncpy(object_type, cur_string, MAX_TYPE_LEN - 1);
        object_type[MAX_TYPE_LEN - 1] = '\0';    
    	bpf_map_update_elem(map_fd, object_type, &val, BPF_ANY);
    }

    return map_fd;         
}

static int create_path_to_types_map(char map_name[128], int entries_cnt) {
    LIBBPF_OPTS(bpf_map_create_opts, opts_inner, .map_flags = BPF_F_NO_PREALLOC);
    int inner_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, NULL, sizeof(char[MAX_TYPE_LEN]), sizeof(char),
				MAX_TYPE_NUM_PER_FILE, &opts_inner);

    LIBBPF_OPTS(bpf_map_create_opts, opts_outer, .inner_map_fd = inner_map_fd, .map_flags = BPF_F_NO_PREALLOC);
    int outer_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH_OF_MAPS,
                        map_name,                           // name 
                        sizeof(char[MAX_PATH_LEN]),         // key size 
                        sizeof(__u32),                      // value size 
                        entries_cnt,            // max entries 
                        &opts_outer);                             // create opts 
    
    close(inner_map_fd);
    return outer_map_fd;
}

static int update_path_to_types_map(int outer_map_fd, char file_path[MAX_PATH_LEN], char type[MAX_TYPE_LEN]) {
    int err, inner_map_id, inner_map_fd;

    err = bpf_map_lookup_elem(outer_map_fd, file_path, &inner_map_id);

    if(err < 0) {
        fprintf(err_fp, "inner map for %s does not exist\n", file_path);
        LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = BPF_F_NO_PREALLOC);
        inner_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, NULL, sizeof(char[MAX_TYPE_LEN]), sizeof(char),
				                      MAX_TYPE_NUM_PER_FILE, &opts);
        if(inner_map_fd < 0) {
            fprintf(err_fp, "inner map creation fails\n");
            return -1;
        }
        
        err = bpf_map_update_elem(outer_map_fd, file_path, &inner_map_fd, BPF_ANY);
        if(err < 0) {
            if(errno == E2BIG) 
                fprintf(err_fp, "outer map is full, ");
            fprintf(err_fp, "fail to update outer map\n");
            return -1;
        }

        bpf_map_lookup_elem(outer_map_fd, file_path, &inner_map_id);
        fprintf(err_fp, "inner map for %s is created\n", file_path);
    }

    inner_map_fd = bpf_map_get_fd_by_id(inner_map_id);
    char val = 1;
    err = bpf_map_update_elem(inner_map_fd, type, &val, BPF_ANY);
    if(err < 0) {
        if(errno == E2BIG) 
            fprintf(err_fp, "inner map is full, ");
        fprintf(err_fp, "fail to update inner map\n");
        return -1;
    }    
    return 0;
}

int init_path_to_types(char entity_type[10], char restricted_target[6]) {
    char config_file_path[128] = "";
    if(strcmp(entity_type, "object") == 0)
        snprintf(config_file_path, sizeof(config_file_path), "/home/qwerty/Desktop/bpf_config/path_to_object_types_%s.config", restricted_target);
    else
        snprintf(config_file_path, sizeof(config_file_path), "/home/qwerty/Desktop/bpf_config/path_to_subject_types.config");
    // S_IROTH | S_IWOTH for debugging
    int fd = open(config_file_path, O_RDONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH);
    FILE *fp = fdopen(fd, "r");

    char map_name[128] = "";
    int map_fd;
    if(strcmp(entity_type, "object") == 0) {
        snprintf(map_name, sizeof(map_name), "path_to_object_types_%s", restricted_target);
        map_fd = create_path_to_types_map(map_name, MAX_FILE_NUM_WITH_OBJECT_TYPE);
    }          
    else {
        snprintf(map_name, sizeof(map_name), "path_to_subject_types");
        map_fd = create_path_to_types_map(map_name, MAX_FILE_NUM_WITH_SUBJECT_TYPE);
    }

    char pin_path[128] = "";
    snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/%s", map_name);
    int err = bpf_obj_pin(map_fd, pin_path);
    if (err) 
        fprintf(err_fp, "ERROR: failed to pin the map: %s\n", map_name);

    char line_buf[MAX_LINE_LEN] = "";
    char file_path[MAX_PATH_LEN] = "";
    char type[MAX_TYPE_LEN] = ""; 
    while(fgets(line_buf, MAX_LINE_LEN, fp) != NULL) {
    	int token_id = 0;
    	char *cur_string = strtok(line_buf, " \n");
    	while(cur_string != NULL) {
    	    if(token_id == 0)
    	    	strncpy(file_path, cur_string, MAX_PATH_LEN);
    	    else
    	    	strncpy(type, cur_string, MAX_TYPE_LEN);
    	    token_id++;
    	    cur_string = strtok(NULL, " \n");   
    	}
    	update_path_to_types_map(map_fd, file_path, type);
    }

    return map_fd;  
}

int get_type_default_setting(char object_type[MAX_TYPE_LEN], char restricted_target[6]) {
    int ret;
    char v;
    int default_allow_object_types_fd, default_deny_object_types_fd;
    if(strcmp(restricted_target, "exec") == 0) {
        default_allow_object_types_fd = default_allow_object_types_exec_fd;
        default_deny_object_types_fd = default_deny_object_types_exec_fd;
    }
    else {
        default_allow_object_types_fd = default_allow_object_types_user_fd;
        default_deny_object_types_fd = default_deny_object_types_user_fd;
    }

    ret = bpf_map_lookup_elem(default_allow_object_types_fd, object_type, &v);
    if(ret == 0)
        return DEFAULT_ALLOW;

    ret = bpf_map_lookup_elem(default_deny_object_types_fd, object_type, &v);
    if(ret == 0)
        return DEFAULT_DENY;
    
    return NOT_REGISTERED;
}

static void add_config_entry_default_type(char default_type[6], char restricted_target[6], char object_type[MAX_TYPE_LEN]) {
    char config_file_path[128] = "";
    snprintf(config_file_path, sizeof(config_file_path), "/home/qwerty/Desktop/bpf_config/default_%s_object_types_%s.config",default_type, restricted_target);
    FILE *fp = fopen(config_file_path, "a");
    fprintf(fp, "%s\n", object_type);
    fclose(fp);
}

void register_object_type(char object_type[MAX_TYPE_LEN], char restricted_target[6], char default_type[6]) {
    int default_setting = get_type_default_setting(object_type, restricted_target);
    if(default_setting == DEFAULT_ALLOW) {
        fprintf(err_fp, "type: %s has been registered in default_allow_object_types_%s\n", object_type, restricted_target);
        return;
    }
    if(default_setting == DEFAULT_DENY) {
        fprintf(err_fp, "type: %s has been registered in default_deny_object_types_%s\n", object_type, restricted_target);
        return;        
    }

    int map_fd;
    if(strcmp(restricted_target, "exec") == 0) {
        if(strcmp(default_type, "allow") == 0)
            map_fd = default_allow_object_types_exec_fd;
        else
            map_fd = default_deny_object_types_exec_fd; 
    }     
    else {
        if(strcmp(default_type, "allow") == 0)
            map_fd = default_allow_object_types_user_fd;
        else
            map_fd = default_deny_object_types_user_fd;
    }

    char val = 1;
    int err = bpf_map_update_elem(map_fd, object_type, &val, BPF_ANY);
    if(err < 0) {
        if(errno == E2BIG) 
            fprintf(err_fp, "default_%s_object_types_%s is full\n", default_type, restricted_target);
        return;
    } 
    add_config_entry_default_type(default_type, restricted_target, object_type);      
}


static void delete_config_entry_default_type(char default_type[6], char restricted_target[6], char object_type[MAX_TYPE_LEN]) {
    char config_file_path[128] = "";
    snprintf(config_file_path, sizeof(config_file_path), "/home/qwerty/Desktop/bpf_config/default_%s_object_types_%s.config",default_type, restricted_target);

    char del_line[MAX_LINE_LEN] = "";
    snprintf(del_line, sizeof(del_line), "%s\n", object_type);

    delete_config_entry_matching_line(config_file_path, del_line);
}

static void delete_object_type_from_config_restriction_map(char permission_type[6], char restricted_target[6], char syscall_name[16], char object_type[MAX_TYPE_LEN]) {
    char config_file_path[128] = "";
    snprintf(config_file_path, sizeof(config_file_path), "/home/qwerty/Desktop/bpf_config/%s_%s_%s_map.config",
             permission_type, restricted_target, syscall_name);

    delete_config_entry_matching_token(config_file_path, object_type, 0);            
}
            
static void delete_object_type_from_config_path_to_types(char restricted_target[6], char object_type[MAX_TYPE_LEN]) {
    char config_file_path[128] = "";
    snprintf(config_file_path, sizeof(config_file_path), "/home/qwerty/Desktop/bpf_config/path_to_object_types_%s.config"
            , restricted_target);

    delete_config_entry_matching_token(config_file_path, object_type, 1);      
}

void unregister_object_type(char object_type[MAX_TYPE_LEN], char restricted_target[6]) {
    int default_setting = get_type_default_setting(object_type, restricted_target);
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
        fprintf(err_fp, "object type: %s has not been registered yet\n", object_type);
        return;
    }

    int err = 0;
    char pin_path[128] = "";
    snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/default_%s_object_types_%s", default_type, restricted_target);
    int map_fd = bpf_obj_get(pin_path);
    //TODO: change cond from (map_fd != -1) to (map_fd >= 0), print error msg when map_fd < 0
    if(map_fd >= 0) {
        err = bpf_map_delete_elem(map_fd, object_type);
        if(err == 0) 
            delete_config_entry_default_type(default_type, restricted_target, object_type);
    }

    char restricted_target_type[6] = "";
    if(strcmp(restricted_target, "exec") == 0)
        strcpy(restricted_target_type, "type");
    else 
        strcpy(restricted_target_type, "group");
    for(int i = 0; i < NR_SYSCALLS; i++) {
        snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/restrict_%s_%s/%s_%s_%s_map", 
                restricted_target, all_syscalls[i], permission_type, restricted_target_type, all_syscalls[i]);
        map_fd = bpf_obj_get(pin_path);
        if(map_fd >= 0) {
            err = bpf_map_delete_elem(map_fd, object_type);
            if(err == 0) 
                delete_object_type_from_config_restriction_map(permission_type, restricted_target_type, all_syscalls[i], object_type);
        }
    }

    snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/path_to_object_types_%s", restricted_target);
    int outer_map_fd = bpf_obj_get(pin_path);
    if(outer_map_fd >= 0) {
        char key[2][MAX_PATH_LEN] = {};
        int idx = 0;
        int inner_map_id, inner_map_fd;
        while((bpf_map_get_next_key(outer_map_fd, key[idx], key[idx^1])) == 0) {
            idx ^= 1;
            bpf_map_lookup_elem(outer_map_fd, key[idx], &inner_map_id);
            inner_map_fd = bpf_map_get_fd_by_id(inner_map_id);
            err = bpf_map_delete_elem(inner_map_fd, object_type);
            if(err == 0) 
                fprintf(err_fp, "delete entry: %s %s\n", key[idx], object_type);
        }
        delete_object_type_from_config_path_to_types(restricted_target, object_type);          
    } 
}

static void add_config_entry_path_to_types(char entity_type[10],char file_path[MAX_PATH_LEN], char type[MAX_TYPE_LEN], char restricted_target[6]) {
    char config_file_path[128] = "";
    if(strcmp(entity_type, "object") == 0)
        snprintf(config_file_path, sizeof(config_file_path), "/home/qwerty/Desktop/bpf_config/path_to_object_types_%s.config", restricted_target);
    else
        snprintf(config_file_path, sizeof(config_file_path), "/home/qwerty/Desktop/bpf_config/path_to_subject_types.config");
    FILE *fp = fopen(config_file_path, "a");
    fprintf(fp, "%s %s\n", file_path, type);
    fclose(fp);
}

void set_type(char entity_type[10], char file_path[MAX_PATH_LEN], char type[MAX_TYPE_LEN], char restricted_target[6]) {
    if(strcmp(entity_type, "object") == 0) {
        int file_default_setting = get_file_default_setting(file_path, restricted_target);
        int type_default_setting = get_type_default_setting(type, restricted_target);
        if(file_default_setting == NOT_REGISTERED) {
            fprintf(err_fp, "file: %s hasn't be registered yet.\n", file_path);
            return;        
        }

        if(type_default_setting == NOT_REGISTERED) {
            fprintf(err_fp, "type: %s hasn't be registered yet.\n", type);
            return;         
        }

        if(file_default_setting != type_default_setting) {
            fprintf(err_fp, "default settings do not match.\n");
            return; 
        }
    }

    int map_fd;
    if(strcmp(entity_type, "subject") == 0)
        map_fd = path_to_subject_types_fd;
    else if(strcmp(restricted_target, "exec") == 0)
        map_fd = path_to_object_types_exec_fd;
    else
        map_fd = path_to_object_types_user_fd;
    int err = update_path_to_types_map(map_fd, file_path, type);
    if(err < 0)
        return;
    add_config_entry_path_to_types(entity_type, file_path, type, restricted_target);
}

static void delete_config_entry_path_to_types(char entity_type[10],char file_path[MAX_PATH_LEN], char type[MAX_TYPE_LEN], char restricted_target[6]) {
    char config_file_path[128] = "";
    if(strcmp(entity_type, "object") == 0)
        snprintf(config_file_path, sizeof(config_file_path), "/home/qwerty/Desktop/bpf_config/path_to_object_types_%s.config", restricted_target);
    else
        snprintf(config_file_path, sizeof(config_file_path), "/home/qwerty/Desktop/bpf_config/path_to_subject_types.config");

    char del_line[MAX_LINE_LEN] = "";
    snprintf(del_line, sizeof(del_line), "%s %s\n", file_path, type);

    delete_config_entry_matching_line(config_file_path, del_line);  
}

void unset_type(char entity_type[10], char file_path[MAX_PATH_LEN], char type[MAX_TYPE_LEN], char restricted_target[6]) {
    if(strcmp(entity_type, "object") == 0) {
        int file_default_setting = get_file_default_setting(file_path, restricted_target);
        int type_default_setting = get_type_default_setting(type, restricted_target);
        if(file_default_setting == NOT_REGISTERED) {
            fprintf(err_fp, "file: %s hasn't be registered yet.\n", file_path);
            return;        
        }

        if(type_default_setting == NOT_REGISTERED) {
            fprintf(err_fp, "type: %s hasn't be registered yet.\n", type);
            return;         
        }

        if(file_default_setting != type_default_setting) {
            fprintf(err_fp, "default settings do not match.\n");
            return; 
        }
    }

    int outer_map_fd;
    if(strcmp(entity_type, "subject") == 0)
        outer_map_fd = path_to_subject_types_fd;
    else if(strcmp(restricted_target, "exec") == 0)
        outer_map_fd = path_to_object_types_exec_fd;
    else
        outer_map_fd = path_to_object_types_user_fd;

    int err, inner_map_id, inner_map_fd;
    err = bpf_map_lookup_elem(outer_map_fd, file_path, &inner_map_id);
    if(err < 0) {
        fprintf(err_fp, "inner map for %s does not exist\n", file_path);
        return;
    }

    inner_map_fd = bpf_map_get_fd_by_id(inner_map_id);
    err = bpf_map_delete_elem(inner_map_fd, type);
    if(err < 0) {
        fprintf(err_fp, "%s is not of type: %s\n", file_path, type);
        return;
    }

    delete_config_entry_path_to_types(entity_type, file_path, type, restricted_target);
}