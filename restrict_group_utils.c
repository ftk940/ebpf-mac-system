#include <bpf/bpf.h> // bpf_map_create
#include <bpf/libbpf.h> // bpf_map__reuse_fd
#include <stdio.h> // fdopen, fgets, fopen, snprintf
#include <fcntl.h> // creat
#include <unistd.h> // close
#include <string.h>
#include <stdlib.h> //atoi
#include <errno.h>
#include "general_utils.h"
#include "general_user_utils.h"
#include "general_type_utils.h"

#include "restrict_group_utils.h"

extern FILE *err_fp;

extern struct my_bpf_data restrict_user_read_data;

extern int uid_to_groups_fd;

static int create_uid_to_groups_map() {
    LIBBPF_OPTS(bpf_map_create_opts, opts_inner, .map_flags = BPF_F_NO_PREALLOC);
    int inner_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, NULL, sizeof(char[MAX_GROUP_LEN]), sizeof(char),
				MAX_GROUP_NUM_PER_USER, &opts_inner);

    LIBBPF_OPTS(bpf_map_create_opts, opts_outer, .inner_map_fd = inner_map_fd, .map_flags = BPF_F_NO_PREALLOC);
    int outer_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH_OF_MAPS,
                        "uid_to_groups",                           // name 
                        sizeof(int),         // key size 
                        sizeof(__u32),                      // value size 
                        MAX_UID_NUM_WITH_GROUP,            // max entries 
                        &opts_outer);                             // create opts 
    
    close(inner_map_fd);
    return outer_map_fd;
}

static int update_uid_to_groups_map(int outer_map_fd, int uid, char group[MAX_GROUP_LEN]) {
    int err, inner_map_id, inner_map_fd;

    err = bpf_map_lookup_elem(outer_map_fd, &uid, &inner_map_id);

    if(err < 0) {
        fprintf(err_fp, "inner map for uid: %d does not exist\n", uid);
        LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = BPF_F_NO_PREALLOC);
        inner_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, NULL, sizeof(char[MAX_GROUP_LEN]), sizeof(char),
				                      MAX_GROUP_NUM_PER_USER, &opts);
        if(inner_map_fd < 0) {
            fprintf(err_fp, "inner map creation fails\n");
            return -1;
        }        

        err = bpf_map_update_elem(outer_map_fd, &uid, &inner_map_fd, BPF_ANY);
        if(err < 0) {
            if(errno == E2BIG) 
                fprintf(err_fp, "outer map is full, ");
            fprintf(err_fp, "fail to update outer map\n");
            return -1;
        }

        bpf_map_lookup_elem(outer_map_fd, &uid, &inner_map_id);
        fprintf(err_fp, "inner map for uid: %d is created\n", uid);
    }

    inner_map_fd = bpf_map_get_fd_by_id(inner_map_id);
    char val = 1;
    err = bpf_map_update_elem(inner_map_fd, group, &val, BPF_ANY);
    if(err < 0) {
        if(errno == E2BIG) 
            fprintf(err_fp, "inner map is full, ");
        fprintf(err_fp, "fail to update inner map\n");
        return -1;
    }    
    return 0;
}

int init_uid_to_groups() {
    char config_file_path[128] = "";
    snprintf(config_file_path, sizeof(config_file_path), "/home/qwerty/Desktop/bpf_config/uid_to_groups.config");
    // S_IROTH | S_IWOTH for debugging
    int fd = open(config_file_path, O_RDONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH);
    FILE *fp = fdopen(fd, "r");

    int map_fd = create_uid_to_groups_map();

    char pin_path[128] = "/sys/fs/bpf/uid_to_groups";
    int err = bpf_obj_pin(map_fd, pin_path);
    if (err) 
        fprintf(err_fp, "ERROR: failed to pin the map: uid_to_groups\n");

    char line_buf[MAX_LINE_LEN] = "";
    char uid_string[MAX_UID_LEN] = "";
    int uid;
    char group[MAX_GROUP_LEN] = ""; 
    while(fgets(line_buf, MAX_LINE_LEN, fp) != NULL) {
    	int token_id = 0;
    	char *cur_string = strtok(line_buf, " \n");
    	while(cur_string != NULL) {
    	    if(token_id == 0)
    	    	strncpy(uid_string, cur_string, MAX_UID_LEN);
    	    else
    	    	strncpy(group, cur_string, MAX_GROUP_LEN);
    	    token_id++;
    	    cur_string = strtok(NULL, " \n");   
    	}
        uid = atoi(uid_string);
    	update_uid_to_groups_map(map_fd, uid, group);
    }

    return map_fd;  
}

static int update_group_restriction_map(int outer_map_fd, char object_type[MAX_TYPE_LEN], char group[MAX_GROUP_LEN]) {
    int err, inner_map_id, inner_map_fd;

    err = bpf_map_lookup_elem(outer_map_fd, object_type, &inner_map_id);

    if(err < 0) {
        fprintf(err_fp, "inner map for type:%s does not exist\n", object_type);
        LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = BPF_F_NO_PREALLOC);
        inner_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, NULL, sizeof(char[MAX_GROUP_LEN]), sizeof(char),
				                      MAX_RESTRICTED_GROUP_NUM_PER_OBJECT_TYPE, &opts);
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
    err = bpf_map_update_elem(inner_map_fd, group, &val, BPF_ANY);
    if(err < 0) {
        if(errno == E2BIG) 
            fprintf(err_fp, "inner map is full, ");
        fprintf(err_fp, "fail to update inner map\n");
        return -1;
    }    
    return 0;
}

void init_group_restriction_map(char permission_type[6], char syscall_name[16], struct my_bpf_data *cur_bpf) {
    char config_file_path[128] = "";
    snprintf(config_file_path, sizeof(config_file_path), "/home/qwerty/Desktop/bpf_config/%s_group_%s_map.config", permission_type, syscall_name);
    // S_IROTH | S_IWOTH for debugging
    int fd = open(config_file_path, O_RDONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH);
    FILE *fp = fdopen(fd, "r");

    char map_name[128] = "";
    snprintf(map_name, sizeof(map_name), "%s_group_%s_map", permission_type, syscall_name);
    struct bpf_map *map = bpf_object__find_map_by_name(cur_bpf->obj, map_name);
    int map_fd = bpf_map__fd(map);

    char pin_path[128] = "";
    snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/restrict_user_%s/%s", syscall_name, map_name);
    int err = bpf_obj_pin(map_fd, pin_path);
    if (err) 
        fprintf(err_fp, "ERROR: failed to pin the map: %s\n", map_name);

    char line_buf[MAX_LINE_LEN] = "";
    char object_type[MAX_TYPE_LEN] = "";
    char group[MAX_GROUP_LEN] = ""; 
    while(fgets(line_buf, MAX_LINE_LEN, fp) != NULL) {
    	int token_id = 0;
    	char *cur_string = strtok(line_buf, " \n");
    	while(cur_string != NULL) {
    	    if(token_id == 0)
    	    	strncpy(object_type, cur_string, MAX_TYPE_LEN);
    	    else
    	    	strncpy(group, cur_string, MAX_GROUP_LEN);
    	    token_id++;
    	    cur_string = strtok(NULL, " \n");   
    	}
    	update_group_restriction_map(map_fd, object_type, group);
    }  
}

static void add_entry_to_config_file_group_set(int uid, char group[MAX_GROUP_LEN]) {
    char config_file_path[128] = "";
    snprintf(config_file_path, sizeof(config_file_path), "/home/qwerty/Desktop/bpf_config/uid_to_groups.config");
    FILE *fp = fopen(config_file_path, "a");
    fprintf(fp, "%d %s\n", uid, group);
    fclose(fp);
}

void set_group(char username[MAX_USERNAME_LEN], char group[MAX_GROUP_LEN]) {
    int uid = username_to_uid(username);
    if(uid < 0) {
        fprintf(err_fp, "user not found\n");
        return;        
    }

    int map_fd = uid_to_groups_fd;
    int err = update_uid_to_groups_map(map_fd, uid, group);
    if(err < 0)
        return;
    add_entry_to_config_file_group_set(uid, group);
}

static void add_entry_to_config_file_group_user(char permission_type[6], char syscall_name[16], char object_type[MAX_TYPE_LEN], char group[MAX_GROUP_LEN]) {
    char config_file_path[128] = "";
    snprintf(config_file_path, sizeof(config_file_path), "/home/qwerty/Desktop/bpf_config/%s_group_%s_map.config",permission_type, syscall_name);
    FILE *fp = fopen(config_file_path, "a");
    fprintf(fp, "%s %s\n", object_type, group);
    fclose(fp);
}

void addrule_group(char syscall_name[16], char object_type[MAX_TYPE_LEN], char group[MAX_GROUP_LEN]) {
    int default_setting = get_type_default_setting(object_type, "user");
    char permission_type[6] = "";
    if(default_setting == DEFAULT_ALLOW)
        strcpy(permission_type, "deny");
    else if(default_setting == DEFAULT_DENY)
        strcpy(permission_type, "allow");
    else {
        fprintf(err_fp, "type: %s has not been registered yet\n", object_type);
        return;
    }
    
    //TODO: check group exist

    char map_name[128] = "";
    snprintf(map_name, sizeof(map_name), "%s_group_%s_map", permission_type, syscall_name);
    //struct bpf_map *map = NULL;
    
    char pin_path[128] = "";
    snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/restrict_user_%s/%s", syscall_name, map_name);
    int map_fd = bpf_obj_get(pin_path);
    if (map_fd < 0) 
        fprintf(err_fp, "ERROR: failed to get the map: %s\n", map_name);    
    
    /*
    if(strcmp(syscall_name, "open") == 0) {
        // map = bpf_object__find_map_by_name(restrict_exec_open_data.obj, map_name);
    }   
    else if(strcmp(syscall_name, "read") == 0) {
        map = bpf_object__find_map_by_name(restrict_user_read_data.obj, map_name);
    }
    else if(strcmp(syscall_name, "write") == 0) {
    }
    else {
        fprintf(err_fp, "wrong syscall, available syscalls: open, read, write, exec, ock, ioctl, getattr\n");
        return;
    }
    int map_fd = bpf_map__fd(map);*/
    
    int err = update_group_restriction_map(map_fd, object_type, group);
    if(err < 0)
        return;
    add_entry_to_config_file_group_user(permission_type, syscall_name, object_type, group);       
}