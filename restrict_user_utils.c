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
#include "restricted_files_utils.h"
#include "restrict_group_utils.h"

#include "restrict_user_utils.h"

extern FILE *err_fp;

extern struct my_bpf_data restrict_user_read_data;

extern int events_ringbuf_fd;

extern int default_allow_files_user_fd;
extern int default_deny_files_user_fd;

extern int default_allow_object_types_user_fd;
extern int default_deny_object_types_user_fd;

extern int path_to_object_types_user_fd;
extern int uid_to_groups_fd;

static int update_restriction_map_user(int outer_map_fd, char file_path[MAX_PATH_LEN], int uid) {
    int err, inner_map_id, inner_map_fd;

    err = bpf_map_lookup_elem(outer_map_fd, file_path, &inner_map_id);

    if(err < 0) {
        fprintf(err_fp, "inner map for %s does not exist\n", file_path);
        LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = BPF_F_NO_PREALLOC);
        inner_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, NULL, sizeof(int), sizeof(char),
				                      MAX_RESTRICTED_UID_NUM, &opts);
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
    err = bpf_map_update_elem(inner_map_fd, &uid, &val, BPF_ANY);
    if(err < 0) {
        if(errno == E2BIG) 
            fprintf(err_fp, "inner map is full, ");
        fprintf(err_fp, "fail to update inner map\n");
        return -1;
    }    
    return 0;
}

static void add_entry_to_config_file_user(char permission_type[6], char syscall_name[16], char file_path[MAX_PATH_LEN], int uid) {
    char config_file_path[128] = "";
    snprintf(config_file_path, sizeof(config_file_path), "/home/qwerty/Desktop/bpf_config/%s_user_%s_map.config",permission_type, syscall_name);
    FILE *fp = fopen(config_file_path, "a");
    fprintf(fp, "%s %d\n", file_path, uid);
    fclose(fp);
}

void addrule_user(char syscall_name[16], char file_path[MAX_PATH_LEN], char username[MAX_USERNAME_LEN]) {
    int uid = username_to_uid(username);
    if(uid < 0) {
        fprintf(err_fp, "user not found\n");
        return;
    }

    int default_setting = get_file_default_setting(file_path, "user");
    char permission_type[6] = "";
    if(default_setting == DEFAULT_ALLOW)
        strcpy(permission_type, "deny");
    else if(default_setting == DEFAULT_DENY)
        strcpy(permission_type, "allow");
    else {
        fprintf(err_fp, "file: %s has not been registered yet\n", file_path);
        return;
    }

    char map_name[128] = "";
    snprintf(map_name, sizeof(map_name), "%s_user_%s_map", permission_type, syscall_name);
    //struct bpf_map *map = NULL;

    char pin_path[128] = "";
    snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/restrict_user_%s/%s", syscall_name, map_name);
    int map_fd = bpf_obj_get(pin_path);
    if (map_fd < 0) 
        fprintf(err_fp, "ERROR: failed to get the map: %s\n", map_name);

    /*if(strcmp(syscall_name, "open") == 0) {
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
    int map_fd = bpf_map__fd(map);
    */       
    
    int err = update_restriction_map_user(map_fd, file_path, uid);
    if(err < 0)
        return;

    add_entry_to_config_file_user(permission_type, syscall_name, file_path, uid);   
}

static void init_restriction_map_user(char permission_type[6], char syscall_name[16], struct my_bpf_data *cur_bpf) {
    char config_file_path[128] = "";
    snprintf(config_file_path, sizeof(config_file_path), "/home/qwerty/Desktop/bpf_config/%s_user_%s_map.config", permission_type, syscall_name);
    // S_IROTH | S_IWOTH for debugging
    int fd = open(config_file_path, O_RDONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH);
    FILE *fp = fdopen(fd, "r");

    char map_name[128] = "";
    snprintf(map_name, sizeof(map_name), "%s_user_%s_map", permission_type, syscall_name);
    struct bpf_map *map = bpf_object__find_map_by_name(cur_bpf->obj, map_name);
    int map_fd = bpf_map__fd(map);

    char pin_path[128] = "";
    snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/restrict_user_%s/%s", syscall_name, map_name);
    int err = bpf_obj_pin(map_fd, pin_path);
    if (err) 
        fprintf(err_fp, "ERROR: failed to pin the map: %s\n", map_name);

    // check if configuration is not empty
    char line_buf[MAX_LINE_LEN] = "";
    char file_path[MAX_PATH_LEN] = "";
    char uid_string[MAX_UID_LEN] = "";
    int uid;
    while(fgets(line_buf, MAX_LINE_LEN, fp) != NULL) {
    	int token_id = 0;
    	char *cur_string = strtok(line_buf, " \n");
    	while(cur_string != NULL) {
    	    if(token_id == 0)
                strncpy(file_path, cur_string, MAX_PATH_LEN);
    	    else
    	    	strncpy(uid_string, cur_string, MAX_UID_LEN);
    	    token_id++;
    	    cur_string = strtok(NULL, " \n");   
    	}
    	uid = atoi(uid_string);
    	update_restriction_map_user(map_fd, file_path, uid);
    }  
}

void init_bpf_prog_user(char syscall_name[16], struct my_bpf_data *cur_bpf) {
    char prog_name[64] = "";
    snprintf(prog_name, sizeof(prog_name), "restrict_user_%s", syscall_name);
    
    char filename[128] = "";	
	snprintf(filename, sizeof(filename), "/home/qwerty/Desktop/libbpf-bootstrap/examples/c/.output/%s.bpf.o", prog_name);
	cur_bpf->obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(cur_bpf->obj)) {
		fprintf(err_fp, "ERROR: opening BPF object file: %s failed\n", filename);
		return;
	}

	cur_bpf->prog = bpf_object__find_program_by_name(cur_bpf->obj, prog_name);
	if (!cur_bpf->prog) {
		fprintf(err_fp, "finding a prog in obj file: %s failed\n", filename);
		goto cleanup;
	}

    /* use shared default before program is loaded */
    struct bpf_map *default_allow_files_user = bpf_object__find_map_by_name(cur_bpf->obj, "default_allow_files_user");
    bpf_map__reuse_fd(default_allow_files_user, default_allow_files_user_fd);

    struct bpf_map *default_deny_files_user = bpf_object__find_map_by_name(cur_bpf->obj, "default_deny_files_user");
    bpf_map__reuse_fd(default_deny_files_user, default_deny_files_user_fd);

    struct bpf_map *default_allow_object_types_user = bpf_object__find_map_by_name(cur_bpf->obj, "default_allow_object_types_user");
    bpf_map__reuse_fd(default_allow_object_types_user, default_allow_object_types_user_fd);

    struct bpf_map *default_deny_object_types_user = bpf_object__find_map_by_name(cur_bpf->obj, "default_deny_object_types_user");
    bpf_map__reuse_fd(default_deny_object_types_user, default_deny_object_types_user_fd);

    struct bpf_map *path_to_object_types_user = bpf_object__find_map_by_name(cur_bpf->obj, "path_to_object_types_user");
    bpf_map__reuse_fd(path_to_object_types_user, path_to_object_types_user_fd);

    struct bpf_map *uid_to_groups = bpf_object__find_map_by_name(cur_bpf->obj, "uid_to_groups");
    bpf_map__reuse_fd(uid_to_groups, uid_to_groups_fd);

    struct bpf_map *rb = bpf_object__find_map_by_name(cur_bpf->obj, "rb");
    bpf_map__reuse_fd(rb, events_ringbuf_fd);  


	/* load and verify BPF program */
	if (bpf_object__load(cur_bpf->obj)) {
		fprintf(err_fp, "ERROR: loading BPF object file: %s failed\n", filename);
		goto cleanup;
	}

    init_restriction_map_user("allow", syscall_name, cur_bpf);
    init_restriction_map_user("deny", syscall_name, cur_bpf);
    
    init_group_restriction_map("allow", syscall_name, cur_bpf);
    init_group_restriction_map("deny", syscall_name, cur_bpf);

    // Attaches the loaded BPF program to the LSM hook
	cur_bpf->link = bpf_program__attach(cur_bpf->prog);
	if (libbpf_get_error(cur_bpf->link)) {
		fprintf(err_fp, "ERROR: attach bpf program: %s failed\n", prog_name);
		goto cleanup;
	}

    char pin_path[128] = "";	
	snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/%s/%s", prog_name, prog_name);
    int err = bpf_link__pin(cur_bpf->link, pin_path);
    if(err) {
        fprintf(err_fp, "ERROR: failed to pin bpf program: %s\n", prog_name);
        goto cleanup;
    }
    return;

cleanup:
	bpf_link__destroy(cur_bpf->link);
	bpf_object__close(cur_bpf->obj);
    cur_bpf->obj = NULL;
    cur_bpf->link = NULL;
	return;
}