#include <bpf/bpf.h> // bpf_map_create
#include <bpf/libbpf.h> // bpf_map__reuse_fd
#include <stdio.h> // fdopen, fgets, fopen, snprintf
#include <fcntl.h> // open
#include <unistd.h> // close
#include <string.h>
#include <errno.h>
#include "general_utils.h"
#include "restricted_files_utils.h"
#include "restrict_type_utils.h"

#include "restrict_exec_utils.h"

extern FILE *err_fp;

extern struct my_bpf_data restrict_exec_open_data;

extern int events_ringbuf_fd;

extern int default_allow_files_exec_fd;
extern int default_deny_files_exec_fd;

extern int default_allow_object_types_exec_fd;
extern int default_deny_object_types_exec_fd;

extern int path_to_object_types_exec_fd;
extern int path_to_subject_types_fd;

/*static int create_outer_map(char bpf_name[128]) {
    int inner_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, NULL, sizeof(char[MAX_PATH_LEN]), sizeof(int),
				MAX_RESTRICTED_FILE_NUM, NULL);

    LIBBPF_OPTS(bpf_map_create_opts, opts, .inner_map_fd = inner_map_fd);
    char map_name[128] = "";
    snprintf(map_name, sizeof(map_name), "%s_map", bpf_name);
    int outer_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH_OF_MAPS,
                        map_name,                           // name 
                        sizeof(char[MAX_PATH_LEN]),         // key size 
                        sizeof(__u32),                      // value size 
                        MAX_RESTRICTED_EXEC_NUM_PER_FILE,            // max entries 
                        &opts);                             // create opts 
    
    close(inner_map_fd);
    return outer_map_fd;
}*/

static int update_restriction_map_exec(int outer_map_fd, char file_path[MAX_PATH_LEN], char exec_path[MAX_PATH_LEN]) {
    int err, inner_map_id, inner_map_fd;

    err = bpf_map_lookup_elem(outer_map_fd, file_path, &inner_map_id);

    if(err < 0) {
        fprintf(err_fp, "inner map for %s does not exist\n", file_path);
        LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = BPF_F_NO_PREALLOC);
        inner_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, NULL, sizeof(char[MAX_PATH_LEN]), sizeof(char),
				                      MAX_RESTRICTED_EXEC_NUM_PER_FILE, &opts);
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
    err = bpf_map_update_elem(inner_map_fd, exec_path, &val, BPF_ANY);
    if(err < 0) {
        if(errno == E2BIG) 
            fprintf(err_fp, "inner map is full, ");
        fprintf(err_fp, "fail to update inner map\n");
        return -1;
    }    
    return 0;
}

static void add_entry_to_config_file_exec(char permission_type[6], char syscall_name[16], char file_path[MAX_PATH_LEN], char exec_path[MAX_PATH_LEN]) {
    char config_file_path[128] = "";
    snprintf(config_file_path, sizeof(config_file_path), "/home/qwerty/Desktop/bpf_config/%s_exec_%s_map.config",permission_type, syscall_name);
    FILE *fp = fopen(config_file_path, "a");
    fprintf(fp, "%s %s\n", file_path, exec_path);
    fclose(fp);
}

void addrule_exec(char syscall_name[16], char file_path[MAX_PATH_LEN], char exec_path[MAX_PATH_LEN]) { 
    int default_setting = get_file_default_setting(file_path, "exec");
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
    snprintf(map_name, sizeof(map_name), "%s_exec_%s_map", permission_type, syscall_name);

    char pin_path[128] = "";
    snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/restrict_exec_%s/%s", syscall_name, map_name);
    int map_fd = bpf_obj_get(pin_path);
    if (map_fd < 0) {
        fprintf(err_fp, "ERROR: failed to get the map: %s\n", map_name);
        return;
    } 

    /*if(strcmp(syscall_name, "open") == 0) 
        map = bpf_object__find_map_by_name(restrict_exec_open_data.obj, map_name);
    else if(strcmp(syscall_name, "read") == 0) {
    }
    else if(strcmp(syscall_name, "write") == 0) {
    }
    else {
        fprintf(err_fp, "wrong syscall, available syscalls: open, read, write, exec, ock, ioctl, getattr\n");
        return;
    }
    int map_fd = bpf_map__fd(map);
    */

    int err = update_restriction_map_exec(map_fd, file_path, exec_path);
    if(err < 0) 
        return;

    add_entry_to_config_file_exec(permission_type, syscall_name, file_path, exec_path);    
}

static void init_restriction_map_exec(char permission_type[6], char syscall_name[16], struct my_bpf_data *cur_bpf) {
    char config_file_path[128] = "";
    snprintf(config_file_path, sizeof(config_file_path), "/home/qwerty/Desktop/bpf_config/%s_exec_%s_map.config", permission_type, syscall_name);
    // S_IROTH | S_IWOTH for debugging
    int fd = open(config_file_path, O_RDONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH);
    FILE *fp = fdopen(fd, "r");

    char map_name[128] = "";
    snprintf(map_name, sizeof(map_name), "%s_exec_%s_map", permission_type, syscall_name);
    struct bpf_map *map = bpf_object__find_map_by_name(cur_bpf->obj, map_name);
    int map_fd = bpf_map__fd(map);

    char pin_path[128] = "";
    snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/restrict_exec_%s/%s", syscall_name, map_name);
    int err = bpf_obj_pin(map_fd, pin_path);
    if (err) 
        fprintf(err_fp, "ERROR: failed to pin the map: %s\n", map_name);

    char line_buf[MAX_LINE_LEN] = "";
    char file_path[MAX_PATH_LEN] = "";
    char exec_path[MAX_PATH_LEN] = ""; 
    while(fgets(line_buf, MAX_LINE_LEN, fp) != NULL) {
    	int token_id = 0;
    	char *cur_path = strtok(line_buf, " \n");
    	while(cur_path != NULL) {
    	    if(token_id == 0)
    	    	strncpy(file_path, cur_path, MAX_PATH_LEN);
    	    else
    	    	strncpy(exec_path, cur_path, MAX_PATH_LEN);
    	    token_id++;
    	    cur_path = strtok(NULL, " \n");   
    	}
    	update_restriction_map_exec(map_fd, file_path, exec_path);
    }  
}

void init_bpf_prog_exec(char syscall_name[16], struct my_bpf_data *cur_bpf) {
    char prog_name[64] = "";
    snprintf(prog_name, sizeof(prog_name), "restrict_exec_%s", syscall_name);

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
    struct bpf_map *default_allow_files_exec = bpf_object__find_map_by_name(cur_bpf->obj, "default_allow_files_exec");
    bpf_map__reuse_fd(default_allow_files_exec, default_allow_files_exec_fd);

    struct bpf_map *default_deny_files_exec = bpf_object__find_map_by_name(cur_bpf->obj, "default_deny_files_exec");
    bpf_map__reuse_fd(default_deny_files_exec, default_deny_files_exec_fd);

    struct bpf_map *default_allow_object_types_exec = bpf_object__find_map_by_name(cur_bpf->obj, "default_allow_object_types_exec");
    bpf_map__reuse_fd(default_allow_object_types_exec, default_allow_object_types_exec_fd);

    struct bpf_map *default_deny_object_types_exec = bpf_object__find_map_by_name(cur_bpf->obj, "default_deny_object_types_exec");
    bpf_map__reuse_fd(default_deny_object_types_exec, default_deny_object_types_exec_fd);

    struct bpf_map *path_to_object_types_exec = bpf_object__find_map_by_name(cur_bpf->obj, "path_to_object_types_exec");
    bpf_map__reuse_fd(path_to_object_types_exec, path_to_object_types_exec_fd);

    struct bpf_map *path_to_subject_types = bpf_object__find_map_by_name(cur_bpf->obj, "path_to_subject_types");
    bpf_map__reuse_fd(path_to_subject_types, path_to_subject_types_fd);

    struct bpf_map *rb = bpf_object__find_map_by_name(cur_bpf->obj, "rb");
    bpf_map__reuse_fd(rb, events_ringbuf_fd);    

	/* load and verify BPF program */
	if (bpf_object__load(cur_bpf->obj)) {
		fprintf(err_fp, "ERROR: loading BPF object file: %s failed\n", filename);
		goto cleanup;
	}

    init_restriction_map_exec("allow", syscall_name, cur_bpf);
    init_restriction_map_exec("deny", syscall_name, cur_bpf);

    init_type_restriction_map_exec("allow", syscall_name, cur_bpf);
    init_type_restriction_map_exec("deny", syscall_name, cur_bpf);

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