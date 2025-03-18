#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <unistd.h> //fork
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h> // umask, mkdir
#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/resource.h> //getrlimit
#include <signal.h> // sigaction
#include "general_utils.h"
#include "get_event.h"
#include "restricted_files_utils.h"
#include "restrict_exec_utils.h"
#include "restrict_user_utils.h"
#include "general_type_utils.h"
#include "restrict_type_utils.h"
#include "restrict_group_utils.h"

FILE *err_fp;
FILE *bpf_err_fp;

struct my_bpf_data restrict_exec_open_data;
struct my_bpf_data restrict_exec_read_data;
struct my_bpf_data restrict_exec_write_data;

struct my_bpf_data restrict_user_read_data;
struct my_bpf_data restrict_user_write_data;
//struct my_bpf_data restrict_type_write_data;

int events_ringbuf_fd;

int default_allow_files_exec_fd;
int default_deny_files_exec_fd;

int default_allow_object_types_exec_fd;
int default_deny_object_types_exec_fd;

int path_to_object_types_exec_fd;
int path_to_subject_types_fd;

//user
int default_allow_files_user_fd;
int default_deny_files_user_fd;

int default_allow_object_types_user_fd;
int default_deny_object_types_user_fd;

int path_to_object_types_user_fd;
int uid_to_groups_fd;
//static int filename_to_types_map_fd;
//int err;

char all_syscalls[NR_SYSCALLS][16] = {"read", "write"};


int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(bpf_err_fp, format, args);
}

int lockfile(int fd) {
    struct flock fl;
    fl.l_type = F_WRLCK;
    fl.l_start = 0;
    fl.l_whence = SEEK_SET;
    fl.l_len = 0;
    return(fcntl(fd, F_SETLK, &fl));
}

int unlockfile(int fd) {
    struct flock fl;
    fl.l_type = F_UNLCK;
    fl.l_start = 0;
    fl.l_whence = SEEK_SET;
    fl.l_len = 0;
    return(fcntl(fd, F_SETLK, &fl));    
}

int already_running(char lock_path[MAX_PATH_LEN]) {
    char buf[16];
    int fd = open(lock_path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH);
    if (fd < 0) {
        fprintf(err_fp, "can’t open %s\n", lock_path);
        exit(1);
    }
    if (lockfile(fd) < 0) {
        if (errno == EACCES || errno == EAGAIN) {
            close(fd);
            return(1);
        }
        fprintf(err_fp, "can’t lock %s\n", lock_path);
        exit(1);
    }

    ftruncate(fd, 0);
    sprintf(buf, "%ld", (long)getpid());
    write(fd, buf, strlen(buf)+1);
    return(0);
}

void init_all_bpf_progs() {
    events_ringbuf_fd = init_events_ringbuf();

    default_allow_files_exec_fd = init_restricted_files("allow", "exec");
    default_deny_files_exec_fd = init_restricted_files("deny", "exec");

    default_allow_object_types_exec_fd = init_restricted_object_types("allow", "exec");
    default_deny_object_types_exec_fd = init_restricted_object_types("deny", "exec");

    path_to_object_types_exec_fd = init_path_to_types("object", "exec");
    path_to_subject_types_fd = init_path_to_types("subject", "");

    //mkdir("/sys/fs/bpf/restrict_exec_open", 0700);
    mkdir("/sys/fs/bpf/restrict_exec_read", 0700);
    //mkdir("/sys/fs/bpf/restrict_exec_write", 0700);

    //init_bpf_prog_exec("open", &restrict_exec_open_data);
    init_bpf_prog_exec("read", &restrict_exec_read_data);
    //init_bpf_prog_exec("write", &restrict_exec_write_data);

    default_allow_files_user_fd = init_restricted_files("allow", "user");
    default_deny_files_user_fd = init_restricted_files("deny", "user");

    default_allow_object_types_user_fd = init_restricted_object_types("allow", "user");
    default_deny_object_types_user_fd = init_restricted_object_types("deny", "user");

    path_to_object_types_user_fd = init_path_to_types("object", "user");
    uid_to_groups_fd = init_uid_to_groups();

    mkdir("/sys/fs/bpf/restrict_user_read", 0700);
    //mkdir("/sys/fs/bpf/restrict_user_write", 0700);

    init_bpf_prog_user("read", &restrict_user_read_data);
    //init_bpf_prog_user("write", &restrict_user_write_data);
    
    /*filename_to_types_map_fd = init_filename_to_types_map();
    init_bpf_prog_type("deny_type_write", &deny_type_write_data, filename_to_types_map_fd);*/
}

static void daemonize() {
    // clear file creation mask.
    umask(0);

    // get maximum number of file descriptors
    struct rlimit rl;
    if(getrlimit(RLIMIT_NOFILE, &rl) < 0) {
        fprintf(err_fp, "get file limit failed\n");
        exit(0);
    }

    // become a session leader to lose controlling TTY
    pid_t pid;
    if((pid = fork()) < 0) {
        fprintf(err_fp, "fork failed\n");
        exit(0);
    }
    else if(pid != 0) // parent
        exit(0);
    setsid();

    // ensure future opens won't allocate controlling TTYs
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if(sigaction(SIGHUP, &sa, NULL) < 0) {
        fprintf(err_fp, "ignore SIGHUP failed\n");
        exit(0);
    }
    if((pid = fork()) < 0) {
        fprintf(err_fp, "fork failed\n");
        exit(0);
    }
    else if(pid != 0) // parent
        exit(0);

    // change the current working directory to the root so we won't prevent file systems from being unmounted
    if(chdir("/") < 0) {
        fprintf(err_fp, "change dir to / failed\n");
        exit(0);
    }

    // close all open file descriptors
    if(rl.rlim_max == RLIM_INFINITY)
        rl.rlim_max = 1024;
    for(int i = 0; i < rl.rlim_max; i++)
        close(i);

    // attach file descriptors 0, 1, and 2 to /dev/null
    int fd0, fd1, fd2;
    fd0 = open("/dev/null", O_RDWR);
    fd1 = dup(0);
    fd2 = dup(0);
}

int main(int argc, char *argv[])
{
    err_fp = stderr;

    // make sure there's only a single instance of the operation
    if(already_running("/home/qwerty/Desktop/bpf_config/bpfmac.lock")) {
        fprintf(err_fp, "there's another operation running, please wait till the operation finished.\n");
        return 0;
    }

    if(argc < 2) {
        fprintf(err_fp, "no args\n");
        return 0;
    }

    if(strcmp(argv[1], "init") == 0) {
        // become daemon, the lock is held by parent so the lock is released 
        daemonize();

        umask(0);
        err_fp = fopen("/home/qwerty/Desktop/bpf_config/bpfmac.log", "a");
        bpf_err_fp = fopen("/home/qwerty/Desktop/bpf_config/libbpf.log", "a");
        libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
        libbpf_set_print(libbpf_print_fn);
        
        // make sure no 2 processes doing initialization at the same time
        if(already_running("/home/qwerty/Desktop/bpf_config/bpfmacd_init.lock")) {
            fprintf(err_fp, "the system is already initializing or running.\n");
            return 0;            
        }
        // initialization 
        init_all_bpf_progs();
        already_running("/home/qwerty/Desktop/bpf_config/bpfmacd.lock");
        start_logging();
        return 0;
    }

    if(!already_running("/home/qwerty/Desktop/bpf_config/bpfmacd.lock")) {
        fprintf(err_fp, "the system has not been started yet, please use cmd \"init\" first\n");
        return 0;
    }

    int err = 0;
    bpf_err_fp = fopen("/home/qwerty/Desktop/bpf_config/libbpf.log", "a");
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);
    
    umask(0);

    default_allow_files_exec_fd = bpf_obj_get("/sys/fs/bpf/default_allow_files_exec");
    default_deny_files_exec_fd = bpf_obj_get("/sys/fs/bpf/default_deny_files_exec");

    default_allow_object_types_exec_fd = bpf_obj_get("/sys/fs/bpf/default_allow_object_types_exec");
    default_deny_object_types_exec_fd = bpf_obj_get("/sys/fs/bpf/default_deny_object_types_exec");

    path_to_object_types_exec_fd = bpf_obj_get("/sys/fs/bpf/path_to_object_types_exec");
    path_to_subject_types_fd = bpf_obj_get("/sys/fs/bpf/path_to_subject_types");

    default_allow_files_user_fd = bpf_obj_get("/sys/fs/bpf/default_allow_files_user");
    default_deny_files_user_fd = bpf_obj_get("/sys/fs/bpf/default_deny_files_user"); 

    default_allow_object_types_user_fd = bpf_obj_get("/sys/fs/bpf/default_allow_object_types_user");
    default_deny_object_types_user_fd = bpf_obj_get("/sys/fs/bpf/default_deny_object_types_user");

    path_to_object_types_user_fd = bpf_obj_get("/sys/fs/bpf/path_to_object_types_user");
    uid_to_groups_fd = bpf_obj_get("/sys/fs/bpf/uid_to_groups");    


    if(strcmp(argv[1], "register_file") == 0) {
        char file_path[MAX_PATH_LEN] = "";
        char restricted_target[6] = "";
        char default_type[6] = "";

        if(argc != 5) {
            fprintf(err_fp, "wrong args, the cmd should be \"register_file file_path restricted_target default_type\"\n");          
            return 0;
        }

        strncpy(file_path, argv[2], MAX_PATH_LEN - 1);
        file_path[MAX_PATH_LEN - 1] = '\0';

        if(strcmp(argv[3], "exec") != 0 && strcmp(argv[3], "user") != 0) {
            fprintf(err_fp, "wrong restricted target, available options: exec, user\n");
            return 0;
        }
        strncpy(restricted_target, argv[3], 5);
        restricted_target[5] = '\0';
        
        if(strcmp(argv[4], "allow") != 0 && strcmp(argv[4], "deny") != 0) {
            fprintf(err_fp, "wrong default type, available options: allow, deny\n");
            return 0;
        }
        strncpy(default_type, argv[4], 5);
        default_type[5] = '\0';

        register_file(file_path, restricted_target, default_type);

        return 0;
    }        

    if(strcmp(argv[1], "unregister_file") == 0) {
        char file_path[MAX_PATH_LEN] = "";
        char restricted_target[6] = "";

        if(argc != 4) {
            fprintf(err_fp, "wrong args, the cmd should be \"unregister_file file_path restricted_target\"\n");          
            return 0;
        }

        strncpy(file_path, argv[2], MAX_PATH_LEN - 1);
        file_path[MAX_PATH_LEN - 1] = '\0';

        if(strcmp(argv[3], "exec") != 0 && strcmp(argv[3], "user") != 0) {
            fprintf(err_fp, "wrong restricted target, available options: exec, user\n");
            return 0;
        }
        strncpy(restricted_target, argv[3], 5);
        restricted_target[5] = '\0';
        
        unregister_file(file_path, restricted_target);
        return 0;
    } 


    if(strcmp(argv[1], "addrule_exec") == 0) {
        char syscall_name[16] = "";
        char file_path[MAX_PATH_LEN] = "";
        char exec_path[MAX_PATH_LEN] = "";

        if(argc != 5) {
            fprintf(err_fp, "wrong args, the cmd should be \"addrule_exec syscall_name file_path exec_path\"\n");          
            return 0;
        }

        strncpy(syscall_name, argv[2], 15);
        syscall_name[15] = '\0';
        strncpy(file_path, argv[3], MAX_PATH_LEN - 1);
        file_path[MAX_PATH_LEN - 1] = '\0';
        strncpy(exec_path, argv[4], MAX_PATH_LEN - 1);
        exec_path[MAX_PATH_LEN - 1] = '\0';

        addrule_exec(syscall_name, file_path, exec_path);
        return 0;
    }

    if(strcmp(argv[1], "addrule_user") == 0) {
        char syscall_name[16] = "";
        char file_path[MAX_PATH_LEN] = "";
        char username[MAX_USERNAME_LEN] = "";

        if(argc != 5) {
            fprintf(err_fp, "wrong args, the cmd should be \"addrule_user syscall_name file_path username\"\n");          
            return 0;
        }

        strncpy(syscall_name, argv[2], 15);
        syscall_name[15] = '\0';
        strncpy(file_path, argv[3], MAX_PATH_LEN - 1);
        syscall_name[MAX_PATH_LEN - 1] = '\0';
        strncpy(username, argv[4], MAX_USERNAME_LEN - 1);
        syscall_name[MAX_USERNAME_LEN - 1] = '\0';

        addrule_user(syscall_name, file_path, username);
        return 0;
    }

    if(strcmp(argv[1], "register_object_type") == 0) {
        char object_type[MAX_TYPE_LEN] = "";
        char restricted_target[6] = "";
        char default_type[6] = "";

        if(argc != 5) {
            fprintf(err_fp, "wrong args, the cmd should be \"register_object_type object_type restricted_target default_type\"\n");          
            return 0;
        }

        strncpy(object_type, argv[2], MAX_TYPE_LEN - 1);
        object_type[MAX_TYPE_LEN - 1] = '\0';

        if(strcmp(argv[3], "exec") != 0 && strcmp(argv[3], "user") != 0) {
            fprintf(err_fp, "wrong restricted target, available options: exec, user\n");
            return 0;
        }
        strncpy(restricted_target, argv[3], 5);
        restricted_target[5] = '\0';
        
        if(strcmp(argv[4], "allow") != 0 && strcmp(argv[4], "deny") != 0) {
            fprintf(err_fp, "wrong default type, available options: allow, deny\n");
            return 0;
        }  
        strncpy(default_type, argv[4], 5);
        default_type[5] = '\0';             

        register_object_type(object_type, restricted_target, default_type);
        return 0;
    }

    if(strcmp(argv[1], "set_type") == 0) {
        char entity_type[10] = "";
        char file_path[MAX_PATH_LEN] = "";
        char type[MAX_TYPE_LEN] = "";
        char restricted_target[6] = "";

        if(argc < 5) {
            fprintf(err_fp, "wrong args, the cmd should be \"set_type entity_type file_path type (restricted_target)\"\n");          
            return 0;
        }

        if(strcmp(argv[2], "object") != 0 && strcmp(argv[2], "subject") != 0) {
            fprintf(err_fp, "wrong entity type, available options: object, subject\n");
            return 0;
        }
        strncpy(entity_type, argv[2], 9);
        entity_type[9] = '\0';

        if(strcmp(entity_type, "object") == 0) {
            if(argc != 6) {
                fprintf(err_fp, "wrong args, the cmd should be \"set_type object file_path type restricted_target\"\n");          
                return 0;
            }
            if(strcmp(argv[5], "exec") != 0 && strcmp(argv[5], "user") != 0) {
                fprintf(err_fp, "wrong restricted target, available options: exec, user\n");
                return 0;
            }   
            strncpy(restricted_target, argv[5], 5);
            restricted_target[5] = '\0';                                  
        }
        else {
            if(argc != 5) {
                fprintf(err_fp, "wrong args, the cmd should be \"set_type subject file_path type\"\n");          
                return 0;
            }
        }
        strncpy(file_path, argv[3], MAX_PATH_LEN - 1);
        file_path[MAX_PATH_LEN - 1] = '\0';
        strncpy(type, argv[4], MAX_TYPE_LEN - 1);
        type[MAX_TYPE_LEN - 1] = '\0';

        set_type(entity_type, file_path, type, restricted_target);
        return 0;
    }

    if(strcmp(argv[1], "addrule_type") == 0) {
        char syscall_name[16] = "";
        char object_type[MAX_TYPE_LEN] = "";
        char subject_type[MAX_TYPE_LEN] = "";

        if(argc != 5) {
            fprintf(err_fp, "wrong args, the cmd should be \"addrule_type syscall_name object_type subject_type\"\n");          
            return 0;
        }

        strncpy(syscall_name, argv[2], 15);
        syscall_name[15] = '\0';
        strncpy(object_type, argv[3], MAX_TYPE_LEN - 1);
        object_type[MAX_TYPE_LEN - 1] = '\0';
        strncpy(subject_type, argv[4], MAX_TYPE_LEN - 1);
        subject_type[MAX_TYPE_LEN - 1] = '\0';

        addrule_type(syscall_name, object_type, subject_type);
        return 0;
    }

    if(strcmp(argv[1], "set_group") == 0) {
        char username[MAX_USERNAME_LEN] = "";
        char group[MAX_GROUP_LEN] = "";

        if(argc != 4) {
            fprintf(err_fp, "wrong args, the cmd should be \"set_group username group\"\n");          
            return 0;
        }

        strncpy(username, argv[2], MAX_USERNAME_LEN - 1);
        username[MAX_USERNAME_LEN - 1] = '\0';
        strncpy(group, argv[3], MAX_GROUP_LEN - 1);
        group[MAX_GROUP_LEN - 1] = '\0';

        set_group(username, group);
        return 0;
    }

    if(strcmp(argv[1], "addrule_group") == 0) {
        char syscall_name[16] = "";
        char object_type[MAX_TYPE_LEN] = "";
        char group[MAX_GROUP_LEN] = "";

        if(argc != 5) {
            fprintf(err_fp, "wrong args, the cmd should be \"addrule_group syscall_name object_type group\"\n");          
            return 0;
        }

        strncpy(syscall_name, argv[2], 15);
        syscall_name[15] = '\0';
        strncpy(object_type, argv[3], MAX_TYPE_LEN - 1);
        object_type[MAX_TYPE_LEN - 1] = '\0';
        strncpy(group, argv[4], MAX_GROUP_LEN - 1);
        group[MAX_GROUP_LEN - 1] = '\0';

        addrule_group(syscall_name, object_type, group);
        return 0;
    }

    fprintf(err_fp, "cmd not found\n");
    return 0;

    /* getting commands */
    /*char cmd[MAX_CMD_LEN] = "";
    char tokens[MAX_TOKEN_NUM][MAX_ARG_LEN];  
    
    if(fgets(cmd, MAX_CMD_LEN, stdin) != NULL) {
        int cnt_tokens = 0;
        char *start = strtok(cmd, " \n");
        bool too_many_args = false;
    	while(start != NULL) {
            if(cnt_tokens >= MAX_TOKEN_NUM) {
                too_many_args = true;
                break;
            }
    	    strncpy(tokens[cnt_tokens], start, MAX_ARG_LEN - 1);
            tokens[cnt_tokens][MAX_ARG_LEN - 1] = '\0';
    	    cnt_tokens++;
    	    start = strtok(NULL, " \n");   
    	}
    
        if(cnt_tokens == 0) 
            return 0;

        if(too_many_args) {
            fprintf(err_fp, "too many args\n");
            return 0;
        }

        if(strcmp(tokens[0], "register") == 0) {
            char file_path[MAX_PATH_LEN] = "";
            char restricted_target[6] = "";
            char default_type[6] = "";

            if(cnt_tokens != 4) {
                fprintf(err_fp, "wrong args, the cmd should be \"register file_path restricted_target default_type\"\n");          
                return 0;
            }

            strncpy(file_path, tokens[1], MAX_PATH_LEN - 1);
            file_path[MAX_PATH_LEN - 1] = '\0';

            if(strcmp(tokens[2], "exec") != 0 && strcmp(tokens[2], "user") != 0) {
                fprintf(err_fp, "wrong restricted target, available options: exec, user\n");
                return 0;
            }
            
            strncpy(restricted_target, tokens[2], 5);
            restricted_target[5] = '\0';
            
            if(strcmp(tokens[3], "allow") != 0 && strcmp(tokens[3], "deny") != 0) {
                fprintf(err_fp, "wrong default type, available options: allow, deny\n");
                return 0;
            }

            strncpy(default_type, tokens[3], 5);
            default_type[5] = '\0';

            handle_cmd_register(file_path, restricted_target, default_type);
        }           
        else if(strcmp(tokens[0], "exec") == 0) {
            char syscall_name[16] = "";
            char file_path[MAX_PATH_LEN] = "";
            char exec_path[MAX_PATH_LEN] = "";

            if(cnt_tokens != 4) {
                fprintf(err_fp, "wrong args, the cmd should be \"exec syscall_name file_path exec_path\"\n");          
                return 0;
            }

            strncpy(syscall_name, tokens[1], 15);
            syscall_name[15] = '\0';
            strncpy(file_path, tokens[2], MAX_PATH_LEN - 1);
            file_path[MAX_PATH_LEN - 1] = '\0';
            strncpy(exec_path, tokens[3], MAX_PATH_LEN - 1);
            exec_path[MAX_PATH_LEN - 1] = '\0';

            handle_cmd_exec(syscall_name, file_path, exec_path);
        }
            
        else if(strcmp(tokens[0], "user") == 0) {
            char syscall_name[16] = "";
            char file_path[MAX_PATH_LEN] = "";
            char username[MAX_USERNAME_LEN] = "";

            if(cnt_tokens != 4) {
                fprintf(err_fp, "wrong args, the cmd should be \"user syscall_name file_path username\"\n");          
                return 0;
            }

            strncpy(syscall_name, tokens[1], 15);
            syscall_name[15] = '\0';
            strncpy(file_path, tokens[2], MAX_PATH_LEN - 1);
            syscall_name[MAX_PATH_LEN - 1] = '\0';
            strncpy(username, tokens[3], MAX_USERNAME_LEN - 1);
            syscall_name[MAX_USERNAME_LEN - 1] = '\0';

            handle_cmd_user(syscall_name, file_path, username);
        }
            
        else if(strcmp(tokens[0], "type") == 0) {

            if(cnt_tokens < 2) {
                fprintf(err_fp, "wrong args, there should be more than 1 argument for cmd \"type\"\n"); 
                return 0;
            }

            if(strcmp(tokens[1], "register") == 0) {
                char object_type[MAX_TYPE_LEN] = "";
                char restricted_target[6] = "";
                char default_type[6] = "";

                if(cnt_tokens != 5) {
                    fprintf(err_fp, "wrong args, the cmd should be \"type register object_type restricted_target default_type\"\n");          
                    return 0;
                }

                strncpy(object_type, tokens[2], MAX_TYPE_LEN - 1);
                object_type[MAX_TYPE_LEN - 1] = '\0';

                if(strcmp(tokens[3], "exec") != 0 && strcmp(tokens[3], "user") != 0) {
                    fprintf(err_fp, "wrong restricted target, available options: exec, user\n");
                    return 0;
                }

                strncpy(restricted_target, tokens[3], 5);
                restricted_target[5] = '\0';
                
                if(strcmp(tokens[4], "allow") != 0 && strcmp(tokens[4], "deny") != 0) {
                    fprintf(err_fp, "wrong default type, available options: allow, deny\n");
                    return 0;
                }
                    
                strncpy(default_type, tokens[4], 5);
                default_type[5] = '\0';             

                handle_cmd_type_register(object_type, restricted_target, default_type);
            }
                
            else if(strcmp(tokens[1], "set") == 0) {
                char entity_type[10] = "";
                char file_path[MAX_PATH_LEN] = "";
                char type[MAX_TYPE_LEN] = "";
                char restricted_target[6] = "";

                if(cnt_tokens < 5) {
                    fprintf(err_fp, "wrong args, the cmd should be \"type set entity_type file_path type (restricted_target)\"\n");          
                    return 0;
                }

                if(strcmp(tokens[2], "object") != 0 && strcmp(tokens[2], "subject") != 0) {
                    fprintf(err_fp, "wrong entity type, available options: object, subject\n");
                    return 0;
                }
                
                strncpy(entity_type, tokens[2], 9);
                entity_type[9] = '\0';

                if(strcmp(entity_type, "object") == 0) {
                    if(cnt_tokens != 6) {
                        fprintf(err_fp, "wrong args, the cmd should be \"type set object file_path type restricted_target\"\n");          
                        return 0;
                    }
                    if(strcmp(tokens[5], "exec") != 0 && strcmp(tokens[5], "user") != 0) {
                        fprintf(err_fp, "wrong restricted target, available options: exec, user\n");
                        return 0;
                    }   
                    strncpy(restricted_target, tokens[5], 5);
                    restricted_target[5] = '\0';                                  
                }
                else {
                    if(cnt_tokens != 5) {
                        fprintf(err_fp, "wrong args, the cmd should be \"type set subject file_path type\"\n");          
                        return 0;
                    }
                }
                strncpy(file_path, tokens[3], MAX_PATH_LEN - 1);
                file_path[MAX_PATH_LEN - 1] = '\0';
                strncpy(type, tokens[4], MAX_TYPE_LEN - 1);
                type[MAX_TYPE_LEN - 1] = '\0';

                handle_cmd_type_set(entity_type, file_path, type, restricted_target);
            }
                
            else if(strcmp(tokens[1], "exec") == 0) {
                char syscall_name[16] = "";
                char object_type[MAX_TYPE_LEN] = "";
                char subject_type[MAX_TYPE_LEN] = "";

                if(cnt_tokens != 5) {
                    fprintf(err_fp, "wrong args, the cmd should be \"type exec syscall_name object_type subject_type\"\n");          
                    return 0;
                }

                strncpy(syscall_name, tokens[2], 15);
                syscall_name[15] = '\0';
                strncpy(object_type, tokens[3], MAX_TYPE_LEN - 1);
                object_type[MAX_TYPE_LEN - 1] = '\0';
                strncpy(subject_type, tokens[4], MAX_TYPE_LEN - 1);
                subject_type[MAX_TYPE_LEN - 1] = '\0';


                handle_cmd_type_exec(syscall_name, object_type, subject_type);
            }
                
            else
                fprintf(err_fp, "wrong arg[1], available arg[1] are: register, set, exec\n");
        }
        else if(strcmp(tokens[0], "group") == 0) {
            if(cnt_tokens < 2) {
                fprintf(err_fp, "wrong args, there should be more than 1 argument for cmd \"group\"\n"); 
                return 0;
            }

            if(strcmp(tokens[1], "set") == 0) {
                char username[MAX_USERNAME_LEN] = "";
                char group[MAX_GROUP_LEN] = "";

                if(cnt_tokens != 4) {
                    fprintf(err_fp, "wrong args, the cmd should be \"group set username group\"\n");          
                    return 0;
                }

                strncpy(username, tokens[2], MAX_USERNAME_LEN - 1);
                username[MAX_USERNAME_LEN - 1] = '\0';
                strncpy(group, tokens[3], MAX_GROUP_LEN - 1);
                group[MAX_GROUP_LEN - 1] = '\0';


                handle_cmd_group_set(username, group);
            }
                
            else if(strcmp(tokens[1], "user") == 0) {
                char syscall_name[16] = "";
                char object_type[MAX_TYPE_LEN] = "";
                char group[MAX_GROUP_LEN] = "";

                if(cnt_tokens != 5) {
                    fprintf(err_fp, "wrong args, the cmd should be \"group user syscall_name, object_type, group\"\n");          
                    return 0;
                }

                strncpy(syscall_name, tokens[2], 15);
                syscall_name[15] = '\0';
                strncpy(object_type, tokens[3], MAX_TYPE_LEN - 1);
                object_type[MAX_TYPE_LEN - 1] = '\0';
                strncpy(group, tokens[4], MAX_GROUP_LEN - 1);
                group[MAX_GROUP_LEN - 1] = '\0';

                handle_cmd_group_user(syscall_name, object_type, group);
            }
                
            else
                fprintf(err_fp, "wrong cmd, available cmds are: set, user\n");            
        }
        else
            fprintf(err_fp, "wrong cmd, available cmds are: exec, user, type\n");
    }*/
    
/*cleanup:
    return err;*/
}
