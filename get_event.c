#include <errno.h>
#include <stdio.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdlib.h>
#include <fcntl.h>
#include "general_utils.h"
#include "event_utils.h"

extern FILE *err_fp;

extern char all_syscalls[NR_SYSCALLS][16];

int init_events_ringbuf() {
	/* create ring buffer */
	int fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, "rb", 0, 0,
		256 * 1024, NULL);
	if(fd < 0) {
		fprintf(err_fp, "Failed to create events ring buffer\n");
		return -1;		
	}

    int err = bpf_obj_pin(fd, "/sys/fs/bpf/events_ringbuf");
    if (err) 
        fprintf(err_fp, "ERROR: failed to pin the map: events_ringbuf\n");
    return fd;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;

    FILE *fp = fopen("/home/qwerty/Desktop/bpf_config/events.log", "a");
    char permission_types[2][6] = {"deny", "allow"};
    char restricted_targets[4][6] = {"exec", "user", "type", "group"}; 
    fprintf(fp, "permission: %s, syscall: %s, restricted_target: %s, euid: %d, exec: %s, file: %s, subject_type: %s, object_type: %s, user_group: %s\n"
            , permission_types[e->permission_type], all_syscalls[e->syscall], restricted_targets[e->restricted_target], e->euid, e->exec_path,
            e->file_path, e->subject_type, e->object_type, e->user_group);  
    fclose(fp);
	return 0;
}

int start_logging() {
	struct ring_buffer *rb = NULL;
	int err;

	/* Set up ring buffer polling */
    int events_ringbuf_fd = bpf_obj_get("/sys/fs/bpf/events_ringbuf");
    if (events_ringbuf_fd < 0) {
        fprintf(err_fp, "ERROR: failed to get the map: events_ringbuf\n");
        return -1;
    } 
	rb = ring_buffer__new(events_ringbuf_fd, handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(err_fp, "Failed to create ring buffer\n");
		return err < 0 ? -err : 0;   
	}

	/* Process events */
	while (true) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		if (err < 0) {
            fprintf(err_fp, "Error polling ring buffer: %d\n", err);
            break;
        }
	}
	return err < 0 ? -err : 0;    
}