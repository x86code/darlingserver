#include <darlingserver/duct-tape.h>

#include <mach/mach_traps.h>

uint32_t dtape_task_self_trap(void) {
	return task_self_trap(NULL);
};

uint32_t dtape_host_self_trap(void) {
	return host_self_trap(NULL);
};

uint32_t dtape_thread_self_trap(void) {
	return thread_self_trap(NULL);
};

uint32_t dtape_mach_reply_port(void) {
	return mach_reply_port(NULL);
};

uint32_t dtape_thread_get_special_reply_port(void) {
	return thread_get_special_reply_port(NULL);
};

uint32_t dtape_mk_timer_create(void) {
	return mk_timer_create_trap(NULL);
};

// x86Code: see host_darling_set_io_master_port()
struct set_io_master_port_args {
	uint32_t name;
};
extern kern_return_t host_darling_set_io_master_port(mach_port_name_t name);

static kern_return_t set_io_master_port(struct set_io_master_port_args* args) {
	return host_darling_set_io_master_port(args->name);
};

// x86Code: see task_spawn_set_special_port()
struct spawn_set_special_port_args {
	int32_t which;
	uint32_t name;
};
extern kern_return_t task_spawn_set_special_port(int which, mach_port_name_t name);

static kern_return_t spawn_set_special_port(struct spawn_set_special_port_args* args) {
	return task_spawn_set_special_port(args->which, args->name);
};

DSERVER_DTAPE_DEFS;

// x86Code: fileports (fileport_makeport/fileport_makefd). The fileglob is just the server's own copy of the fd;
// fileport_releasefg (no more senders) closes it. libxpc sends file descriptors as fileports (xpc_fd_create,
// NSFileHandle over NSXPC); fileport_makeport used to hit the old LKM API and crashed the caller.
#include <ipc/ipc_port.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_space.h>
#include <kern/task.h>
#include <kern/ipc_misc.h>
#include <stdlib.h>
struct fileglob {
	int fd;
};
extern int close(int fd);
extern int dup(int fd);

void fileport_releasefg(struct fileglob* fg) {
	close(fg->fd);
	free(fg);
};

int dtape_fileport_makeport(int fd, uint32_t* out_name) {
	struct fileglob* fg = malloc(sizeof(*fg));
	if (!fg) {
		return -12; // ENOMEM
	}
	fg->fd = fd;
	ipc_port_t port = fileport_alloc(fg);
	if (!IP_VALID(port)) {
		free(fg);
		return -12;
	}
	mach_port_name_t name = ipc_port_copyout_send(port, current_task()->itk_space);
	if (!MACH_PORT_VALID(name)) {
		// the port (and with it the fileglob) goes away with its last send right
		return -24; // EMFILE
	}
	*out_name = name;
	return 0;
};

int dtape_fileport_makefd(uint32_t name, int* out_fd) {
	ipc_port_t fileport;
	struct fileglob* fg;
	kern_return_t kr = ipc_object_copyin(current_task()->itk_space, name, MACH_MSG_TYPE_COPY_SEND, (ipc_object_t*)&fileport, 0, NULL, IPC_OBJECT_COPYIN_FLAGS_ALLOW_IMMOVABLE_SEND);
	if (kr != KERN_SUCCESS) {
		return -22; // EINVAL
	}
	int result = -22;
	if ((fg = fileport_port_to_fileglob(fileport)) != NULL) {
		int fd = dup(fg->fd);
		if (fd < 0) {
			result = -24;
		} else {
			*out_fd = fd;
			result = 0;
		}
	}
	ipc_port_release_send(fileport);
	return result;
};
