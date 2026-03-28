package process

/*
#cgo LDFLAGS: -lproc

#include <string.h>
#include <libproc.h>
#include <sys/types.h>

// Defined in process_darwin.c
int find_pid_by_port(uint16_t port, pid_t *out_pid);
int find_process_path_by_pid(pid_t pid, char *buf, size_t buflen);
int find_process_name_by_pid(pid_t pid, char *buf, size_t buflen);
*/
import "C"

import "fmt"

// ProcPathMaxsize sets the buffer length for proc_name. It's not defined
// in libproc.h, and various codebases use values from 64 to 4096, but 1024 is likely ok.
const ProcPathMaxsize = 1024

// FindBySourcePort returns the process that owns the given TCP source port,
// or ErrNotFound if no process owns it.
func FindBySourcePort(port uint16) (Process, error) {
	var pid C.pid_t
	ret := C.find_pid_by_port(C.uint16_t(port), &pid)
	switch {
	case ret == 1:
		return Process{}, ErrNotFound
	case ret < 0:
		return Process{}, fmt.Errorf("find pid for port %d: %s", port, C.GoString(C.strerror(-ret)))
	}

	var p Process
	p.ID = int(pid)

	var pathBuf [C.PROC_PIDPATHINFO_MAXSIZE]C.char
	ret = C.find_process_path_by_pid(pid, &pathBuf[0], C.size_t(len(pathBuf)))
	if ret < 0 {
		return Process{}, fmt.Errorf("find path for pid %d: %s", pid, C.GoString(C.strerror(-ret)))
	}
	p.DiskPath = C.GoString(&pathBuf[0])

	var nameBuf [ProcPathMaxsize]C.char
	ret = C.find_process_name_by_pid(pid, &nameBuf[0], C.size_t(len(nameBuf)))
	if ret < 0 {
		return Process{}, fmt.Errorf("find name for pid %d: %s", pid, C.GoString(C.strerror(-ret)))
	}
	p.Name = C.GoString(&nameBuf[0])

	return p, nil
}
