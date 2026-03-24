package proc

/*
#cgo LDFLAGS: -lproc

#include <string.h>
#include <libproc.h>

// Defined in proc_darwin.c
int find_process_path_by_port(uint16_t port, char *buf, size_t buflen);
*/
import "C"

import "fmt"

// FindProcessPath returns the filesystem path of the process that owns
// the given TCP source port, or ErrNotFound if no process owns it.
func FindProcessPath(port uint16) (string, error) {
	var buf [C.PROC_PIDPATHINFO_MAXSIZE]C.char

	ret := C.find_process_path_by_port(C.uint16_t(port), &buf[0], C.size_t(len(buf)))
	switch {
	case ret == 0:
		return C.GoString(&buf[0]), nil
	case ret == 1:
		return "", ErrNotFound
	default:
		return "", fmt.Errorf("find process for port %d: %s", port, C.GoString(C.strerror(C.int(-ret))))
	}
}
