// process resolves the filesystem path of the process that owns
// a given TCP port.
package process

import "errors"

type Process struct {
	ID       int
	Name     string
	DiskPath string
}

var (
	// ErrNotFound is returned when no process is found owning the given port.
	ErrNotFound = errors.New("no process found for port")
)
