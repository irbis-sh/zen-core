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
