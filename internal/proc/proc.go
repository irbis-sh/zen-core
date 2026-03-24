// proc resolves the filesystem path of the process that owns
// a given TCP port.
package proc

import "errors"

var (
	// ErrNotFound is returned when no process is found owning the given port.
	ErrNotFound = errors.New("no process found for port")

	// ErrUnsupported is returned on platforms where process path lookup
	// is not implemented.
	ErrUnsupported = errors.New("process path lookup is not supported on this platform")
)
