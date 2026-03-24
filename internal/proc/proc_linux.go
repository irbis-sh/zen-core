package proc

// FindProcessPath is not implemented on Linux.
func FindProcessPath(port uint16) (string, error) {
	return "", ErrUnsupported
}
