package proc

// FindProcessPath is not implemented on Windows.
func FindProcessPath(port uint16) (string, error) {
	return "", ErrUnsupported
}
