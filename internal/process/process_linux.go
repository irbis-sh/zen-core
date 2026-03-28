package process

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// FindBySourcePort returns the process that owns the given TCP source port,
// or ErrNotFound if no process owns it.
func FindBySourcePort(port uint16) (Process, error) {
	inode, err := findInode(port)
	if err != nil {
		return Process{}, fmt.Errorf("find inode: %v", err)
	}

	pid, err := findPid(inode)
	if err != nil {
		return Process{}, fmt.Errorf("find pid: %v", err)
	}

	path, err := findProcPath(pid)
	if err != nil {
		return Process{}, fmt.Errorf("find proc path: %v", err)
	}

	name := procName(pid, path)

	return Process{
		ID:       int(pid),
		Name:     name,
		DiskPath: path,
	}, nil
}

// findInode finds the inode corresponding to a file descriptor
// associated with a TCP socket with the given port.
func findInode(port uint16) (uint64, error) {
	f, err := os.Open("/proc/net/tcp")
	if err != nil {
		return 0, fmt.Errorf("open /proc/net/tcp: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan() // Skip header line.

	var inode string
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			return 0, fmt.Errorf("parse /proc/net/tcp: expected at least 10 fields, got %d", len(fields))
		}

		localAddr := fields[1]
		_, localPort, found := strings.Cut(localAddr, ":")
		if !found {
			return 0, fmt.Errorf("parse /proc/net/tcp: malformed local addr %q", localAddr)
		}

		localPortNum, err := strconv.ParseUint(localPort, 16, 16)
		if err != nil {
			return 0, fmt.Errorf("parse /proc/net/tcp: parse port %q: %v", localPort, err)
		}

		if uint64(port) == localPortNum {
			inode = fields[9]
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("read /proc/net/tcp: %v", err)
	}

	if inode == "" {
		return 0, ErrNotFound
	}

	inodeNum, err := strconv.ParseUint(inode, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse /proc/net/tcp: parse inode %q: %v", inode, err)
	}
	if inodeNum == 0 {
		return 0, fmt.Errorf("socket has already been closed")
	}

	return inodeNum, nil
}

func findPid(inode uint64) (uint32, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}

	target := fmt.Sprintf("socket:[%d]", inode)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue // Not a PID directory.
		}

		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // Permission denied or process gone.
		}

		for _, fd := range fds {
			if fd.Type() != fs.ModeSymlink {
				continue
			}

			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if link == target {
				return uint32(pid), nil
			}
		}
	}
	return 0, ErrNotFound
}

// procName determines the best display name for a process.
// It reads /proc/<pid>/comm and compares it against the basename of the exe path.
// If they diverge (comm was set via prctl(PR_SET_NAME)), comm wins.
// Otherwise the exe basename is used since comm may be truncated to 16 characters.
func procName(pid uint32, exePath string) string {
	comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return filepath.Base(exePath)
	}
	commStr := strings.TrimRight(string(comm), "\n")
	base := filepath.Base(exePath)

	// If comm diverges from base, it reflects a
	// custom name set via prctl(PR_SET_NAME) - use it.
	// Otherwise use base.
	commLen := len(commStr)
	baseLen := len(base)
	if commLen > baseLen || commStr != base[:commLen] {
		return commStr
	}
	return base
}

func findProcPath(pid uint32) (string, error) {
	exe := fmt.Sprintf("/proc/%d/exe", pid)
	path, err := os.Readlink(exe)
	if err != nil {
		return "", fmt.Errorf("readlink %q: %v", exe, err)
	}
	return path, nil
}
