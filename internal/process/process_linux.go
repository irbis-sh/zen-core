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

	// An alternative approach would be to read /proc/pid/comm, but it's truncated
	// to 16 characters (which a lot of GUI programs exceed).
	// The downside with basenaming /proc/pid/exe is that it doesn't reflect prctl(PR_SET_NAME),
	// but I feel like it's an okay tradeoff to make.
	name := filepath.Base(path)

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

func findProcPath(pid uint32) (string, error) {
	exe := fmt.Sprintf("/proc/%d/exe", pid)
	path, err := os.Readlink(exe)
	if err != nil {
		return "", fmt.Errorf("readlink %q: %v", exe, err)
	}
	return path, nil
}
