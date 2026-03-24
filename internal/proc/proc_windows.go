package proc

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// FindProcessPath returns the filesystem path of the process that owns
// the given TCP source port, or ErrNotFound if no process owns it.
func FindProcessPath(port uint16) (string, error) {
	tcpTable, err := getTCPTable()
	if err != nil {
		return "", fmt.Errorf("get tcp table: %v", err)
	}

	for _, r := range tcpTable {
		// dwLocalPort stores the port in network byte order (big-endian)
		// in the lower 16 bits; swap bytes to get host order.
		p := uint16(r.dwLocalPort)
		localPort := syscall.Ntohs(p)
		if localPort != port {
			continue
		}

		path, err := getProcPath(r.dwOwningPid)
		if err != nil {
			return "", fmt.Errorf("get process path by pid %d: %v", r.dwOwningPid, err)
		}
		return path, nil
	}
	return "", ErrNotFound
}

func getTCPTable() ([]mibTcpRowOwnerPid, error) {
	var bufSize uint32
	ret, _ := getExtendedTcpTable(nil, &bufSize, false, windows.AF_INET, tcpTableOwnerPidAll, 0)
	if ret != uint32(windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, fmt.Errorf("GetExtendedTcpTable size query: %w", syscall.Errno(ret))
	}

	for {
		table := make([]byte, bufSize)
		ret, _ = getExtendedTcpTable(&table[0], &bufSize, false, windows.AF_INET, tcpTableOwnerPidAll, 0)
		switch ret {
		case 0:
			dwNumEntries := int(*(*uint32)(unsafe.Pointer(&table[0])))
			return unsafe.Slice((*mibTcpRowOwnerPid)(unsafe.Pointer(&table[mibTcpTableOwnerPidTableOffset])), dwNumEntries), nil
		case uint32(windows.ERROR_INSUFFICIENT_BUFFER):
			continue
		default:
			return nil, fmt.Errorf("GetExtendedTcpTable: %w", syscall.Errno(ret))
		}
	}
}

func getProcPath(pid uint32) (string, error) {
	proc, err := openProcess(processQueryLimitedInformation, false, pid)
	if err != nil {
		return "", fmt.Errorf("OpenProcess: %v", err)
	}
	defer windows.CloseHandle(proc)

	bufSize := uint32(256)
	for {
		b := make([]uint16, bufSize)
		err := queryFullProcessImageName(proc, 0, &b[0], &bufSize)
		if errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			bufSize *= 2
			continue
		}
		if err != nil {
			return "", err
		}
		return windows.UTF16ToString(b[:bufSize]), nil
	}
}
