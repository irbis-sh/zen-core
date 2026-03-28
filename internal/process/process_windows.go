package process

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// FindProcess returns the process that owns the given TCP source port,
// or ErrNotFound if no process owns it.
func FindProcessBySourcePort(port uint16) (Process, error) {
	tcpTable, err := getTCPTable()
	if err != nil {
		return Process{}, fmt.Errorf("get tcp table: %v", err)
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
			return Process{}, fmt.Errorf("get process path by pid %d: %v", r.dwOwningPid, err)
		}
		name, _ := getFileDescription(path)
		return Process{
			ID:       int(r.dwOwningPid),
			Name:     name,
			DiskPath: path,
		}, nil
	}
	return Process{}, ErrNotFound
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

// getFileDescription returns the FileDescription from the executable's
// version info resource. This is the friendly name shown in Task Manager
// (e.g. "Firefox" for firefox.exe).
func getFileDescription(path string) (string, error) {
	pathUTF16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}

	size, err := getFileVersionInfoSize(pathUTF16, nil)
	if err != nil {
		return "", fmt.Errorf("GetFileVersionInfoSize: %w", err)
	}

	data := make([]byte, size)
	if err := getFileVersionInfo(pathUTF16, 0, size, &data[0]); err != nil {
		return "", fmt.Errorf("GetFileVersionInfo: %w", err)
	}

	// Query \VarFileInfo\Translation to get the language/codepage pairs.
	var transPtr uintptr
	var transLen uint32
	transQuery, _ := windows.UTF16PtrFromString(`\VarFileInfo\Translation`)
	if err := verQueryValue(&data[0], transQuery, &transPtr, &transLen); err != nil {
		return "", fmt.Errorf("VerQueryValue(Translation): %w", err)
	}
	if transLen < uint32(unsafe.Sizeof(langAndCodePage{})) {
		return "", fmt.Errorf("no translation entries in version info")
	}

	trans := (*langAndCodePage)(unsafe.Pointer(transPtr))
	query := fmt.Sprintf(`\StringFileInfo\%04x%04x\FileDescription`, trans.wLanguage, trans.wCodePage)
	queryUTF16, _ := windows.UTF16PtrFromString(query)

	var descPtr uintptr
	var descLen uint32
	if err := verQueryValue(&data[0], queryUTF16, &descPtr, &descLen); err != nil {
		return "", fmt.Errorf("VerQueryValue(FileDescription): %w", err)
	}
	if descLen == 0 {
		return "", nil
	}

	desc := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(descPtr)))
	return desc, nil
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
