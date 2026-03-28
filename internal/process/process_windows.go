package process

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// FindBySourcePort returns the process that owns the given TCP source port,
// or ErrNotFound if no process owns it.
func FindBySourcePort(port uint16) (Process, error) {
	pid, err := findPidByPort(port)
	if err != nil {
		return Process{}, err
	}

	path, err := getProcPath(pid)
	if err != nil {
		return Process{}, fmt.Errorf("get process path by pid %d: %v", pid, err)
	}

	name, _ := getFileDescription(path)
	return Process{
		ID:       int(pid),
		Name:     name,
		DiskPath: path,
	}, nil
}

func findPidByPort(port uint16) (uint32, error) {
	tcpTable, err := getTCPTable()
	if err != nil {
		return 0, fmt.Errorf("get tcp table: %v", err)
	}

	// Pre-convert to network byte order.
	netPort := port<<8 | port>>8

	for _, r := range tcpTable {
		if uint16(r.dwLocalPort) == netPort {
			return r.dwOwningPid, nil
		}
	}
	return 0, ErrNotFound
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

// getFileDescription returns the FileDescription from the executable's version info resource.
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
