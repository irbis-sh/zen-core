package proc

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go syscall_windows.go

//sys getExtendedTcpTable(pTcpTable *byte, pdwSize *uint32, bOrder bool, ulAf uint32, tableClass uint32, reserved uint32) (ret uint32, err error) = iphlpapi.GetExtendedTcpTable
//sys queryFullProcessImageName(process handle, flags uint32, buffer *uint16, bufferSize *uint32) (err error) = kernel32.QueryFullProcessImageNameW
//sys openProcess(desiredAccess uint32, inheritHandle bool, processId uint32) (process handle, err error) = kernel32.OpenProcess

// https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcprow_owner_pid
type mibTcpRowOwnerPid struct {
	dwState, dwLocalAddr, dwLocalPort, dwRemoteAddr, dwRemotePort, dwOwningPid uint32
}

type mibTcpTableOwnerPid struct {
	DwNumEntries uint32
	Table        [1]mibTcpRowOwnerPid
}

type handle = windows.Handle

const (
	tcpTableOwnerPidAll            = 5
	mibTcpTableOwnerPidTableOffset = unsafe.Offsetof(mibTcpTableOwnerPid{}.Table)
	// https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
	processQueryLimitedInformation = 0x1000
)
