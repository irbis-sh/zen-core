package process_test

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/ZenPrivacy/zen-core/internal/process"
)

func TestFindBySourcePort(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverConn := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		serverConn <- c
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if sc := <-serverConn; sc != nil {
		defer sc.Close()
	}

	port := conn.LocalAddr().(*net.TCPAddr).Port

	proc, err := process.FindBySourcePort(uint16(port)) // #nosec G115 -- port will fit in uint16
	if err != nil {
		t.Fatalf("FindBySourcePort(%d): %v", port, err)
	}

	if proc.ID != os.Getpid() {
		t.Errorf("PID = %d, want %d", proc.ID, os.Getpid())
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	if proc.DiskPath != exe {
		t.Errorf("DiskPath = %q, want %q", proc.DiskPath, exe)
	}
}
