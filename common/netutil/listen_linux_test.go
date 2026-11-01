package netutil

import (
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestListenTCPOverridesMPTCPEnvironment(t *testing.T) {
	t.Setenv("GODEBUG", "multipathtcp=2")
	listener, err := ListenTCP("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	raw, err := listener.(*net.TCPListener).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var protocol int
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		protocol, socketErr = unix.GetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_PROTOCOL)
	}); err != nil {
		t.Fatal(err)
	}
	if socketErr != nil || protocol != syscall.IPPROTO_TCP {
		t.Fatalf("listener protocol = %d, %v; want TCP", protocol, socketErr)
	}
}
