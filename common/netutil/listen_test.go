package netutil

import (
	"io"
	"net"
	"testing"
)

func TestMPTCPDisabledByDefault(t *testing.T) {
	// This also protects third-party listeners such as lego's HTTP-01 server.
	t.Setenv("GODEBUG", "")
	var config net.ListenConfig
	if config.MultipathTCP() {
		t.Fatal("main-module default must disable implicit MPTCP listeners")
	}
}

func TestListenTCPPreservesConnectionsAndBindErrors(t *testing.T) {
	t.Setenv("GODEBUG", "multipathtcp=2")
	listener, err := ListenTCP("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if duplicate, err := ListenTCP("tcp4", listener.Addr().String()); err == nil {
		duplicate.Close()
		t.Fatal("binding an occupied port must fail")
	}
	result := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		_, err = conn.Write([]byte("hello"))
		result <- err
	}()
	conn, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	data, err := io.ReadAll(conn)
	if err != nil || string(data) != "hello" {
		t.Fatalf("TCP exchange = %q, %v", data, err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}
