//go:build linux || darwin

package scanguard

import (
	"errors"
	"io"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// Leave ordinary clients on their original TCP socket, including fast-path methods.
func directSocket(conn net.Conn) (bool, error) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return false, nil
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return false, err
	}
	var first [1]byte
	var readErr error
	err = raw.Read(func(fd uintptr) bool {
		var n int
		for {
			n, _, readErr = unix.Recvfrom(int(fd), first[:], unix.MSG_PEEK)
			if !errors.Is(readErr, syscall.EINTR) {
				break
			}
		}
		if errors.Is(readErr, syscall.EAGAIN) || errors.Is(readErr, syscall.EWOULDBLOCK) {
			return false
		}
		if n == 0 && readErr == nil {
			readErr = io.EOF
		}
		return true
	})
	if err != nil {
		return false, err
	}
	return first[0] != visitorMagic[0], readErr
}
