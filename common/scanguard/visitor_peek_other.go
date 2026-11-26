//go:build !linux && !darwin

package scanguard

import "net"

func directSocket(net.Conn) (bool, error) { return false, nil }
