package scanguard

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Designdocs/N2X/conf"
)

// RejectedStream runs after native authentication has rejected the connection.
// Inspect only the first HTTP/1 request line, never authenticated application data.
func RejectedStream(tag string, cfg conf.WSScanGuardConfig, conn net.Conn, prefix []byte, remaining io.Reader) bool {
	if !cfg.Enabled || len(prefix) == 0 {
		return false
	}
	if !couldStartHTTP(prefix) {
		return false
	}
	if !bytes.ContainsRune(prefix, '\n') {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	}
	reader := bufio.NewReader(io.LimitReader(io.MultiReader(bytes.NewReader(prefix), remaining), 8192))
	line, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	fields := strings.Split(strings.TrimSuffix(line, "\r\n"), " ")
	if len(fields) != 3 || !couldStartHTTP([]byte(fields[0]+" ")) || !strings.HasPrefix(fields[1], "/") || (fields[2] != "HTTP/1.0" && fields[2] != "HTTP/1.1") {
		return false
	}
	target, err := url.ParseRequestURI(fields[1])
	if err != nil {
		return false
	}
	r := &http.Request{Method: fields[0], URL: target}
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, conn.LocalAddr()))
	if !SensitiveFilter(tag, cfg)(r) {
		return false
	}
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.WriteString(conn, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	return true
}

func couldStartHTTP(prefix []byte) bool {
	for _, method := range [...]string{"GET ", "HEAD ", "POST ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "TRACE ", "CONNECT "} {
		n := min(len(method), len(prefix))
		if string(prefix[:n]) == method[:n] {
			return true
		}
	}
	return false
}
