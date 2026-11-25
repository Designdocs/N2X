//go:build with_utls && !race

package xray

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Designdocs/N2X/conf"
)

func TestRealityFallbackRateLimits(t *testing.T) {
	const flow = "xtls-rprx-vision"
	payload := bytes.Repeat([]byte("reality01"), 65536) // 576 KiB
	decoy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, err := io.ReadAll(r.Body)
			if err != nil || !bytes.Equal(body, payload) {
				http.Error(w, "upload mismatch", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Write(payload)
	}))
	decoy.EnableHTTP2 = true
	decoy.TLS = &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}}
	decoy.StartTLS()
	defer decoy.Close()
	host, port, err := net.SplitHostPort(decoy.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, config     string
		upload, download bool
	}{
		{"default", `{"Core":"xray"}`, false, false},
		{"upload_only", `{"Core":"xray","limitFallbackUpload":{"bytesPerSec":131072}}`, true, false},
		{"download_only", `{"Core":"xray","limitFallbackDownload":{"bytesPerSec":131072}}`, false, true},
		{"both", `{"Core":"xray","limitFallbackUpload":{"bytesPerSec":131072},"limitFallbackDownload":{"bytesPerSec":131072}}`, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var node conf.NodeConfig
			if err := json.Unmarshal([]byte(tc.config), &node); err != nil {
				t.Fatal(err)
			}
			node.Options.ListenIP = "127.0.0.1"
			addr := startRealityNode(t, host, port, base64.RawURLEncoding.EncodeToString(key.Bytes()), flow, &node.Options)
			// Each direction gets a fresh, unauthenticated TLS connection and bucket.
			tr := decoy.Client().Transport.(*http.Transport).Clone()
			tr.DisableKeepAlives = true
			tr.DisableCompression = true
			client := &http.Client{Transport: tr, Timeout: 12 * time.Second}
			defer tr.CloseIdleConnections()
			for _, direction := range []struct {
				method  string
				limited bool
			}{{http.MethodPost, tc.upload}, {http.MethodGet, tc.download}} {
				var data io.Reader
				if direction.method == http.MethodPost {
					data = bytes.NewReader(payload)
				}
				req, err := http.NewRequest(direction.method, "https://"+addr, data)
				if err != nil {
					t.Fatal(err)
				}
				start := time.Now()
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				elapsed := time.Since(start)
				if direction.method == http.MethodPost && resp.StatusCode != http.StatusNoContent ||
					direction.method == http.MethodGet && (resp.StatusCode != http.StatusOK || !bytes.Equal(body, payload)) {
					t.Fatalf("%s failed: status %d, %d bytes", direction.method, resp.StatusCode, len(body))
				}
				t.Logf("fallback %s %d bytes in %v", direction.method, len(payload), elapsed)
				// After the initially full 128 KiB bucket, 448 KiB takes 3.5 s.
				if direction.limited && (elapsed < 2500*time.Millisecond || elapsed > 6*time.Second) ||
					!direction.limited && elapsed >= 2*time.Second {
					t.Fatalf("%s limited=%v: unexpected duration %v", direction.method, direction.limited, elapsed)
				}
			}
			if !tc.upload || !tc.download {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			conn := dialXrayRealityClient(t, ctx, addr, startTCPEcho(t), base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), flow, "chrome")
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(15 * time.Second))
			// Complete the handshake before timing authenticated application data.
			for _, data := range [][]byte{[]byte("warmup"), payload} {
				start := time.Now()
				if _, err := conn.Write(data); err != nil {
					t.Fatal(err)
				}
				reply := make([]byte, len(data))
				if _, err := io.ReadFull(conn, reply); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(reply, data) {
					t.Fatal("authenticated echo mismatch")
				}
				if len(data) == len(payload) {
					elapsed := time.Since(start)
					t.Logf("authenticated echo %d bytes each way in %v", len(data), elapsed)
					if elapsed >= 2*time.Second {
						t.Fatalf("authenticated transfer took %v", elapsed)
					}
				}
			}
		})
	}
}
