package cmd

import "testing"

func TestResolveDecoyListenAddress(t *testing.T) {
	t.Setenv("N2X_ARTX_DECOY_LISTEN", "127.0.0.1:61000")

	if got := resolveDecoyListen(""); got != "127.0.0.1:61000" {
		t.Fatalf("environment address = %q", got)
	}
	if got := resolveDecoyListen("127.0.0.1:62000"); got != "127.0.0.1:62000" {
		t.Fatalf("flag address = %q", got)
	}
}

func TestDefaultDecoyListen(t *testing.T) {
	t.Setenv("N2X_ARTX_DECOY_LISTEN", "")

	if got := resolveDecoyListen(""); got != "127.0.0.1:60443" {
		t.Fatalf("default address = %q", got)
	}
}
