package panel

import "testing"

func TestNormalizeShadowTLSNodeDefaults(t *testing.T) {
	node := &ShadowTLSNode{}
	node.ServerName = "node.example.com"

	normalizeShadowTLSNode(node)

	// v3 is the only version that resists active probing, so an unset or
	// out-of-range version must land there rather than on v1.
	if node.Version != 3 {
		t.Fatalf("version = %d, want 3", node.Version)
	}
	if node.Cipher != "2022-blake3-aes-128-gcm" {
		t.Fatalf("cipher = %q", node.Cipher)
	}
	if node.Handshake.Server != "node.example.com" {
		t.Fatalf("handshake server = %q", node.Handshake.Server)
	}
	if node.Handshake.ServerPort != 443 {
		t.Fatalf("handshake port = %d", node.Handshake.ServerPort)
	}
	if node.WildcardSNI != "off" {
		t.Fatalf("wildcard sni = %q", node.WildcardSNI)
	}
}

func TestNormalizeShadowTLSNodeFallsBackToHost(t *testing.T) {
	node := &ShadowTLSNode{}
	node.Host = "1.2.3.4"

	normalizeShadowTLSNode(node)

	if node.Handshake.Server != "1.2.3.4" {
		t.Fatalf("handshake server = %q, want the node host", node.Handshake.Server)
	}
}

func TestNormalizeShadowTLSNodePreservesExplicitValues(t *testing.T) {
	node := &ShadowTLSNode{
		Version:     2,
		Cipher:      "aes-256-gcm",
		Handshake:   ShadowTLSHandshake{Server: "www.apple.com", ServerPort: 8443},
		WildcardSNI: "ALL",
	}

	normalizeShadowTLSNode(node)

	if node.Version != 2 || node.Cipher != "aes-256-gcm" {
		t.Fatalf("explicit values overwritten: %#v", node)
	}
	if node.Handshake.Server != "www.apple.com" || node.Handshake.ServerPort != 8443 {
		t.Fatalf("handshake = %#v", node.Handshake)
	}
	// Case is normalised so downstream comparisons stay simple.
	if node.WildcardSNI != "all" {
		t.Fatalf("wildcard sni = %q, want lowercased", node.WildcardSNI)
	}
}

func TestNormalizeShadowTLSNodeRejectsBadVersion(t *testing.T) {
	for _, version := range []int{-1, 0, 4, 99} {
		node := &ShadowTLSNode{Version: version}
		node.Host = "h"
		normalizeShadowTLSNode(node)
		if node.Version != 3 {
			t.Fatalf("version %d normalised to %d, want 3", version, node.Version)
		}
	}
}
