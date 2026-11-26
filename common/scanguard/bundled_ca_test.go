package scanguard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"path/filepath"
	"testing"

	"github.com/Designdocs/N2X/conf"
)

func TestBundledRelayCA(t *testing.T) {
	block, rest := pem.Decode(bundledRelayCA)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		t.Fatal("expected one public relay certificate")
	}
	hash := sha256.Sum256(block.Bytes)
	if hex.EncodeToString(hash[:]) != "ca26cfc9e510d9975a5a1931dd2816ddd71a77017140738372bddf6d5ca8ab1b" {
		t.Fatal("unexpected official relay CA")
	}
	roots, err := relayRoots("builtin")
	if err != nil {
		t.Fatal(err)
	}
	implicit, err := relayRoots("")
	if err != nil || !roots.Equal(implicit) {
		t.Fatal("feedback must use the same bundled root", err)
	}
	if _, err := relayRoots(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Fatal("silently replaced an explicitly configured CA")
	}
	for _, enabled := range []bool{false, true} {
		cfg := conf.WSScanGuardConfig{Enabled: enabled}
		if HasRelayCA(cfg) {
			t.Fatal("ordinary listener enabled relay trust")
		}
		cfg.FeedbackCertFile = "cert.pem"
		cfg.FeedbackKeyFile = "key.pem"
		if !HasRelayCA(cfg) {
			t.Fatal("configured feedback route lost relay trust")
		}
		cfg = conf.WSScanGuardConfig{Enabled: enabled, RelayCAFile: "builtin"}
		if !HasRelayCA(cfg) {
			t.Fatal("explicit bundled trust ignored")
		}
	}
}
