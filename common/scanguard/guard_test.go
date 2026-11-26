package scanguard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWSScanAuditRotation(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 20; i++ {
		if err := appendWSAudit(root, []byte("event\n"), 32); err != nil {
			t.Fatal(err)
		}
	}
	var size int64
	for _, name := range []string{"intercepts.jsonl", "intercepts.jsonl.1"} {
		fi, err := os.Stat(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		size += fi.Size()
	}
	if size > 32 {
		t.Fatalf("logs occupy %d bytes", size)
	}
}
