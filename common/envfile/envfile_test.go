package envfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_NoOverride(t *testing.T) {
	t.Setenv("EXISTING", "keep")
	dir := t.TempDir()
	p := filepath.Join(dir, ".env")
	if err := os.WriteFile(p, []byte(`
# comment
export A=1
B="two"
C='three'
EXISTING=replace
`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := Load(p, false); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("A"); got != "1" {
		t.Fatalf("A=%q", got)
	}
	if got := os.Getenv("B"); got != "two" {
		t.Fatalf("B=%q", got)
	}
	if got := os.Getenv("C"); got != "three" {
		t.Fatalf("C=%q", got)
	}
	if got := os.Getenv("EXISTING"); got != "keep" {
		t.Fatalf("EXISTING=%q", got)
	}
}
