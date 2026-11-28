package domainusage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStorageUsageMatchesQuotaWithoutOpeningDatabases(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "not-created", "stats")
	used, available := StorageUsage(missing)
	if used != 0 || available <= 0 {
		t.Fatalf("missing directory: %d, %d", used, available)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("created a directory")
	}
	file := filepath.Join(dir, "old.db")
	if err := os.WriteFile(file, []byte("old data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".quota.lock"), []byte("123"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(file, filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	used, available = StorageUsage(dir)
	if used != 11 || available <= 0 {
		t.Fatalf("got usage %d, free %d", used, available)
	}
}
