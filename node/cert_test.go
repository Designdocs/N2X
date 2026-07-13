package node

import (
	"path/filepath"
	"testing"
)

func Test_generateSelfSslCertificate(t *testing.T) {
	directory := t.TempDir()
	certificatePath := filepath.Join(directory, "certificate.pem")
	keyPath := filepath.Join(directory, "certificate.key")
	if err := generateSelfSslCertificate("domain.com", certificatePath, keyPath); err != nil {
		t.Fatal(err)
	}
}
