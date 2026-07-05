package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDNSFallbackWarningReadsPersistedNotice(t *testing.T) {
	noticePath := filepath.Join(t.TempDir(), "dns-fallback.notice")
	t.Setenv("N2X_DNS_FALLBACK_NOTICE_PATH", noticePath)
	if err := os.WriteFile(noticePath, []byte("DNS 配置错误已降级为空配置：geosite:stabilityai 不存在\n"), 0644); err != nil {
		t.Fatalf("write fallback notice: %v", err)
	}

	warning := dnsFallbackWarning()
	if !strings.Contains(warning, "提醒：DNS 配置错误已降级为空配置") {
		t.Fatalf("expected command warning, got %q", warning)
	}
}
