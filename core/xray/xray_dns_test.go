package xray

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Designdocs/N2X/conf"
)

func TestGetCoreFallsBackWhenDNSFileReferencesMissingGeositeCode(t *testing.T) {
	noticePath := filepath.Join(t.TempDir(), "dns-fallback.notice")
	t.Setenv("N2X_DNS_FALLBACK_NOTICE_PATH", noticePath)
	dnsPath := filepath.Join(t.TempDir(), "dns.json")
	dns := []byte(`{"servers":[{"address":"8.8.8.8","domains":["geosite:stabilityai"]}]}`)
	if err := os.WriteFile(dnsPath, dns, 0644); err != nil {
		t.Fatalf("write dns config: %v", err)
	}

	config := conf.NewXrayConfig()
	config.AssetPath = filepath.Join("..", "..", "example")
	config.DnsConfigPath = dnsPath

	server := getCore(config)
	if server == nil {
		t.Fatal("expected xray core to start with default DNS fallback")
	}
	if err := server.Close(); err != nil {
		t.Fatalf("close xray core: %v", err)
	}

	notice, err := os.ReadFile(noticePath)
	if err != nil {
		t.Fatalf("read fallback notice: %v", err)
	}
	if !strings.Contains(string(notice), "DNS 配置错误已降级为空配置") {
		t.Fatalf("expected fallback notice, got %q", notice)
	}
}

func TestSaveDnsConfigKeepsCurrentFileWhenNewConfigReferencesMissingGeositeCode(t *testing.T) {
	noticePath := filepath.Join(t.TempDir(), "dns-fallback.notice")
	t.Setenv("N2X_DNS_FALLBACK_NOTICE_PATH", noticePath)
	t.Setenv("XRAY_LOCATION_ASSET", filepath.Join("..", "..", "example"))
	dnsPath := filepath.Join(t.TempDir(), "dns.json")
	currentDNS := []byte(`{"servers":["1.1.1.1","localhost"],"tag":"dns_inbound"}`)
	if err := os.WriteFile(dnsPath, currentDNS, 0644); err != nil {
		t.Fatalf("write current dns config: %v", err)
	}

	invalidDNS := []byte(`{"servers":[{"address":"8.8.8.8","domains":["geosite:stabilityai"]}]}`)
	if err := saveDnsConfig(invalidDNS, dnsPath); err != nil {
		t.Fatalf("expected invalid panel DNS to be ignored, got error: %v", err)
	}

	keptDNS, err := os.ReadFile(dnsPath)
	if err != nil {
		t.Fatalf("read dns config: %v", err)
	}
	if string(keptDNS) != string(currentDNS) {
		t.Fatalf("expected current DNS config to be kept, got %s", keptDNS)
	}

	notice, err := os.ReadFile(noticePath)
	if err != nil {
		t.Fatalf("read fallback notice: %v", err)
	}
	if !strings.Contains(string(notice), "新的 DNS 配置错误，已保留上一份配置") {
		t.Fatalf("expected fallback notice, got %q", notice)
	}
}
