package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/Designdocs/N2X/common/exec"
)

const (
	red    = "\033[0;31m"
	green  = "\033[0;32m"
	yellow = "\033[0;33m"
	plain  = "\033[0m"
)

const defaultDNSFallbackNoticePath = "/etc/N2X/dns_fallback.notice"

func checkRunning() (bool, error) {
	o, err := exec.RunCommandByShell("systemctl status N2X | grep Active")
	if err != nil {
		return false, err
	}
	return strings.Contains(o, "running"), nil
}

func Err(msg ...any) string {
	return red + fmt.Sprint(msg...) + plain
}

func Ok(msg ...any) string {
	return green + fmt.Sprint(msg...) + plain
}

func Warn(msg ...any) string {
	return yellow + fmt.Sprint(msg...) + plain
}

func dnsFallbackWarning() string {
	notice, err := os.ReadFile(dnsFallbackNoticePath())
	if err != nil {
		return ""
	}
	text := strings.TrimSpace(string(notice))
	if text == "" {
		return ""
	}
	return Warn("提醒：", text)
}

func dnsFallbackNoticePath() string {
	if path := os.Getenv("N2X_DNS_FALLBACK_NOTICE_PATH"); path != "" {
		return path
	}
	return defaultDNSFallbackNoticePath
}
