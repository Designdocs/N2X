package panel

import (
	"crypto/sha256"
	"fmt"
	"os"
	"regexp"
	"strings"
)

var instanceIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// Stable across restarts and independent of a shared NAT address. Operators
// running cloned hosts or several agents may pin N2X_INSTANCE_ID explicitly.
func backendInstanceID(apiHost string, nodeID int, sendIP string) string {
	if value := strings.TrimSpace(os.Getenv("N2X_INSTANCE_ID")); instanceIDPattern.MatchString(value) {
		return value
	}
	host, _ := os.Hostname()
	machine, _ := os.ReadFile("/etc/machine-id")
	identity := fmt.Sprintf("%s|%s|%s|%d|%s", host, strings.TrimSpace(string(machine)), apiHost, nodeID, sendIP)
	return fmt.Sprintf("n2x-%x", sha256.Sum256([]byte(identity)))
}
