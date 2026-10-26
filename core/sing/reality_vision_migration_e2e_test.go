//go:build with_utls && !race

package sing

import "testing"

// The unchanged public upstream client uses uintptr-based TLS field access,
// which its checkptr instrumentation rejects. Keep public-client Vision wire
// interoperability here; the server's corrected pointer path has a separate
// race/checkptr regression in internal/compat/singvmess/vless.
func TestRealityMigrationVisionHandshake(t *testing.T) {
	runRealityHandshakes(t, []string{"vless"}, true)
}
