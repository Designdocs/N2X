package conf

// ArtXOptions carries the host-level knobs a native ArtX wire node exposes.
// The whole block is optional and every field defaults to the core's own
// value, so an existing config keeps behaving exactly as before an upgrade.
type ArtXOptions struct {
	// WindowBudgetSharePercent is the share of total host memory ArtX may
	// commit to receive windows, 1..100. The budget is divided across the
	// connections that are live at accept time, so it decides how many
	// concurrent users still get the widest window. 0 keeps the core default
	// of 25.
	WindowBudgetSharePercent uint64 `json:"WindowBudgetSharePercent"`

	// WindowBudgetReservePercent is the share of total host memory that must
	// stay available to everything else; the budget is trimmed so ArtX's
	// windows cannot drive available memory below it. 1..99, and 0 keeps the
	// core default of 20.
	WindowBudgetReservePercent uint64 `json:"WindowBudgetReservePercent"`
}
