package xray

import (
	"strings"
	"testing"

	"github.com/Designdocs/N2X/api/panel"
)

// The tier is mapped before the inbound is looked up, so a rejected tier can
// never reach a live node — checked here on a zero-value Xray, which has no
// inbound manager to reach at all.
func TestSetArtXFlowControlRejectsBadInputBeforeTouchingTheInbound(t *testing.T) {
	core := &Xray{}
	if err := core.SetArtXFlowControl("tag", nil); err == nil {
		t.Fatal("a missing ArtX block should be rejected")
	}
	err := core.SetArtXFlowControl("tag", &panel.ArtXNode{FlowControl: "turbo"})
	if err == nil || !strings.Contains(err.Error(), "turbo") {
		t.Fatalf("an unsupported tier should be rejected by name, got %v", err)
	}
}
