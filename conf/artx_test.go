package conf

import (
	"path/filepath"
	"testing"
)

func TestArtXOptionsParseFromNodeOptions(t *testing.T) {
	config := filepath.Join(t.TempDir(), "config.json")
	writeFile(t, config, `{
  "Nodes": [
    {
      "ApiConfig": { "ApiHost": "https://panel.example.com", "ApiKey": "k", "NodeID": 333, "NodeType": "artx" },
      "Options": {
        "Name": "artx",
        "Core": "xray",
        "ArtXOptions": { "WindowBudgetSharePercent": 40, "WindowBudgetReservePercent": 15 }
      }
    }
  ]
}`)

	c := New()
	if err := c.LoadFromPath(config); err != nil {
		t.Fatalf("load config: %v", err)
	}
	if len(c.NodeConfig) != 1 {
		t.Fatalf("nodes = %d, want 1", len(c.NodeConfig))
	}
	options := c.NodeConfig[0].Options.ArtXOptions
	if options == nil {
		t.Fatal("ArtXOptions block did not parse")
	}
	if options.WindowBudgetSharePercent != 40 || options.WindowBudgetReservePercent != 15 {
		t.Fatalf("ArtXOptions = %+v, want share 40 reserve 15", *options)
	}
}

func TestArtXOptionsAbsentBlockStaysNil(t *testing.T) {
	// A nil block is how the agent spells "take the core's defaults", so it
	// must stay distinguishable from a block of explicit zeros.
	config := filepath.Join(t.TempDir(), "config.json")
	writeFile(t, config, `{
  "Nodes": [
    {
      "ApiConfig": { "ApiHost": "https://panel.example.com", "ApiKey": "k", "NodeID": 333, "NodeType": "artx" },
      "Options": { "Name": "artx", "Core": "xray" }
    }
  ]
}`)

	c := New()
	if err := c.LoadFromPath(config); err != nil {
		t.Fatalf("load config: %v", err)
	}
	if got := c.NodeConfig[0].Options.ArtXOptions; got != nil {
		t.Fatalf("ArtXOptions = %+v, want nil for an absent block", *got)
	}
}
