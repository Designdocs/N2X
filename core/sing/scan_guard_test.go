package sing

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Designdocs/N2X/api/panel"

	"github.com/Designdocs/N2X/conf"
)

func TestSingRelayScanGuard(t *testing.T) {
	t.Setenv("N2X_WS_SCAN_STATE_DIR", t.TempDir())
	core := newLifecycleCore(t)
	core.scanConfig = conf.WSScanGuardConfig{Enabled: true, LogMaxMB: 10}
	for _, transport := range []string{"ws", "httpupgrade"} {
		t.Run(transport, func(t *testing.T) {
			tag := t.Name()
			port := freePort(t)
			info := &panel.NodeInfo{Type: "vless", Common: &panel.CommonNode{ServerPort: port}, VAllss: &panel.VAllssNode{Network: transport, NetworkSettings: json.RawMessage(`{"path":"/private"}`)}}
			if err := core.AddNode(tag, info, lifecycleOptions(t, false)); err != nil {
				t.Fatal(err)
			}
			defer core.DelNode(tag)
			resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/.env", port))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != 404 {
				t.Fatal(resp.StatusCode)
			}
			log, err := os.ReadFile(filepath.Join(os.Getenv("N2X_WS_SCAN_STATE_DIR"), "intercepts.jsonl"))
			if err != nil || !strings.Contains(string(log), tag) {
				t.Fatalf("missing interception: %v", err)
			}
		})
	}
}
