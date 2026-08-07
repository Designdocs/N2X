//go:build with_quic

package sing

import (
	"testing"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	vCore "github.com/Designdocs/N2X/core"
	"github.com/Designdocs/N2X/limiter"
)

// TestQUICLifecycle runs the QUIC protocols through the same add/remove
// sequence as the TCP ones. They are gated behind the with_quic build tag, so
// they live in their own file; without the tag Protocols() does not advertise
// them and the selector never routes a node here.
func TestQUICLifecycle(t *testing.T) {
	tests := []struct {
		name string
		info func(port int) *panel.NodeInfo
	}{
		{
			name: "hysteria2",
			info: func(port int) *panel.NodeInfo {
				return &panel.NodeInfo{
					Type:      "hysteria2",
					Security:  panel.Tls,
					Common:    &panel.CommonNode{ServerPort: port},
					Hysteria2: &panel.Hysteria2Node{UpMbps: 100, DownMbps: 100},
				}
			},
		},
		{
			// A panel that sends only "obfs" means the Salamander password;
			// see buildHysteria2Obfs.
			name: "hysteria2-lone-obfs",
			info: func(port int) *panel.NodeInfo {
				return &panel.NodeInfo{
					Type:      "hysteria2",
					Security:  panel.Tls,
					Common:    &panel.CommonNode{ServerPort: port},
					Hysteria2: &panel.Hysteria2Node{UpMbps: 100, DownMbps: 100, ObfsType: "a-shared-secret"},
				}
			},
		},
		{
			name: "hysteria2-obfs-pair",
			info: func(port int) *panel.NodeInfo {
				return &panel.NodeInfo{
					Type:     "hysteria2",
					Security: panel.Tls,
					Common:   &panel.CommonNode{ServerPort: port},
					Hysteria2: &panel.Hysteria2Node{
						UpMbps: 100, DownMbps: 100,
						ObfsType: "salamander", ObfsPassword: "a-shared-secret",
					},
				}
			},
		},
		{
			name: "hysteria",
			info: func(port int) *panel.NodeInfo {
				return &panel.NodeInfo{
					Type:     "hysteria",
					Security: panel.Tls,
					Common:   &panel.CommonNode{ServerPort: port},
					Hysteria: &panel.HysteriaNode{UpMbps: 100, DownMbps: 100},
				}
			},
		},
		{
			name: "tuic",
			info: func(port int) *panel.NodeInfo {
				return &panel.NodeInfo{
					Type:     "tuic",
					Security: panel.Tls,
					Common:   &panel.CommonNode{ServerPort: port},
					Tuic:     &panel.TuicNode{CongestionControl: "bbr"},
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core := newLifecycleCore(t)
			tag := "quic-" + tt.name
			limiter.AddLimiter(tag, &conf.LimitConfig{}, nil, nil)
			t.Cleanup(func() { limiter.DeleteLimiter(tag) })

			info := tt.info(freePort(t))
			if err := core.AddNode(tag, info, lifecycleOptions(t, true)); err != nil {
				t.Fatalf("AddNode: %v", err)
			}
			if _, found := core.box.Inbound().Get(tag); !found {
				t.Fatal("inbound was not created")
			}

			added, err := core.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: lifecycleUsers, NodeInfo: info})
			if err != nil {
				t.Fatalf("AddUsers: %v", err)
			}
			if added != len(lifecycleUsers) {
				t.Fatalf("added = %d, want %d", added, len(lifecycleUsers))
			}

			if err := core.DelUsers(lifecycleUsers, tag, info); err != nil {
				t.Fatalf("DelUsers: %v", err)
			}
			if err := core.DelNode(tag); err != nil {
				t.Fatalf("DelNode: %v", err)
			}
			if _, found := core.box.Inbound().Get(tag); found {
				t.Fatal("inbound outlived the node")
			}
		})
	}
}
