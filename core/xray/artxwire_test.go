package xray

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	coreConf "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/anytls"
	"github.com/xtls/xray-core/proxy/artx"
)

func TestBuildArtXWireInboundOwnsTLS(t *testing.T) {
	options := &conf.Options{CertConfig: &conf.CertConfig{
		CertMode: "file",
		CertFile: "/panel/cert.pem",
		KeyFile:  "/panel/key.pem",
	}}
	nodeInfo := &panel.NodeInfo{
		Type:     "artx",
		Security: panel.Tls,
		ArtX: &panel.ArtXNode{
			Underlay:       "artx-wire",
			WireVersion:    1,
			ProfileVersion: 1,
			Fallback: panel.ArtXFallback{
				Enabled: true,
				Origin:  "https://fallback.example.com/",
			},
		},
	}
	inbound := &coreConf.InboundDetourConfig{}

	if err := buildArtX(options, nodeInfo, inbound); err != nil {
		t.Fatalf("buildArtX returned error: %v", err)
	}
	if inbound.Protocol != "artx" {
		t.Fatalf("expected ArtX wire protocol, got %q", inbound.Protocol)
	}
	if !artXWireHandlesTLS(nodeInfo) {
		t.Fatal("expected ArtX wire handler to own TLS")
	}
	if inbound.StreamSetting == nil || inbound.StreamSetting.Security != "" || inbound.StreamSetting.TLSSettings != nil {
		t.Fatalf("expected generic transport TLS to remain unset, got %+v", inbound.StreamSetting)
	}

	var settings coreConf.ArtXServerConfig
	if inbound.Settings == nil {
		t.Fatal("expected ArtX wire settings")
	}
	if err := json.Unmarshal(*inbound.Settings, &settings); err != nil {
		t.Fatalf("unmarshal ArtX wire settings failed: %v", err)
	}
	if settings.WireVersion != 1 || settings.ProfileVersion != 1 {
		t.Fatalf("unexpected ArtX versions: %+v", settings)
	}
	if settings.TLSSettings == nil || len(settings.TLSSettings.Certs) != 1 {
		t.Fatalf("expected ArtX handler TLS certificate settings, got %+v", settings.TLSSettings)
	}
	if settings.Fallback == nil || !settings.Fallback.Enabled || settings.Fallback.Origin != "https://fallback.example.com/" {
		t.Fatalf("expected ArtX fallback settings, got %+v", settings.Fallback)
	}
}

func TestBuildArtXWireInboundRoutesInstalledDecoyByProfile(t *testing.T) {
	options := &conf.Options{CertConfig: &conf.CertConfig{
		CertMode: "file",
		CertFile: "/panel/cert.pem",
		KeyFile:  "/panel/key.pem",
	}}
	nodeInfo := &panel.NodeInfo{
		Type:     "artx",
		Security: panel.Tls,
		ArtX: &panel.ArtXNode{
			Underlay:       artXUnderlayWire,
			WireVersion:    artXWireVersion,
			Profile:        artXProfileMedia,
			ProfileVersion: artXWireProfileVersion,
			Fallback: panel.ArtXFallback{
				Enabled: true,
				Origin:  artXDecoySelector,
			},
		},
	}
	inbound := &coreConf.InboundDetourConfig{}

	if err := buildArtX(options, nodeInfo, inbound); err != nil {
		t.Fatalf("buildArtX returned error: %v", err)
	}

	var settings coreConf.ArtXServerConfig
	if inbound.Settings == nil {
		t.Fatal("expected ArtX wire settings")
	}
	if err := json.Unmarshal(*inbound.Settings, &settings); err != nil {
		t.Fatalf("unmarshal ArtX wire settings failed: %v", err)
	}
	wantOrigin := "http://127.0.0.1:60443/?profile=media"
	if settings.Fallback == nil || settings.Fallback.Origin != wantOrigin {
		t.Fatalf("installed decoy origin = %+v, want %q", settings.Fallback, wantOrigin)
	}
}

func TestBuildArtXUsersSelectsAccountByUnderlay(t *testing.T) {
	users := []panel.UserInfo{{Uuid: "test-psk"}}

	wireUsers := buildArtXUsers("artx", users, &panel.NodeInfo{ArtX: &panel.ArtXNode{Underlay: "artx-wire"}})
	wireAccount, err := wireUsers[0].Account.GetInstance()
	if err != nil {
		t.Fatalf("decode ArtX account failed: %v", err)
	}
	if account, ok := wireAccount.(*artx.Account); !ok || account.Psk != "test-psk" {
		t.Fatalf("expected xray.proxy.artx.Account, got %T", wireAccount)
	}

	scaffoldUsers := buildArtXUsers("artx", users, &panel.NodeInfo{ArtX: &panel.ArtXNode{Underlay: "anytls"}})
	scaffoldAccount, err := scaffoldUsers[0].Account.GetInstance()
	if err != nil {
		t.Fatalf("decode AnyTLS account failed: %v", err)
	}
	if account, ok := scaffoldAccount.(*anytls.Account); !ok || account.Password != "test-psk" {
		t.Fatalf("expected xray.proxy.anytls.Account, got %T", scaffoldAccount)
	}
}

func TestArtXWireTLSOwnershipDoesNotAffectAnyTLSScaffold(t *testing.T) {
	nodeInfo := &panel.NodeInfo{ArtX: &panel.ArtXNode{Underlay: "anytls"}}
	if artXWireHandlesTLS(nodeInfo) {
		t.Fatal("expected AnyTLS scaffold to keep generic transport TLS")
	}
}

func TestArtXWireBuildObservationUsesWireSpecificFields(t *testing.T) {
	node := &panel.ArtXNode{
		Underlay:       artXUnderlayWire,
		ProfileVersion: 1,
		Fallback: panel.ArtXFallback{
			Enabled: true,
			Origin:  artXDecoySelector,
		},
	}

	observation := newArtXWireBuildObservation(node, true)
	if observation.Protocol != "artx" || observation.Underlay != artXUnderlayWire {
		t.Fatalf("unexpected ArtX wire identity: %+v", observation)
	}
	if observation.ProfileVersion != 1 {
		t.Fatalf("unexpected profile version: %+v", observation)
	}
	if observation.FallbackMode != "installed-decoy" || !observation.FallbackAvailable {
		t.Fatalf("unexpected fallback observation: %+v", observation)
	}
}

func TestBuildArtXWireInboundRejectsUnsupportedProfileVersions(t *testing.T) {
	options := &conf.Options{CertConfig: &conf.CertConfig{
		CertMode: "file",
		CertFile: "/panel/cert.pem",
		KeyFile:  "/panel/key.pem",
	}}
	for _, version := range []int{0, 2, int(^uint(0) >> 1)} {
		t.Run(strconv.Itoa(version), func(t *testing.T) {
			nodeInfo := &panel.NodeInfo{ArtX: &panel.ArtXNode{
				Underlay:       "artx-wire",
				WireVersion:    1,
				ProfileVersion: version,
			}}
			err := buildArtX(options, nodeInfo, &coreConf.InboundDetourConfig{})
			if err == nil {
				t.Fatalf("expected profile version %d to be rejected", version)
			}
			if !strings.Contains(err.Error(), strconv.Itoa(version)) {
				t.Fatalf("expected error to include profile version %d, got %q", version, err)
			}
		})
	}
}
