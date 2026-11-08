package xray

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"encoding/json/v2"

	"github.com/Designdocs/N2X/conf"
	vCore "github.com/Designdocs/N2X/core"
	"github.com/Designdocs/N2X/core/xray/app/dispatcher"
	_ "github.com/Designdocs/N2X/core/xray/distro/all"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

var _ vCore.Core = (*Xray)(nil)

func init() {
	vCore.RegisterCore("xray", New)
}

// Xray Structure
type Xray struct {
	access                    sync.Mutex
	Server                    *core.Instance
	ihm                       inbound.Manager
	ohm                       outbound.Manager
	dispatcher                *dispatcher.DefaultDispatcher
	users                     *UserMap
	nodeReportMinTrafficBytes map[string]int64
	nativeUDPMu               sync.Mutex
	nativeUDP                 map[string]*nativeUDPService
	nativeUDPState            map[string]*nativeUDPState
}

type UserMap struct {
	uidMap  map[string]int
	mapLock sync.RWMutex
}

func New(c *conf.CoreConfig) (vCore.Core, error) {
	return &Xray{
		Server: getCore(c.XrayConfig),
		users: &UserMap{
			uidMap: make(map[string]int),
		},
		nodeReportMinTrafficBytes: make(map[string]int64),
		nativeUDP:                 make(map[string]*nativeUDPService),
		nativeUDPState:            make(map[string]*nativeUDPState),
	}, nil
}

func parseConnectionConfig(c *conf.XrayConnectionConfig) (policy *coreConf.Policy) {
	policy = &coreConf.Policy{
		StatsUserUplink:   c.StatsUserUplink,
		StatsUserDownlink: c.StatsUserDownlink,
		Handshake:         &c.Handshake,
		ConnectionIdle:    &c.ConnIdle,
		UplinkOnly:        &c.UplinkOnly,
		DownlinkOnly:      &c.DownlinkOnly,
		BufferSize:        &c.BufferSize,
	}
	return
}

func getCore(c *conf.XrayConfig) *core.Instance {
	os.Setenv("XRAY_LOCATION_ASSET", c.AssetPath)
	dispatcher.SetBTExtraSniffing(c.BTExtraSniffingEnabled())
	// Log Config
	coreLogConfig := &coreConf.LogConfig{
		LogLevel:  c.LogConfig.Level,
		AccessLog: c.LogConfig.AccessPath,
		ErrorLog:  c.LogConfig.ErrorPath,
	}
	// DNS config
	coreDnsConfig := &coreConf.DNSConfig{}
	os.Setenv("XRAY_DNS_PATH", "")
	if c.DnsConfigPath != "" {
		data, err := os.ReadFile(c.DnsConfigPath)
		if err != nil {
			log.Error(fmt.Sprintf("Failed to read xray dns config file: %v", err))
			coreDnsConfig = &coreConf.DNSConfig{}
		} else {
			if err := json.Unmarshal(data, coreDnsConfig); err != nil {
				log.Error(fmt.Sprintf("Failed to unmarshal xray dns config: %v. Using default DNS options.", err))
				coreDnsConfig = &coreConf.DNSConfig{}
			}
		}
		os.Setenv("XRAY_DNS_PATH", c.DnsConfigPath)
	}
	dnsConfig, err := coreDnsConfig.Build()
	if err != nil {
		recordDNSFallbackNotice("DNS 配置错误已降级为空配置", err)
		log.WithField("err", err).Error("Failed to understand DNS config, using default DNS options. Please check: https://xtls.github.io/config/dns.html for help")
		coreDnsConfig = &coreConf.DNSConfig{}
		dnsConfig, err = coreDnsConfig.Build()
		if err != nil {
			log.WithField("err", err).Panic("Failed to build default DNS config")
		}
	}
	routeConfig, err := buildRouteConfig(c)
	if err != nil {
		log.WithField("err", err).Panic("Failed to understand Routing config. Please check: https://xtls.github.io/config/routing.html for help")
	}
	// Custom Inbound config
	var coreCustomInboundConfig []coreConf.InboundDetourConfig
	if c.InboundConfigPath != "" {
		data, err := os.ReadFile(c.InboundConfigPath)
		if err != nil {
			log.WithField("err", err).Panic("Failed to read Custom Inbound config file")
		} else {
			if err = json.Unmarshal(data, &coreCustomInboundConfig); err != nil {
				log.WithField("err", err).Panic("Failed to unmarshal Custom Inbound config")
			}
		}
	}
	var inBoundConfig []*core.InboundHandlerConfig
	for _, config := range coreCustomInboundConfig {
		oc, err := config.Build()
		if err != nil {
			log.WithField("err", err).Panic("Failed to understand Inbound config. Please check: https://xtls.github.io/config/inbound.html for help")
		}
		inBoundConfig = append(inBoundConfig, oc)
	}
	outboundDefinitions, err := readOutboundDefinitions(c)
	if err != nil {
		log.WithField("err", err).Panic("Failed to understand Custom Outbound config")
	}
	// Policy config
	levelPolicyConfig := parseConnectionConfig(c.ConnectionConfig)
	corePolicyConfig := &coreConf.PolicyConfig{}
	corePolicyConfig.Levels = map[uint32]*coreConf.Policy{0: levelPolicyConfig}
	policyConfig, _ := corePolicyConfig.Build()
	app := []*serial.TypedMessage{
		serial.ToTypedMessage(coreLogConfig.Build()),
		serial.ToTypedMessage(&dispatcher.Config{}),
		serial.ToTypedMessage(&stats.Config{}),
		serial.ToTypedMessage(&proxyman.InboundConfig{}),
	}
	ctx := context.Background()
	var manager *outboundManager
	if c.OutboundConfigPath == "" {
		app = append(app, serial.ToTypedMessage(&proxyman.OutboundConfig{}))
	} else {
		manager, err = newOutboundManager(ctx)
		if err != nil {
			log.WithField("err", err).Panic("Failed to create outbound manager")
		}
		ctx = dispatcher.WithOutboundManager(ctx, manager)
	}
	app = append(app, serial.ToTypedMessage(policyConfig), serial.ToTypedMessage(dnsConfig), serial.ToTypedMessage(routeConfig))
	server, err := core.NewWithContext(ctx, &core.Config{App: app, Inbound: inBoundConfig})
	if err != nil {
		log.WithField("err", err).Panic("failed to create instance")
	}
	if manager != nil {
		finish, err := manager.prepare(outboundDefinitions, outboundFactory(server), false, nil)
		if err != nil {
			_ = server.Close()
			log.WithField("err", err).Panic("Failed to create Custom Outbound handlers")
		}
		finish(true)
	}
	log.Info("Xray Core Version: ", core.Version())
	return server
}

// Start the Xray
func (c *Xray) Start() error {
	c.access.Lock()
	defer c.access.Unlock()
	if err := c.Server.Start(); err != nil {
		return err
	}
	c.ihm = c.Server.GetFeature(inbound.ManagerType()).(inbound.Manager)
	c.ohm = c.Server.GetFeature(outbound.ManagerType()).(outbound.Manager)
	c.dispatcher = c.Server.GetFeature(routing.DispatcherType()).(*dispatcher.DefaultDispatcher)
	return nil
}

// Close  the core
func (c *Xray) Close() error {
	c.access.Lock()
	defer c.access.Unlock()
	nativeUDPErr := c.closeNativeUDP()
	c.ihm = nil
	c.ohm = nil
	c.dispatcher = nil
	return errors.Join(nativeUDPErr, c.Server.Close())
}

func (c *Xray) Protocols() []string {
	return []string{
		"vmess",
		"vless",
		"anytls",
		"artx",
		"shadowsocks",
		"trojan",
	}
}

func (c *Xray) Type() string {
	return "xray"
}
