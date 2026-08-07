//go:build !with_quic

package sing

import (
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/dns"
)

// quicProtocols is empty without the with_quic build tag: TUIC, Hysteria and
// Hysteria2 all run over QUIC, so a build without it cannot serve them and
// must not advertise them to the selector.
var quicProtocols []string

func registerQUICInbounds(*inbound.Registry) {}

func registerQUICTransports(*dns.TransportRegistry) {}
