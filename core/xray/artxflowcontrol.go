package xray

import (
	"context"
	"errors"
	"fmt"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/artx"
)

// artXInbound resolves the running ArtX proxy behind one node tag. It is the
// only way into a live inbound's runtime knobs, and it fails rather than
// guessing when the tag belongs to some other protocol.
func (c *Xray) artXInbound(tag string) (*artx.Server, error) {
	inboundHandler, err := c.ihm.GetHandler(context.Background(), tag)
	if err != nil {
		return nil, err
	}
	getter, ok := inboundHandler.(proxy.GetInbound)
	if !ok {
		return nil, errors.New("ArtX inbound does not expose its proxy")
	}
	server, ok := getter.GetInbound().(*artx.Server)
	if !ok {
		return nil, errors.New("ArtX inbound proxy has an unexpected type")
	}
	return server, nil
}

// SetArtXFlowControl implements vCore.ArtXFlowControlProvider. It retiers a
// running inbound in place so an operator changing the panel's flow-control
// setting does not cost the node a full listener rebuild — and with it every
// established session.
//
// The panel name is mapped through artXFlowControlPolicy, the same mapping
// buildArtXWireInbound uses, so an in-place retier and a rebuild can never
// land on different settings for the same tier.
func (c *Xray) SetArtXFlowControl(tag string, node *panel.ArtXNode) error {
	if node == nil {
		return errors.New("artx flow control: no node settings")
	}
	maxWindowScale, auto, err := artXFlowControlPolicy(node)
	if err != nil {
		return err
	}
	server, err := c.artXInbound(tag)
	if err != nil {
		return fmt.Errorf("artx flow control: %w", err)
	}
	server.SetFlowControl(auto, maxWindowScale)
	return nil
}
