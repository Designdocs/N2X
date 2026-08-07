package sing

import (
	"errors"
	"fmt"
	"os"

	"encoding/json"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	"github.com/sagernet/sing-box/option"
	F "github.com/sagernet/sing/common/format"
)

func (b *Sing) AddNode(tag string, info *panel.NodeInfo, config *conf.Options) error {
	if err := ensureSingOptions(config); err != nil {
		return err
	}
	b.setReportMinTraffic(tag, config.ReportMinTraffic*1024)
	b.nodeTypes.Store(tag, info.Type)

	var err error
	switch info.Type {
	case "naive":
		err = b.registerNaiveNode(tag, info, config)
	case "shadowtls":
		err = b.addShadowTLSNode(tag, info, config)
	default:
		var in option.Inbound
		in, err = getInboundOptions(tag, info, config)
		if err == nil {
			err = b.createInbound(tag, in)
		}
	}
	if err != nil {
		b.nodeTypes.Delete(tag)
		b.deleteReportMinTraffic(tag)
		return err
	}
	return nil
}

// addShadowTLSNode brings up the detour before the public listener and rolls
// the detour back if the listener fails, so a failed AddNode never leaves a
// half-built node behind.
func (b *Sing) addShadowTLSNode(tag string, info *panel.NodeInfo, config *conf.Options) error {
	inbounds, err := buildShadowTLSInbounds(tag, info, config)
	if err != nil {
		return err
	}
	var created []string
	for _, in := range inbounds {
		if err := b.createInbound(in.Tag, in); err != nil {
			for i := len(created) - 1; i >= 0; i-- {
				if removeErr := b.box.Inbound().Remove(created[i]); removeErr != nil && !errors.Is(removeErr, os.ErrInvalid) {
					err = errors.Join(err, fmt.Errorf("rollback %s: %w", created[i], removeErr))
				}
			}
			return err
		}
		created = append(created, in.Tag)
	}
	// Route the detour's traffic and limits back to the node that owns it.
	b.detourOwners.Store(detourTag(tag), tag)
	return nil
}

func (b *Sing) createInbound(tag string, in option.Inbound) error {
	err := b.box.Inbound().Create(
		b.ctx,
		b.router,
		b.logFactory.NewLogger(F.ToString("inbound/", in.Type, "[", tag, "]")),
		tag,
		in.Type,
		in.Options,
	)
	if err != nil {
		return fmt.Errorf("add inbound error: %w", err)
	}
	return nil
}

func (b *Sing) DelNode(tag string) error {
	nodeType, _ := b.nodeTypes.Load(tag)
	b.nodeTypes.Delete(tag)
	b.deleteReportMinTraffic(tag)
	b.hookServer.counter.Delete(tag)

	switch nodeType {
	case "naive":
		return b.unregisterNaiveNode(tag)
	case "shadowtls":
		detour := detourTag(tag)
		b.detourOwners.Delete(detour)
		return errors.Join(
			b.removeInbound(tag),
			b.removeInbound(detour),
		)
	default:
		return b.removeInbound(tag)
	}
}

func (b *Sing) removeInbound(tag string) error {
	if err := b.box.Inbound().Remove(tag); err != nil {
		if errors.Is(err, os.ErrInvalid) {
			// Already gone; deleting an absent inbound is not a failure.
			return nil
		}
		return fmt.Errorf("delete inbound %s error: %w", tag, err)
	}
	return nil
}

// ensureSingOptions fills in the sing-specific options when the node config
// did not carry them. This happens when a single-core deployment omits the
// "Core" field, in which case conf keeps the raw JSON instead of decoding it.
func ensureSingOptions(config *conf.Options) error {
	if config.SingOptions != nil {
		return nil
	}
	config.SingOptions = conf.NewSingOptions()
	if len(config.RawOptions) == 0 {
		return nil
	}
	if err := json.Unmarshal(config.RawOptions, config.SingOptions); err != nil {
		return fmt.Errorf("unmarshal sing options error: %w", err)
	}
	return nil
}
