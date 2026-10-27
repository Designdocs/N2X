package node

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Designdocs/N2X/common/ddns"
	"github.com/Designdocs/N2X/conf"
	log "github.com/sirupsen/logrus"
)

type ddnsUpdater interface {
	Update(context.Context) error
}

// Own DDNS at the node-set level: it must keep running even if certificate
// issuance or panel bootstrap fails, and must stop before a config reload.
func (n *Node) startDDNS(ctx context.Context, nodes []conf.NodeConfig) error {
	type worker struct {
		config  conf.DDNSConfig
		updater ddnsUpdater
	}
	var workers []worker
	seen := map[[32]byte]bool{}
	for i := range nodes {
		options := &nodes[i].Options
		if !options.DDNSConfig.Enabled {
			continue
		}
		config := options.DDNSConfig.Effective(options.CertConfig)
		if err := config.Validate(); err != nil {
			return fmt.Errorf("Nodes[%d].DDNSConfig: %w", i, err)
		}
		encoded, _ := json.Marshal(config)
		key := sha256.Sum256(encoded)
		if seen[key] {
			continue
		}
		seen[key] = true
		var updater ddnsUpdater
		var err error
		if n.newDDNSUpdater != nil {
			updater, err = n.newDDNSUpdater(config)
		} else {
			updater, err = ddns.New(config)
		}
		if err != nil {
			return fmt.Errorf("Nodes[%d].DDNSConfig: %w", i, err)
		}
		workers = append(workers, worker{config, updater})
	}
	for _, w := range workers {
		// First update precedes controller startup and HTTP certificate issuance.
		syncDDNS(ctx, w.config, w.updater)
		log.WithFields(log.Fields{"domain": w.config.Domain, "provider": w.config.Provider,
			"record_type": w.config.RecordType, "interval": w.config.Interval}).Info("DDNS enabled")
		n.ddnsWG.Add(1)
		go func() {
			defer n.ddnsWG.Done()
			runDDNS(ctx, w.config, w.updater, time.Duration(w.config.Interval)*time.Second)
		}()
	}
	return nil
}

func runDDNS(ctx context.Context, config conf.DDNSConfig, updater ddnsUpdater, interval time.Duration) {
	if closer, ok := updater.(interface{ Close() }); ok {
		defer closer.Close()
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			syncDDNS(ctx, config, updater)
		}
	}
}

func syncDDNS(ctx context.Context, config conf.DDNSConfig, updater ddnsUpdater) {
	if ctx.Err() != nil {
		return
	}
	if err := updater.Update(ctx); err != nil && ctx.Err() == nil {
		log.WithFields(log.Fields{"domain": config.Domain, "provider": config.Provider,
			"err": err}).Warn("DDNS sync failed; will retry at the next interval")
	}
}
