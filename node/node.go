package node

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	vCore "github.com/Designdocs/N2X/core"
	log "github.com/sirupsen/logrus"
)

const (
	nodeStartRetryBase = 30 * time.Second
	nodeStartRetryMax  = 5 * time.Minute
)

type Node struct {
	mu                   sync.Mutex
	controllers          []*Controller
	httpsRedirectManager *httpsRedirectManager
	retryCancel          context.CancelFunc
	retryWG              sync.WaitGroup
}

func New() *Node {
	return &Node{
		httpsRedirectManager: newHTTPSRedirectManager(defaultHTTPSRedirectListenAddress),
	}
}

// Start brings up every configured node. A node that fails to start (for
// example because its certificate cannot be issued) is retried in the
// background instead of failing the whole process: exiting made systemd
// restart N2X in a tight loop, which took the healthy nodes down with it and
// burned the ACME rate limit on every restart.
//
// Start returns the nodes whose first attempt failed, in config order. The
// error is reserved for a node config no panel client can be built from, in
// which case nothing was started.
func (n *Node) Start(nodes []conf.NodeConfig, core vCore.Core) ([]StartFailure, error) {
	clients := make([]*panel.Client, len(nodes))
	for i := range nodes {
		p, err := panel.New(&nodes[i].ApiConfig)
		if err != nil {
			return nil, fmt.Errorf("Nodes[%d]: create panel client: %w", i, err)
		}
		clients[i] = p
	}

	ctx, cancel := context.WithCancel(context.Background())
	n.mu.Lock()
	n.retryCancel = cancel
	n.mu.Unlock()

	var failures []StartFailure
	for i := range nodes {
		label := fmt.Sprintf("%s-%s-%d",
			nodes[i].ApiConfig.APIHost,
			nodes[i].ApiConfig.NodeType,
			nodes[i].ApiConfig.NodeID)
		client, options := clients[i], &nodes[i].Options
		start := func() error {
			return n.startController(ctx, core, client, options)
		}
		if err := start(); err != nil {
			failures = append(failures, StartFailure{Index: i, Stage: startStageOf(err), Err: err})
			log.WithFields(log.Fields{
				"node": label,
				"err":  err,
			}).Error("Start node controller failed; other nodes keep running and this one retries in the background")
			n.retryWG.Add(1)
			go func() {
				defer n.retryWG.Done()
				retryUntilStarted(ctx, label, start, nodeStartRetryDelay)
			}()
		}
	}
	return failures, nil
}

func (n *Node) startController(
	ctx context.Context,
	core vCore.Core,
	client *panel.Client,
	options *conf.Options,
) error {
	controller := NewController(core, client, options, n.httpsRedirectManager)
	if err := controller.Start(); err != nil {
		// Start can fail after registering the limiter, hooks or the core
		// node; roll those back so the next attempt starts clean.
		if closeErr := controller.Close(); closeErr != nil {
			log.WithField("err", closeErr).Debug("Rollback of failed node controller reported an error")
		}
		return err
	}

	n.mu.Lock()
	if ctx.Err() != nil {
		n.mu.Unlock()
		if err := controller.Close(); err != nil {
			log.WithField("err", err).Error("Close node controller started during shutdown failed")
		}
		return nil
	}
	n.controllers = append(n.controllers, controller)
	n.mu.Unlock()

	// Only start the optional WebSocket driver once the HTTP bootstrap
	// has succeeded, so a misconfigured WS endpoint can never block
	// the node from coming up.
	client.StartWebSocket()
	return nil
}

func (n *Node) Close() {
	n.mu.Lock()
	cancel := n.retryCancel
	n.retryCancel = nil
	n.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	// A retry may be inside controller.Start; wait for it so it cannot add a
	// node to the core that is about to be closed.
	n.retryWG.Wait()

	if n.httpsRedirectManager != nil {
		_ = n.httpsRedirectManager.Close()
	}

	n.mu.Lock()
	controllers := n.controllers
	n.controllers = nil
	n.mu.Unlock()
	for _, c := range controllers {
		c.apiClient.StopWebSocket()
		err := c.Close()
		if err != nil {
			panic(err)
		}
	}
}

// retryUntilStarted calls start after each delay until it succeeds or ctx is
// canceled.
func retryUntilStarted(
	ctx context.Context,
	label string,
	start func() error,
	delay func(attempt int) time.Duration,
) {
	for attempt := 1; ; attempt++ {
		timer := time.NewTimer(delay(attempt))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if ctx.Err() != nil {
			return
		}

		err := start()
		if err == nil {
			log.WithField("node", label).Infof("Node controller started after %d retries", attempt)
			return
		}
		log.WithFields(log.Fields{
			"node":  label,
			"err":   err,
			"retry": delay(attempt + 1).String(),
		}).Error("Retry start node controller failed")
	}
}

func nodeStartRetryDelay(attempt int) time.Duration {
	delay := nodeStartRetryBase
	for i := 1; i < attempt && delay < nodeStartRetryMax; i++ {
		delay *= 2
	}
	return min(delay, nodeStartRetryMax)
}
