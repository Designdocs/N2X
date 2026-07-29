package node

import (
	"fmt"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	vCore "github.com/Designdocs/N2X/core"
)

type Node struct {
	controllers          []*Controller
	httpsRedirectManager *httpsRedirectManager
}

func New() *Node {
	return &Node{
		httpsRedirectManager: newHTTPSRedirectManager(defaultHTTPSRedirectListenAddress),
	}
}

func (n *Node) Start(nodes []conf.NodeConfig, core vCore.Core) error {
	n.controllers = make([]*Controller, len(nodes))
	for i := range nodes {
		p, err := panel.New(&nodes[i].ApiConfig)
		if err != nil {
			return err
		}
		// Register controller service
		n.controllers[i] = NewController(
			core,
			p,
			&nodes[i].Options,
			n.httpsRedirectManager,
		)
		err = n.controllers[i].Start()
		if err != nil {
			return fmt.Errorf("start node controller [%s-%s-%d] error: %s",
				nodes[i].ApiConfig.APIHost,
				nodes[i].ApiConfig.NodeType,
				nodes[i].ApiConfig.NodeID,
				err)
		}
		// Only start the optional WebSocket driver once the HTTP bootstrap
		// has succeeded, so a misconfigured WS endpoint can never block
		// the node from coming up.
		p.StartWebSocket()
	}
	return nil
}

func (n *Node) Close() {
	if n.httpsRedirectManager != nil {
		_ = n.httpsRedirectManager.Close()
	}
	for _, c := range n.controllers {
		c.apiClient.StopWebSocket()
		err := c.Close()
		if err != nil {
			panic(err)
		}
	}
	n.controllers = nil
}
