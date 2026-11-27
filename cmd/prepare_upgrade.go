package cmd

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/Designdocs/N2X/api/panel"
	"github.com/Designdocs/N2X/conf"
	"github.com/spf13/cobra"
)

const upgradeDataLifetime = 5 * time.Minute

type upgradeData struct {
	Version   string
	Created   time.Time
	ConfigKey string
	Nodes     []panel.PreparedNode
}

func nodeConfigKey(nodes []conf.NodeConfig) (string, error) {
	// NodeConfig's JSON representation intentionally omits these two fields.
	h := sha256.New()
	for _, n := range nodes {
		if err := json.NewEncoder(h).Encode([]any{n.ApiConfig, n.Options}); err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func init() {
	var path, env, output, check string
	prep := &cobra.Command{
		Use:           "prepare-upgrade",
		Short:         "Prepare one-use panel data for a service upgrade",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			loadEnvFile(path, env, false)
			c, err := loadConfig(path)
			if err != nil {
				return err
			}
			if check != "" {
				_, err := readUpgradeData(c, check, false)
				return err
			}
			return prepareUpgrade(c, output)
		},
	}
	prep.Flags().StringVarP(&path, "config", "c", "/etc/N2X/config.json", "config file path")
	prep.Flags().StringVarP(&env, "env-file", "e", "", "env file path")
	prep.Flags().StringVar(&output, "output", "", "new private file for the next startup")
	prep.Flags().StringVar(&check, "verify", "", "verify a staged handoff against the current configuration")
	prep.MarkFlagsOneRequired("output", "verify")
	prep.MarkFlagsMutuallyExclusive("output", "verify")
	command.AddCommand(prep)
}

func prepareUpgrade(c *conf.Conf, path string) error {
	key, err := nodeConfigKey(c.NodeConfig)
	if err != nil {
		return err
	}
	b := upgradeData{Version: version, Created: time.Now(), ConfigKey: key}
	for i, n := range c.NodeConfig {
		client, err := panel.New(&n.ApiConfig)
		if err != nil {
			return fmt.Errorf("Nodes[%d]: %w", i, err)
		}
		data, err := client.PrepareNode(&n.Options)
		if err != nil {
			return fmt.Errorf("Nodes[%d] %s #%d: %w", i, n.ApiConfig.NodeType, n.ApiConfig.NodeID, err)
		}
		b.Nodes = append(b.Nodes, *data)
	}
	if time.Since(b.Created) >= upgradeDataLifetime {
		return errors.New("prepared node data expired before cutover")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	err = json.NewEncoder(f).Encode(b)
	if err = errors.Join(err, f.Close()); err != nil {
		os.Remove(path)
	}
	return err
}

func readUpgradeData(c *conf.Conf, path string, consume bool) ([]panel.PreparedNode, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// An interrupted installer may leave a stale handoff under /run. Claim
	// that dedicated slot once, even if validation rejects it: a later normal
	// service restart must be able to do an ordinary HTTP bootstrap.
	const serviceSlot = "/run/n2x-upgrade/ready"
	if consume && path == serviceSlot {
		if err = os.Remove(path); err != nil {
			return nil, err
		}
	}
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("prepared node data must be a private regular file")
	}
	var b upgradeData
	if err = json.NewDecoder(f).Decode(&b); err != nil {
		return nil, err
	}
	key, err := nodeConfigKey(c.NodeConfig)
	if err != nil {
		return nil, err
	}
	age := time.Since(b.Created)
	if age < 0 || age >= upgradeDataLifetime || b.Version != version || b.ConfigKey != key || len(b.Nodes) != len(c.NodeConfig) {
		return nil, errors.New("prepared node data expired or does not match this version and node configuration")
	}
	for i, n := range b.Nodes {
		if len(n.Config) == 0 || n.Users == nil || n.Devices == nil || n.Devices.Alive == nil {
			return nil, fmt.Errorf("incomplete prepared data for Nodes[%d]", i)
		}
	}
	if consume && path != serviceSlot {
		if err = os.Remove(path); err != nil {
			return nil, err
		}
	}
	return b.Nodes, nil
}
