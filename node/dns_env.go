package node

import (
	"fmt"
	"os"
	"sync"

	"github.com/go-acme/lego/v4/challenge"
)

// lego DNS providers read their credentials from the process environment
// while they are constructed. Each node carries its own DNSEnv, so writing
// it with a bare os.Setenv lets one node's credentials leak into the next
// provider: Cloudflare, for one, prefers CLOUDFLARE_EMAIL/API_KEY over a
// token and CLOUDFLARE_* names over CF_* names, so a leftover key silently
// wins over the token the second node configured. The variables are
// therefore applied only for the duration of the construction, under a lock
// shared by every node, and restored afterwards.
var dnsEnvMu sync.Mutex

type dnsProviderFactory func(name string) (challenge.Provider, error)

func newScopedDNSProvider(
	name string,
	envs map[string]string,
	factory dnsProviderFactory,
) (challenge.Provider, error) {
	dnsEnvMu.Lock()
	defer dnsEnvMu.Unlock()

	restore, err := applyScopedEnv(envs)
	defer restore()
	if err != nil {
		return nil, err
	}
	return factory(name)
}

type savedEnv struct {
	value   string
	existed bool
}

// applyScopedEnv sets envs and returns a func that puts every touched key
// back to its previous state. The restore func is valid even on error, so a
// half-applied set is still rolled back.
func applyScopedEnv(envs map[string]string) (func(), error) {
	previous := make(map[string]savedEnv, len(envs))
	restore := func() {
		for key, saved := range previous {
			if saved.existed {
				_ = os.Setenv(key, saved.value)
			} else {
				_ = os.Unsetenv(key)
			}
		}
	}
	for key, value := range envs {
		old, existed := os.LookupEnv(key)
		previous[key] = savedEnv{value: old, existed: existed}
		if err := os.Setenv(key, value); err != nil {
			return restore, fmt.Errorf("set dns env %q: %w", key, err)
		}
	}
	return restore, nil
}
