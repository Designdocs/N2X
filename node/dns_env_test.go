package node

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"
)

type stubDNSProvider struct{}

func (stubDNSProvider) Present(string, string, string) error { return nil }
func (stubDNSProvider) CleanUp(string, string, string) error { return nil }

func TestNewScopedDNSProviderDoesNotLeakEnvBetweenNodes(t *testing.T) {
	unsetForTest(t, "CLOUDFLARE_EMAIL", "CLOUDFLARE_API_KEY", "CF_DNS_API_TOKEN")

	_, err := newScopedDNSProvider("cloudflare", map[string]string{
		"CLOUDFLARE_EMAIL":   "first@example.com",
		"CLOUDFLARE_API_KEY": "first-key",
	}, func(string) (challenge.Provider, error) {
		if got := os.Getenv("CLOUDFLARE_API_KEY"); got != "first-key" {
			t.Fatalf("expected first node key during construction, got %q", got)
		}
		return stubDNSProvider{}, nil
	})
	if err != nil {
		t.Fatalf("first provider: %v", err)
	}

	_, err = newScopedDNSProvider("cloudflare", map[string]string{
		"CF_DNS_API_TOKEN": "second-token",
	}, func(string) (challenge.Provider, error) {
		if _, leaked := os.LookupEnv("CLOUDFLARE_EMAIL"); leaked {
			t.Fatal("first node CLOUDFLARE_EMAIL leaked into second node provider")
		}
		if _, leaked := os.LookupEnv("CLOUDFLARE_API_KEY"); leaked {
			t.Fatal("first node CLOUDFLARE_API_KEY leaked into second node provider")
		}
		if got := os.Getenv("CF_DNS_API_TOKEN"); got != "second-token" {
			t.Fatalf("expected second node token, got %q", got)
		}
		return stubDNSProvider{}, nil
	})
	if err != nil {
		t.Fatalf("second provider: %v", err)
	}

	for _, key := range []string{"CLOUDFLARE_EMAIL", "CLOUDFLARE_API_KEY", "CF_DNS_API_TOKEN"} {
		if _, exists := os.LookupEnv(key); exists {
			t.Fatalf("expected %s to be removed after provider construction", key)
		}
	}
}

func TestNewScopedDNSProviderRestoresProcessEnv(t *testing.T) {
	t.Setenv("CF_DNS_API_TOKEN", "process-token")

	_, err := newScopedDNSProvider("cloudflare", map[string]string{
		"CF_DNS_API_TOKEN": "node-token",
	}, func(string) (challenge.Provider, error) {
		if got := os.Getenv("CF_DNS_API_TOKEN"); got != "node-token" {
			t.Fatalf("expected node token to override process env, got %q", got)
		}
		return stubDNSProvider{}, nil
	})
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	if got := os.Getenv("CF_DNS_API_TOKEN"); got != "process-token" {
		t.Fatalf("expected process token to be restored, got %q", got)
	}
}

func TestNewScopedDNSProviderRestoresEnvOnFactoryError(t *testing.T) {
	unsetForTest(t, "CF_DNS_API_TOKEN")

	_, err := newScopedDNSProvider("cloudflare", map[string]string{
		"CF_DNS_API_TOKEN": "node-token",
	}, func(string) (challenge.Provider, error) {
		return nil, fmt.Errorf("boom")
	})
	if err == nil {
		t.Fatal("expected factory error to be returned")
	}
	if _, exists := os.LookupEnv("CF_DNS_API_TOKEN"); exists {
		t.Fatal("expected node token to be removed after factory error")
	}
}

func TestNewScopedDNSProviderSerializesConcurrentNodes(t *testing.T) {
	unsetForTest(t, "CF_DNS_API_TOKEN")

	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		token := fmt.Sprintf("token-%d", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := newScopedDNSProvider("cloudflare", map[string]string{
				"CF_DNS_API_TOKEN": token,
			}, func(string) (challenge.Provider, error) {
				time.Sleep(time.Millisecond)
				if got := os.Getenv("CF_DNS_API_TOKEN"); got != token {
					return nil, fmt.Errorf("expected %q, got %q", token, got)
				}
				return stubDNSProvider{}, nil
			})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

// unsetForTest clears keys for the test and puts back whatever the process
// had afterwards, so a developer's own CLOUDFLARE_* shell variables survive.
func unsetForTest(t *testing.T, keys ...string) {
	t.Helper()
	for _, key := range keys {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("unset %s: %v", key, err)
		}
	}
}
