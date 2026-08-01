package decoy

import "testing"

func TestResolveListenAddress(t *testing.T) {
	tests := []struct {
		name      string
		env       string
		want      string
		wantError bool
	}{
		{name: "unset falls back to default", want: DefaultListenAddress},
		{name: "blank falls back to default", env: "   ", want: DefaultListenAddress},
		{name: "custom IPv4 loopback", env: "127.0.0.1:61443", want: "127.0.0.1:61443"},
		{name: "custom IPv6 loopback", env: "[::1]:61443", want: "[::1]:61443"},
		{name: "surrounding whitespace trimmed", env: " 127.0.0.1:61443 ", want: "127.0.0.1:61443"},
		{name: "wildcard rejected", env: "0.0.0.0:60443", wantError: true},
		{name: "public address rejected", env: "192.0.2.1:60443", wantError: true},
		{name: "hostname rejected", env: "localhost:60443", wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(ListenAddressEnvironment, test.env)

			got, err := ResolveListenAddress()
			if (err != nil) != test.wantError {
				t.Fatalf("ResolveListenAddress() error = %v, wantError %v", err, test.wantError)
			}
			if test.wantError {
				return
			}
			if got != test.want {
				t.Fatalf("ResolveListenAddress() = %q, want %q", got, test.want)
			}
		})
	}
}
