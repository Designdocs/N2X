package conf

import "testing"

func TestWSScanGuardConfig(t *testing.T) {
	for _, tc := range []struct {
		raw     string
		enabled bool
		size    int
	}{
		{`{"Cores":[{"Type":"xray"}]}`, false, 10},
		{`{"WSScanGuard":{"Enabled":true,"LogMaxMB":2},"Cores":[{"Type":"xray"}]}`, true, 2},
	} {
		c := New()
		if err := c.decode([]byte(tc.raw)); err != nil {
			t.Fatal(err)
		}
		actual := c.CoresConfig[0].XrayConfig.WSScanGuard
		if actual.Enabled != tc.enabled || actual.LogMaxMB != tc.size {
			t.Fatal(actual)
		}
	}
}
