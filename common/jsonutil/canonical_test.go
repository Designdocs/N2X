package jsonutil

import (
	"bytes"
	"testing"
)

func TestCanonicalIgnoresObjectFormattingAndPreservesValues(t *testing.T) {
	a, err := Canonical([]byte(`{"window":18446744073709551615,"nested":{"b":2,"a":1},"ports":[1,2]}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Canonical([]byte("{\n\"ports\": [1, 2], \"nested\": {\"a\":1,\"b\":2}, \"window\":18446744073709551615}"))
	if err != nil || !bytes.Equal(a, b) {
		t.Fatalf("same JSON differs: %s vs %s (%v)", a, b, err)
	}
	for _, raw := range []string{
		`{"window":18446744073709551614,"nested":{"b":2,"a":1},"ports":[1,2]}`,
		`{"window":18446744073709551615,"nested":{"b":2,"a":1},"ports":[2,1]}`,
	} {
		changed, err := Canonical([]byte(raw))
		if err != nil || bytes.Equal(a, changed) {
			t.Fatalf("a real value/order change was lost: %s (%v)", changed, err)
		}
	}
}

func TestCanonicalRejectsIncompleteOrTrailingJSON(t *testing.T) {
	for _, raw := range []string{`{"x":`, `{} {}`, `{} garbage`, ``} {
		if _, err := Canonical([]byte(raw)); err == nil {
			t.Fatalf("accepted invalid JSON %q", raw)
		}
	}
}
