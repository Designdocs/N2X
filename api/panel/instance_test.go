package panel

import "testing"

func TestBackendInstanceIDIsStableAndSupportsExplicitIsolation(t *testing.T) {
	t.Setenv("N2X_INSTANCE_ID", "")
	a := backendInstanceID("https://panel.test", 7, "")
	if a != backendInstanceID("https://panel.test", 7, "") {
		t.Fatal("instance ID changes across construction")
	}
	if a == backendInstanceID("https://panel.test", 8, "") {
		t.Fatal("different runtime nodes share identity")
	}
	t.Setenv("N2X_INSTANCE_ID", "agent-a")
	if backendInstanceID("https://panel.test", 7, "") != "agent-a" {
		t.Fatal("explicit instance ID ignored")
	}
}
