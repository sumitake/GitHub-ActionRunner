package buildinfo

import "testing"

func TestInfoDefaults(t *testing.T) {
	if got := Info(); got.Version != "dev" || got.Commit != "unknown" {
		t.Fatalf("unexpected build info: %#v", got)
	}
}
