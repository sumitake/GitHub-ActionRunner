package testenv

import (
	"os"
	"strings"
	"testing"
)

func TestLinuxStaticPreflightUsesExplicitCommandRunnerBounds(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("static_preflight_linux.go")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	text := string(source)
	if got := strings.Count(
		text,
		"commandRunnerFromConformanceLimits(",
	); got != 1 {
		t.Fatalf("explicit command runner calls = %d, want 1", got)
	}
	if strings.Contains(text, "hostruntime.NewExecCommandRunner(") {
		t.Fatal("Linux static preflight retains implicit command bounds")
	}
}
