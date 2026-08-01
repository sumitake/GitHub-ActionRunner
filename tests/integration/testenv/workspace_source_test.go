package testenv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinuxFixtureWorkspaceUsesExactNonrecursiveAuthority(t *testing.T) {
	t.Parallel()

	document, err := os.ReadFile(filepath.Join(
		"workspace_linux.go",
	))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	source := string(document)
	for _, required := range []string{
		"unix.Openat2",
		"unix.Mkdirat",
		"unix.Unlinkat",
		`"state"`,
		`"relay"`,
		`"authority"`,
		`"controller.db"`,
		`"controller.db-wal"`,
		`"controller.db-shm"`,
		"ErrFixtureUnexpectedObject",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("workspace source missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"os.RemoveAll",
		"filepath.Walk",
		"filepath.Glob",
	} {
		if strings.Contains(source, forbidden) {
			t.Errorf("workspace source contains %q", forbidden)
		}
	}
}
