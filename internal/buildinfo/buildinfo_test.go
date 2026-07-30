package buildinfo

import (
	"os"
	"strings"
	"testing"
)

func TestInfoDefaults(t *testing.T) {
	if got := Info(); got.Version != "dev" || got.Commit != "unknown" {
		t.Fatalf("unexpected build info: %#v", got)
	}
	if stamp != "portable-ghar-build-identity-v1|dev|unknown" {
		t.Fatalf("unexpected default stamp: %q", stamp)
	}
}

func TestIdentityStampUsesOneClosedFrame(t *testing.T) {
	commit := strings.Repeat("a", 40)
	tests := []struct {
		name    string
		version string
		commit  string
		want    string
		ok      bool
	}{
		{
			name:    "developer default",
			version: "dev",
			commit:  "unknown",
			want:    "portable-ghar-build-identity-v1|dev|unknown",
			ok:      true,
		},
		{
			name:    "release",
			version: "1.2.3-rc.1+build_7",
			commit:  commit,
			want: "portable-ghar-build-identity-v1|1.2.3-rc.1+build_7|" +
				commit,
			ok: true,
		},
		{name: "empty version", commit: commit},
		{name: "empty commit", version: "1.2.3"},
		{name: "partial default", version: "dev", commit: commit},
		{name: "other partial default", version: "1.2.3", commit: "unknown"},
		{name: "leading punctuation", version: "-1.2.3", commit: commit},
		{name: "double dot", version: "1..2", commit: commit},
		{name: "delimiter injection", version: "1.2.3|other", commit: commit},
		{
			name:    "oversized version",
			version: strings.Repeat("a", 129),
			commit:  commit,
		},
		{
			name:    "uppercase commit",
			version: "1.2.3",
			commit:  strings.Repeat("A", 40),
		},
		{
			name:    "short commit",
			version: "1.2.3",
			commit:  strings.Repeat("a", 39),
		},
		{
			name:    "long commit",
			version: "1.2.3",
			commit:  strings.Repeat("a", 41),
		},
		{
			name:    "nonhex commit",
			version: "1.2.3",
			commit:  strings.Repeat("g", 40),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := IdentityStamp(test.version, test.commit)
			if ok != test.ok || got != test.want {
				t.Fatalf(
					"IdentityStamp(%q, %q) = (%q, %t), want (%q, %t)",
					test.version,
					test.commit,
					got,
					ok,
					test.want,
					test.ok,
				)
			}
		})
	}
}

func TestLinkedIdentity(t *testing.T) {
	expectedVersion := os.Getenv("PGHAR_EXPECTED_BUILD_VERSION")
	expectedCommit := os.Getenv("PGHAR_EXPECTED_BUILD_COMMIT")
	if expectedVersion == "" && expectedCommit == "" {
		return
	}
	if expectedVersion == "" || expectedCommit == "" {
		t.Fatal("partial expected linked identity")
	}
	expectedStamp, ok := IdentityStamp(expectedVersion, expectedCommit)
	if !ok {
		t.Fatal("invalid expected linked identity")
	}
	if got := Info(); got.Version != expectedVersion || got.Commit != expectedCommit {
		t.Fatalf("linked identity = %#v", got)
	}
	if stamp != expectedStamp {
		t.Fatalf("linked stamp = %q, want %q", stamp, expectedStamp)
	}
}
