package buildinfo

import (
	"reflect"
	"testing"
)

// TestPinsExactValues asserts that Pins() equals the pinned dependency and
// artifact manifest verbatim. Every field is load-bearing: later tasks read
// these values directly rather than re-deriving them, so an accidental
// change here must fail loudly.
func TestPinsExactValues(t *testing.T) {
	want := Manifest{
		GoLanguageVersion: "1.26.0",
		GoToolchain:       "go1.26.9",
		Scaleset: ModulePin{
			Path:    "github.com/actions/scaleset",
			Version: "v0.4.0",
			Commit:  "6ce025902cd964747a078c2aabe7340ebc667eca",
			Sum:     "h1:691GC2AkHb3ZGjfNvatboYoRS7CLr3+4VcZk/6w9IbM=",
			License: "MIT",
		},
		SQLite: ModulePin{
			Path:    "modernc.org/sqlite",
			Version: "v1.53.0",
		},
		NFTables: ModulePin{
			Path:    "github.com/google/nftables",
			Version: "v0.3.0",
		},
		UpstreamRunner: UpstreamRunnerPin{
			Version:               "v2.337.0",
			LinuxX64SHA256:        "70920811a4f8ad4328818682bca5c6469c1c942fab52448868071d0063816613",
			SourceCommit:          "397b032cbf865e9c3ddfab89d533ec19325e1273",
			CommandSettingsSHA256: "937f6552579f7d1eeb0a6d0201586781eb3e2e5ea2ab3878429076560e0cab08",
		},
		RunnerBaseImage: "debian:bookworm-slim@sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867",
		AdapterImage:    "scratch",
		BrokerImage:     "scratch",
		HelperImage:     "scratch",
		VerifierImage:   "scratch",
		EgressBackends: []EgressBackend{
			{Name: "restricted-broker-v1", Available: true},
			{Name: "nftables-direct-v1", Available: false},
		},
		IPFamilies: []IPFamily{"public_ipv4_only", "public_dual_stack"},
	}

	got := Pins()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Pins() mismatch:\n got:  %#v\n want: %#v", got, want)
	}
}

// TestPinsFieldTable is a table test over the individual scalar pins named
// explicitly in the Global Constraints, independent of the full-manifest
// comparison above.
func TestPinsFieldTable(t *testing.T) {
	p := Pins()

	tests := []struct {
		name string
		got  string
		want string
	}{
		{"go language version", p.GoLanguageVersion, "1.26.0"},
		{"go toolchain", p.GoToolchain, "go1.26.9"},
		{"scaleset module path", p.Scaleset.Path, "github.com/actions/scaleset"},
		{"scaleset version", p.Scaleset.Version, "v0.4.0"},
		{"scaleset commit", p.Scaleset.Commit, "6ce025902cd964747a078c2aabe7340ebc667eca"},
		{"scaleset sum", p.Scaleset.Sum, "h1:691GC2AkHb3ZGjfNvatboYoRS7CLr3+4VcZk/6w9IbM="},
		{"scaleset license", p.Scaleset.License, "MIT"},
		{"sqlite module path", p.SQLite.Path, "modernc.org/sqlite"},
		{"sqlite version", p.SQLite.Version, "v1.53.0"},
		{"nftables module path", p.NFTables.Path, "github.com/google/nftables"},
		{"nftables version", p.NFTables.Version, "v0.3.0"},
		{"upstream runner version", p.UpstreamRunner.Version, "v2.337.0"},
		{"upstream runner sha256", p.UpstreamRunner.LinuxX64SHA256, "70920811a4f8ad4328818682bca5c6469c1c942fab52448868071d0063816613"},
		{"upstream runner source commit", p.UpstreamRunner.SourceCommit, "397b032cbf865e9c3ddfab89d533ec19325e1273"},
		{"upstream command settings sha256", p.UpstreamRunner.CommandSettingsSHA256, "937f6552579f7d1eeb0a6d0201586781eb3e2e5ea2ab3878429076560e0cab08"},
		{"runner base image", p.RunnerBaseImage, "debian:bookworm-slim@sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867"},
		{"adapter image", p.AdapterImage, "scratch"},
		{"broker image", p.BrokerImage, "scratch"},
		{"helper image", p.HelperImage, "scratch"},
		{"verifier image", p.VerifierImage, "scratch"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %q, want %q", tt.got, tt.want)
			}
		})
	}
}

// TestPinsEgressBackendAvailability locks in which egress backends are
// available today: restricted-broker-v1 (the QTS default) is available;
// nftables-direct-v1 is defined but not yet available pending exact
// pre-conntrack qualification.
func TestPinsEgressBackendAvailability(t *testing.T) {
	p := Pins()

	availability := make(map[string]bool, len(p.EgressBackends))
	for _, b := range p.EgressBackends {
		availability[b.Name] = b.Available
	}

	tests := []struct {
		name string
		want bool
	}{
		{"restricted-broker-v1", true},
		{"nftables-direct-v1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := availability[tt.name]
			if !ok {
				t.Fatalf("egress backend %q not present in Pins()", tt.name)
			}
			if got != tt.want {
				t.Errorf("Available = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestPinsIPFamilies locks in the two supported public IP families.
func TestPinsIPFamilies(t *testing.T) {
	p := Pins()
	want := []IPFamily{"public_ipv4_only", "public_dual_stack"}
	if !reflect.DeepEqual(p.IPFamilies, want) {
		t.Fatalf("IPFamilies = %#v, want %#v", p.IPFamilies, want)
	}
}
