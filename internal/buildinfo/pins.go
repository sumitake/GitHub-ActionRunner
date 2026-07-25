package buildinfo

import (
	// Anchor imports. `go mod tidy` would prune requires that nothing in
	// the module imports yet; these dependencies are pinned now (see
	// Manifest below) but their real production use lands in later tasks.
	// Each blank import below is replaced by real usage in the task that
	// needs it -- do not remove until that task lands. The Linux-only
	// nftables anchor lives in pins_linux.go so this package still
	// compiles on non-Linux developer hosts (`go mod tidy` retains the
	// require because it walks build-tagged files for every GOOS).
	_ "github.com/actions/scaleset" // Task 2: scale-set session/listener client.
	_ "modernc.org/sqlite"          // Task 2: registers the database/sql driver for controller state.
)

// Manifest captures the exact pinned runtime dependency versions, upstream
// runner artifact, container base images, and egress feature-availability
// decisions for the controller runtime. Pins() returns this fixed value;
// later tasks read individual fields from it rather than re-deriving or
// re-stating these values.
type Manifest struct {
	// GoLanguageVersion and GoToolchain mirror the `go` and `toolchain`
	// directives in go.mod.
	GoLanguageVersion string
	GoToolchain       string

	Scaleset ModulePin
	SQLite   ModulePin
	NFTables ModulePin

	UpstreamRunner UpstreamRunnerPin

	// RunnerBaseImage is the base image for the upstream GitHub Actions
	// runner image layer. AdapterImage, BrokerImage, HelperImage, and
	// VerifierImage are the controller's own component images, all built
	// from scratch.
	RunnerBaseImage string
	AdapterImage    string
	BrokerImage     string
	HelperImage     string
	VerifierImage   string

	// EgressBackends lists every defined egress backend and whether it is
	// available for use today. A backend can be defined (so config schemas
	// and validation code can reference it by name) without being
	// available (so runtime config validation rejects selecting it).
	EgressBackends []EgressBackend

	// IPFamilies lists the supported public IP address families for
	// controller-managed egress.
	IPFamilies []IPFamily
}

// ModulePin pins a single Go module dependency. Commit, Sum, and License
// are populated only where the Global Constraints assert an exact value;
// an empty string means no such value is asserted for that module.
type ModulePin struct {
	Path    string
	Version string
	Commit  string
	Sum     string
	License string
}

// UpstreamRunnerPin pins the upstream (non-Go-module) GitHub Actions runner
// release the controller provisions into runner images.
type UpstreamRunnerPin struct {
	Version        string
	LinuxX64SHA256 string
}

// EgressBackend names one controller egress backend and whether it is
// currently available for selection in runtime configuration.
type EgressBackend struct {
	Name      string
	Available bool
}

// IPFamily names a supported public IP address family for
// controller-managed egress.
type IPFamily string

const (
	// EgressBackendRestrictedBrokerV1 is the QTS default egress backend:
	// available today.
	EgressBackendRestrictedBrokerV1 = "restricted-broker-v1"

	// EgressBackendNFTablesDirectV1 is defined but not yet available.
	// iptables-legacy remains a generated broker-helper protocol rather
	// than a host userspace dependency; nftables-direct-v1 itself is
	// unavailable until it has exact pre-conntrack qualification.
	EgressBackendNFTablesDirectV1 = "nftables-direct-v1"
)

const (
	// IPFamilyPublicIPv4Only restricts controller-managed egress to public
	// IPv4 addresses only.
	IPFamilyPublicIPv4Only IPFamily = "public_ipv4_only"

	// IPFamilyPublicDualStack allows controller-managed egress over both
	// public IPv4 and public IPv6 addresses.
	IPFamilyPublicDualStack IPFamily = "public_dual_stack"
)

// Pins returns the pinned dependency and artifact manifest for the
// controller runtime. The returned value is fixed; callers must not mutate
// its slice fields in place if they intend to call Pins again and compare.
func Pins() Manifest {
	return Manifest{
		GoLanguageVersion: "1.26.0",
		GoToolchain:       "go1.26.5",
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
			Version:        "v2.336.0",
			LinuxX64SHA256: "04cf0be1aff4c3ec3554466c39124ca250e3effd8873bb7e8d68535aa9505d5d",
		},
		RunnerBaseImage: "debian:bookworm-slim@sha256:1def178129dfb5f24db43afbf2fcac04530012e3264ba4ff81c71184e17a9ee4",
		AdapterImage:    "scratch",
		BrokerImage:     "scratch",
		HelperImage:     "scratch",
		VerifierImage:   "scratch",
		EgressBackends: []EgressBackend{
			{Name: EgressBackendRestrictedBrokerV1, Available: true},
			{Name: EgressBackendNFTablesDirectV1, Available: false},
		},
		IPFamilies: []IPFamily{IPFamilyPublicIPv4Only, IPFamilyPublicDualStack},
	}
}
