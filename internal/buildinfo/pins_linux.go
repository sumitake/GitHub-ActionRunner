//go:build linux

package buildinfo

// Linux-only dependency anchor. github.com/google/nftables (via its xt
// subpackage) references netfilter constants that exist only on Linux, so
// its blank import is constrained here to keep internal/buildinfo -- and
// therefore `go build ./...` -- compiling on non-Linux developer hosts.
// `go mod tidy` still retains the require because it walks build-tagged
// files for every GOOS. Task 6 replaces this anchor with real usage in the
// nftables-direct-v1 egress backend.
import _ "github.com/google/nftables"
