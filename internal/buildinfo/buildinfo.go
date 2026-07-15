// Package buildinfo exposes immutable build metadata stamped at link time.
package buildinfo

// BuildInfo carries the version and commit of a build.
type BuildInfo struct {
	Version string
	Commit  string
}

// Default values are used until a release build overrides them with
// -ldflags "-X ...version -X ...commit".
var (
	version = "dev"
	commit  = "unknown"
)

// Info returns the immutable build metadata for this binary.
func Info() BuildInfo {
	return BuildInfo{Version: version, Commit: commit}
}
