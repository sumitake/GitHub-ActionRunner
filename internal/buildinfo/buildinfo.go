// Package buildinfo exposes immutable build metadata stamped at link time.
package buildinfo

import "strings"

const identityPrefix = "portable-ghar-build-identity-v1|"

// BuildInfo carries the version and commit of a build.
type BuildInfo struct {
	Version string
	Commit  string
}

// Default values are used until a release build overrides them with
// -ldflags "-X ...version -X ...commit -X ...stamp".
var (
	version = "dev"
	commit  = "unknown"
	stamp   string
)

func init() {
	// Read all three linker variables from an observable initializer so partial
	// or cross-paired -X assignments fail before a command can run.
	if stamp == "" && version == "dev" && commit == "unknown" {
		stamp = identityPrefix + version + "|" + commit
	}
	expected, ok := IdentityStamp(version, commit)
	if !ok || stamp != expected {
		panic("buildinfo: invalid build identity")
	}
}

// IdentityStamp validates and frames one coherent developer or release
// identity. It is the sole authority for the linker stamp's byte format.
func IdentityStamp(buildVersion, sourceCommit string) (string, bool) {
	if buildVersion == "dev" || sourceCommit == "unknown" {
		if buildVersion != "dev" || sourceCommit != "unknown" {
			return "", false
		}
		return identityPrefix + buildVersion + "|" + sourceCommit, true
	}
	if !validVersion(buildVersion) || !validCommit(sourceCommit) {
		return "", false
	}
	return identityPrefix + buildVersion + "|" + sourceCommit, true
}

func validVersion(value string) bool {
	if value == "" || len(value) > 128 || !asciiAlphaNumeric(value[0]) {
		return false
	}
	if strings.Contains(value, "..") {
		return false
	}
	for index := 1; index < len(value); index++ {
		switch value[index] {
		case '.', '_', '+', '-':
		default:
			if !asciiAlphaNumeric(value[index]) {
				return false
			}
		}
	}
	return true
}

func asciiAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' ||
		value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9'
}

func validCommit(value string) bool {
	if len(value) != 40 {
		return false
	}
	for index := range value {
		if !((value[index] >= '0' && value[index] <= '9') ||
			(value[index] >= 'a' && value[index] <= 'f')) {
			return false
		}
	}
	return true
}

// Info returns the immutable build metadata for this binary.
func Info() BuildInfo {
	return BuildInfo{Version: version, Commit: commit}
}
