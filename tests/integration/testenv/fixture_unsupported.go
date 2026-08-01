//go:build integration && !linux

package testenv

import "testing"

// StartDockerFixture is explicit on unsupported hosts. A skip is never target
// evidence and cannot produce a conformance Report.
func StartDockerFixture(t *testing.T) *Fixture {
	t.Helper()
	t.Skip(unsupportedHostSkip)
	return nil
}
