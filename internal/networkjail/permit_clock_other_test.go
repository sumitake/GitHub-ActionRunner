//go:build !linux

package networkjail

import (
	"errors"
	"testing"
)

func TestSystemMonotonicClockUnavailableOffLinux(t *testing.T) {
	if _, err := NewSystemMonotonicClock(); !errors.Is(err, ErrPermitAuthorityUnavailable) {
		t.Fatalf("NewSystemMonotonicClock = %v, want ErrPermitAuthorityUnavailable", err)
	}
}
