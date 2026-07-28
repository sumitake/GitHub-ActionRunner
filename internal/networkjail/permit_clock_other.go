//go:build !linux

package networkjail

type SystemMonotonicClock struct{}

func NewSystemMonotonicClock() (*SystemMonotonicClock, error) {
	return nil, ErrPermitAuthorityUnavailable
}
