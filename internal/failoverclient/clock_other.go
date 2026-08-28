//go:build !linux

package failoverclient

func NewProductionAuthorityClock() (AuthorityClock, error) {
	return NewUnsupportedAuthorityClock(), nil
}
