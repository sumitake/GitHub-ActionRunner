//go:build !darwin && !linux

package cli

func readPrivateOverlayDocument(string, int) ([]byte, error) {
	return nil, ErrHostCommandFailed
}
