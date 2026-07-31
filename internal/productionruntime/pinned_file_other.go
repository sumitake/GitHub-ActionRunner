//go:build !darwin && !linux

package productionruntime

func readPinnedAbsoluteFile(string, uint32, int) ([]byte, error) {
	return nil, ErrProtocol
}
