//go:build !darwin && !linux

package productionruntime

import "os"

func releaseIdentityFields(
	os.FileInfo,
) (releaseFileIdentity, bool) {
	return releaseFileIdentity{}, false
}

func releaseDeviceNumbers(uint64) (uint32, uint32, bool) {
	return 0, 0, false
}
