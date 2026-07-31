//go:build darwin

package productionruntime

import (
	"bytes"
	"context"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"golang.org/x/sys/unix"
)

func observeStoragePath(
	ctx context.Context,
	path string,
	role string,
) (StorageAvailability, error) {
	if ctx == nil || ctx.Err() != nil {
		return StorageAvailability{}, ErrStorageEnvelope
	}
	fd, err := unix.Open(
		path,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return StorageAvailability{}, ErrStorageEnvelope
	}
	defer unix.Close(fd)

	var identity unix.Stat_t
	var capacity unix.Statfs_t
	if unix.Fstat(fd, &identity) != nil ||
		unix.Fstatfs(fd, &capacity) != nil ||
		identity.Ino == 0 ||
		identity.Dev <= 0 ||
		capacity.Bsize == 0 ||
		capacity.Bavail == 0 ||
		capacity.Ffree == 0 {
		return StorageAvailability{}, ErrStorageEnvelope
	}
	freeBytes, ok := multiplyStorageAmount(
		capacity.Bavail,
		uint64(capacity.Bsize),
	)
	if !ok || freeBytes == 0 {
		return StorageAvailability{}, ErrStorageEnvelope
	}
	device := uint64(uint32(identity.Dev))
	deviceMajor := uint32(device >> 24)
	deviceMinor := uint32(device & 0x00ffffff)
	fsTypeBytes := capacity.Fstypename[:]
	if index := bytes.IndexByte(fsTypeBytes, 0); index >= 0 {
		fsTypeBytes = fsTypeBytes[:index]
	}
	if deviceMajor == 0 || len(fsTypeBytes) == 0 {
		return StorageAvailability{}, ErrStorageEnvelope
	}
	return StorageAvailability{
		Filesystem: hostruntime.LifecycleFilesystemIdentity{
			Role:        role,
			MountID:     device,
			DeviceMajor: deviceMajor,
			DeviceMinor: deviceMinor,
			RootInode:   identity.Ino,
			FSType:      string(fsTypeBytes),
		},
		Device:     device,
		FreeBytes:  freeBytes,
		FreeInodes: capacity.Ffree,
	}, nil
}
