//go:build linux

package productionruntime

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"golang.org/x/sys/unix"
)

const maximumFDInfoBytes = 4096

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
		identity.Dev == 0 ||
		capacity.Bsize <= 0 ||
		capacity.Bavail == 0 ||
		capacity.Ffree == 0 {
		return StorageAvailability{}, ErrStorageEnvelope
	}
	mountID, err := linuxMountID(fd)
	if err != nil {
		return StorageAvailability{}, ErrStorageEnvelope
	}
	freeBytes, ok := multiplyStorageAmount(
		capacity.Bavail,
		uint64(capacity.Bsize),
	)
	if !ok || freeBytes == 0 {
		return StorageAvailability{}, ErrStorageEnvelope
	}
	device := uint64(identity.Dev)
	deviceMajor := unix.Major(identity.Dev)
	if deviceMajor == 0 {
		return StorageAvailability{}, ErrStorageEnvelope
	}
	return StorageAvailability{
		Filesystem: hostruntime.LifecycleFilesystemIdentity{
			Role:        role,
			MountID:     mountID,
			DeviceMajor: deviceMajor,
			DeviceMinor: unix.Minor(identity.Dev),
			RootInode:   identity.Ino,
			FSType:      fmt.Sprintf("0x%x", uint64(capacity.Type)),
		},
		Device:     device,
		FreeBytes:  freeBytes,
		FreeInodes: capacity.Ffree,
	}, nil
}

func linuxMountID(fd int) (uint64, error) {
	file, err := os.Open("/proc/self/fdinfo/" + strconv.Itoa(fd))
	if err != nil {
		return 0, ErrStorageEnvelope
	}
	defer file.Close()
	reader := bufio.NewReader(io.LimitReader(file, maximumFDInfoBytes+1))
	var mountID uint64
	var found bool
	for {
		line, readErr := reader.ReadString('\n')
		if len(line) > maximumFDInfoBytes {
			return 0, ErrStorageEnvelope
		}
		if strings.HasPrefix(line, "mnt_id:\t") {
			value := strings.TrimSuffix(
				strings.TrimPrefix(line, "mnt_id:\t"),
				"\n",
			)
			parsed, parseErr := strconv.ParseUint(value, 10, 64)
			if parseErr != nil || parsed == 0 || found {
				return 0, ErrStorageEnvelope
			}
			mountID = parsed
			found = true
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return 0, ErrStorageEnvelope
		}
	}
	if !found {
		return 0, ErrStorageEnvelope
	}
	return mountID, nil
}
