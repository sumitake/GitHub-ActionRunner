//go:build darwin || linux

package productionruntime

import (
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func readPinnedAbsoluteFile(
	path string,
	mode uint32,
	maximum int,
) ([]byte, error) {
	if !filepath.IsAbs(path) ||
		filepath.Clean(path) != path ||
		maximum <= 0 {
		return nil, ErrProtocol
	}
	fd, err := unix.Open(
		path,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK,
		0,
	)
	if err != nil {
		return nil, ErrProtocol
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrProtocol
	}
	defer file.Close()
	beforeInfo, err := file.Stat()
	if err != nil {
		return nil, ErrProtocol
	}
	before, ok := privateReleaseIdentity(
		beforeInfo,
		0,
		os.FileMode(mode),
		true,
	)
	if !ok ||
		before.size <= 0 ||
		before.size > int64(maximum) {
		return nil, ErrProtocol
	}
	document, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil ||
		len(document) == 0 ||
		len(document) > maximum {
		return nil, ErrProtocol
	}
	afterInfo, err := file.Stat()
	if err != nil {
		return nil, ErrProtocol
	}
	after, ok := privateReleaseIdentity(
		afterInfo,
		0,
		os.FileMode(mode),
		true,
	)
	if !ok ||
		before != after ||
		after.size != int64(len(document)) {
		return nil, ErrProtocol
	}
	return document, nil
}
