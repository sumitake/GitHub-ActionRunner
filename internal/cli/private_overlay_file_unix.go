//go:build darwin || linux

package cli

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	maxPrivateTreeDepth    = 16
	maxPrivateTreeEntries  = 256
	maxPrivateArtifactSize = int64(1 << 30)
	privateTreeReadBatch   = 32
)

type privateTreeIdentity struct {
	device uint64
	inode  uint64
	mode   uint32
	uid    uint32
	nlink  uint64
	size   int64
}

func readPrivateOverlayDocument(path string, maximum int) ([]byte, error) {
	if !canonicalHostPath(path) || maximum <= 0 {
		return nil, ErrHostCommandFailed
	}
	rootPath := filepath.Dir(path)
	leaf := filepath.Base(path)
	if rootPath == "/" || leaf == "" || leaf == "." || leaf == ".." {
		return nil, ErrHostCommandFailed
	}
	rootFD, err := openPrivateTreeRoot(rootPath)
	if err != nil {
		return nil, ErrHostCommandFailed
	}
	defer unix.Close(rootFD)
	entries := 0
	if err := inspectPrivateTree(rootFD, 0, &entries); err != nil {
		return nil, ErrHostCommandFailed
	}
	return readPinnedPrivateTreeFile(rootFD, leaf, maximum)
}

func openPrivateTreeRoot(path string) (int, error) {
	if !canonicalHostPath(path) || path == "/" {
		return -1, ErrHostCommandFailed
	}
	fd, err := unix.Open(
		"/",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return -1, ErrHostCommandFailed
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if component == "" || component == "." || component == ".." {
			_ = unix.Close(fd)
			return -1, ErrHostCommandFailed
		}
		next, openErr := unix.Openat(
			fd,
			component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		closeErr := unix.Close(fd)
		if openErr != nil || closeErr != nil {
			if openErr == nil {
				_ = unix.Close(next)
			}
			return -1, ErrHostCommandFailed
		}
		fd = next
	}
	if _, err := privateTreeFDIdentity(
		fd,
		unix.S_IFDIR,
		0o700,
		false,
		maxPrivateArtifactSize,
	); err != nil {
		_ = unix.Close(fd)
		return -1, ErrHostCommandFailed
	}
	return fd, nil
}

func inspectPrivateTree(dirFD int, depth int, total *int) error {
	if dirFD < 0 || depth > maxPrivateTreeDepth || total == nil {
		return ErrHostCommandFailed
	}
	dupFD, err := unix.Dup(dirFD)
	if err != nil {
		return ErrHostCommandFailed
	}
	unix.CloseOnExec(dupFD)
	directory := os.NewFile(uintptr(dupFD), "private-tree")
	if directory == nil {
		_ = unix.Close(dupFD)
		return ErrHostCommandFailed
	}
	defer directory.Close()
	for {
		entries, readErr := directory.ReadDir(privateTreeReadBatch)
		for _, entry := range entries {
			name := entry.Name()
			if name == "" || name == "." || name == ".." {
				return ErrHostCommandFailed
			}
			*total++
			if *total > maxPrivateTreeEntries {
				return ErrHostCommandFailed
			}
			var pathStat unix.Stat_t
			if err := unix.Fstatat(
				dirFD,
				name,
				&pathStat,
				unix.AT_SYMLINK_NOFOLLOW,
			); err != nil {
				return ErrHostCommandFailed
			}
			kind := uint32(pathStat.Mode) & unix.S_IFMT
			switch kind {
			case unix.S_IFDIR:
				pathIdentity, err := validatePrivateTreeStat(
					&pathStat,
					unix.S_IFDIR,
					0o700,
					false,
					maxPrivateArtifactSize,
				)
				if err != nil || depth == maxPrivateTreeDepth {
					return ErrHostCommandFailed
				}
				childFD, err := unix.Openat(
					dirFD,
					name,
					unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
					0,
				)
				if err != nil {
					return ErrHostCommandFailed
				}
				childIdentity, identityErr := privateTreeFDIdentity(
					childFD,
					unix.S_IFDIR,
					0o700,
					false,
					maxPrivateArtifactSize,
				)
				if identityErr != nil || childIdentity != pathIdentity {
					_ = unix.Close(childFD)
					return ErrHostCommandFailed
				}
				walkErr := inspectPrivateTree(childFD, depth+1, total)
				closeErr := unix.Close(childFD)
				if walkErr != nil || closeErr != nil {
					return ErrHostCommandFailed
				}
			case unix.S_IFREG:
				pathIdentity, err := validatePrivateTreeStat(
					&pathStat,
					unix.S_IFREG,
					0o600,
					true,
					maxPrivateArtifactSize,
				)
				if err != nil {
					return ErrHostCommandFailed
				}
				fileFD, err := unix.Openat(
					dirFD,
					name,
					unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK,
					0,
				)
				if err != nil {
					return ErrHostCommandFailed
				}
				fileIdentity, identityErr := privateTreeFDIdentity(
					fileFD,
					unix.S_IFREG,
					0o600,
					true,
					maxPrivateArtifactSize,
				)
				closeErr := unix.Close(fileFD)
				if identityErr != nil || closeErr != nil ||
					fileIdentity != pathIdentity {
					return ErrHostCommandFailed
				}
			default:
				return ErrHostCommandFailed
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return ErrHostCommandFailed
		}
	}
}

func readPinnedPrivateTreeFile(
	rootFD int,
	name string,
	maximum int,
) ([]byte, error) {
	if rootFD < 0 || name == "" || name == "." || name == ".." ||
		strings.Contains(name, "/") || maximum <= 0 {
		return nil, ErrHostCommandFailed
	}
	fd, err := unix.Openat(
		rootFD,
		name,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK,
		0,
	)
	if err != nil {
		return nil, ErrHostCommandFailed
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrHostCommandFailed
	}
	defer file.Close()
	before, err := privateTreeFDIdentity(
		fd,
		unix.S_IFREG,
		0o600,
		true,
		int64(maximum),
	)
	if err != nil || before.size <= 0 {
		return nil, ErrHostCommandFailed
	}
	document, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || len(document) == 0 || len(document) > maximum {
		return nil, ErrHostCommandFailed
	}
	after, err := privateTreeFDIdentity(
		fd,
		unix.S_IFREG,
		0o600,
		true,
		int64(maximum),
	)
	if err != nil || before != after || after.size != int64(len(document)) {
		return nil, ErrHostCommandFailed
	}
	var pathStat unix.Stat_t
	if err := unix.Fstatat(
		rootFD,
		name,
		&pathStat,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return nil, ErrHostCommandFailed
	}
	pathIdentity, err := validatePrivateTreeStat(
		&pathStat,
		unix.S_IFREG,
		0o600,
		true,
		int64(maximum),
	)
	if err != nil || pathIdentity != after {
		return nil, ErrHostCommandFailed
	}
	return document, nil
}

func privateTreeFDIdentity(
	fd int,
	expectedKind uint32,
	expectedMode uint32,
	singleLink bool,
	maximumSize int64,
) (privateTreeIdentity, error) {
	var stat unix.Stat_t
	if fd < 0 || unix.Fstat(fd, &stat) != nil {
		return privateTreeIdentity{}, ErrHostCommandFailed
	}
	return validatePrivateTreeStat(
		&stat,
		expectedKind,
		expectedMode,
		singleLink,
		maximumSize,
	)
}

func validatePrivateTreeStat(
	stat *unix.Stat_t,
	expectedKind uint32,
	expectedMode uint32,
	singleLink bool,
	maximumSize int64,
) (privateTreeIdentity, error) {
	if stat == nil || maximumSize < 0 {
		return privateTreeIdentity{}, ErrHostCommandFailed
	}
	mode := uint32(stat.Mode)
	if mode&unix.S_IFMT != expectedKind ||
		mode&0o7777 != expectedMode ||
		stat.Uid != uint32(os.Geteuid()) ||
		(singleLink && uint64(stat.Nlink) != 1) ||
		stat.Ino == 0 ||
		int64(stat.Size) < 0 ||
		int64(stat.Size) > maximumSize {
		return privateTreeIdentity{}, ErrHostCommandFailed
	}
	return privateTreeIdentity{
		device: uint64(stat.Dev),
		inode:  uint64(stat.Ino),
		mode:   mode,
		uid:    stat.Uid,
		nlink:  uint64(stat.Nlink),
		size:   int64(stat.Size),
	}, nil
}
