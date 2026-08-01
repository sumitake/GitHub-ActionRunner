package main

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sumitake/portable-ghar/internal/task11synthetic"
	"golang.org/x/sys/unix"
)

type listenerFileIdentity struct {
	device uint64
	inode  uint64
	mode   uint32
	uid    uint32
	gid    uint32
	nlink  uint64
	size   int64
}

type registrationFile struct {
	parentFD int
	name     string
	identity listenerFileIdentity
	removed  bool
}

func createRegistrationMarker(
	payload [sha256.Size]byte,
) (registrationMarker, error) {
	return createRegistrationMarkerAt(
		filepath.Dir(task11synthetic.RegistrationMarkerPath),
		filepath.Base(task11synthetic.RegistrationMarkerPath),
		payload,
		uint32(os.Geteuid()),
	)
}

func createRegistrationMarkerAt(
	parentPath string,
	name string,
	payload [sha256.Size]byte,
	expectedUID uint32,
) (registrationMarker, error) {
	if !validLeaf(name) {
		return nil, errors.New("task11 listener registration unavailable")
	}
	parentFD, parentIdentity, err := openExactDirectory(parentPath)
	if err != nil ||
		parentIdentity.uid != expectedUID {
		closeFD(parentFD)
		return nil, errors.New("task11 listener registration unavailable")
	}
	identity, err := createFreshFileAt(
		parentFD,
		name,
		payload[:],
		expectedUID,
	)
	if err != nil || syncDirectoryFD(parentFD) != nil {
		if err == nil {
			removeExactFileAt(parentFD, name, identity)
		}
		closeFD(parentFD)
		return nil, errors.New("task11 listener registration unavailable")
	}
	return &registrationFile{
		parentFD: parentFD,
		name:     name,
		identity: identity,
	}, nil
}

func (marker *registrationFile) Remove() error {
	if marker == nil ||
		marker.removed ||
		marker.parentFD < 0 ||
		!validLeaf(marker.name) {
		return errors.New("task11 listener registration unavailable")
	}
	defer func() {
		closeFD(marker.parentFD)
		marker.parentFD = -1
	}()
	current, err := identityAt(marker.parentFD, marker.name)
	if err != nil ||
		!current.equal(marker.identity) ||
		unix.Unlinkat(marker.parentFD, marker.name, 0) != nil ||
		syncDirectoryFD(marker.parentFD) != nil ||
		!absentAt(marker.parentFD, marker.name) {
		return errors.New("task11 listener registration unavailable")
	}
	marker.removed = true
	return nil
}

func createUpgradeStaging(
	payload [sha256.Size]byte,
) error {
	return createUpgradeStagingAt(
		filepath.Dir(filepath.Dir(task11synthetic.UpgradeStagingMarkerPath)),
		filepath.Base(filepath.Dir(task11synthetic.UpgradeStagingMarkerPath)),
		filepath.Base(task11synthetic.UpgradeStagingMarkerPath),
		payload,
		uint32(os.Geteuid()),
	)
}

func createUpgradeStagingAt(
	workPath string,
	updateName string,
	markerName string,
	payload [sha256.Size]byte,
	expectedUID uint32,
) error {
	if !validLeaf(updateName) || !validLeaf(markerName) {
		return errors.New("task11 listener upgrade staging unavailable")
	}
	workFD, workIdentity, err := openExactDirectory(workPath)
	if err != nil || workIdentity.uid != expectedUID ||
		!absentAt(workFD, updateName) {
		closeFD(workFD)
		return errors.New("task11 listener upgrade staging unavailable")
	}
	defer closeFD(workFD)
	if unix.Mkdirat(workFD, updateName, 0o700) != nil {
		return errors.New("task11 listener upgrade staging unavailable")
	}
	updateFD, err := unix.Openat(
		workFD,
		updateName,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		removeExactDirectoryAt(workFD, updateName)
		return errors.New("task11 listener upgrade staging unavailable")
	}
	defer closeFD(updateFD)
	updateIdentity, err := identityFromFD(updateFD)
	if err != nil ||
		!updateIdentity.isDirectory(0o700, expectedUID) ||
		updateIdentity.device != workIdentity.device {
		removeExactDirectoryAt(workFD, updateName)
		return errors.New("task11 listener upgrade staging unavailable")
	}
	markerIdentity, err := createFreshFileAt(
		updateFD,
		markerName,
		payload[:],
		expectedUID,
	)
	if err != nil ||
		!directoryContainsOnly(updateFD, markerName) ||
		syncDirectoryFD(updateFD) != nil ||
		syncDirectoryFD(workFD) != nil {
		if err == nil {
			removeExactFileAt(updateFD, markerName, markerIdentity)
		}
		removeExactDirectoryAt(workFD, updateName)
		return errors.New("task11 listener upgrade staging unavailable")
	}
	return nil
}

func createFreshFileAt(
	parentFD int,
	name string,
	payload []byte,
	expectedUID uint32,
) (listenerFileIdentity, error) {
	var zeroIdentity listenerFileIdentity
	if parentFD < 0 ||
		!validLeaf(name) ||
		len(payload) != sha256.Size ||
		!absentAt(parentFD, name) {
		return zeroIdentity, errors.New("task11 listener file unavailable")
	}
	fd, err := unix.Openat(
		parentFD,
		name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|
			unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0o600,
	)
	if err != nil {
		return zeroIdentity, errors.New("task11 listener file unavailable")
	}
	created := false
	defer func() {
		if !created {
			if identity, identityErr := identityFromFD(fd); identityErr == nil {
				removeExactFileAt(parentFD, name, identity)
			}
		}
		closeFD(fd)
	}()
	if unix.Fchmod(fd, 0o600) != nil {
		return zeroIdentity, errors.New("task11 listener file unavailable")
	}
	before, err := identityFromFD(fd)
	if err != nil ||
		!before.isRegular(0o600, expectedUID) ||
		before.size != 0 {
		return zeroIdentity, errors.New("task11 listener file unavailable")
	}
	if writeExactFD(fd, payload) != nil ||
		unix.Fsync(fd) != nil {
		return zeroIdentity, errors.New("task11 listener file unavailable")
	}
	after, err := identityFromFD(fd)
	pathIdentity, pathErr := identityAt(parentFD, name)
	if err != nil ||
		pathErr != nil ||
		!before.sameObject(after) ||
		!after.equal(pathIdentity) ||
		after.size != int64(len(payload)) ||
		!after.isRegular(0o600, expectedUID) {
		return zeroIdentity, errors.New("task11 listener file unavailable")
	}
	created = true
	return after, nil
}

func openExactDirectory(
	path string,
) (int, listenerFileIdentity, error) {
	var zeroIdentity listenerFileIdentity
	if !canonicalAbsolutePath(path) || path == "/" {
		return -1, zeroIdentity, errors.New("task11 listener directory unavailable")
	}
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	current, err := unix.Open(
		"/",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return -1, zeroIdentity, errors.New("task11 listener directory unavailable")
	}
	for _, segment := range segments {
		if !validLeaf(segment) {
			closeFD(current)
			return -1, zeroIdentity, errors.New("task11 listener directory unavailable")
		}
		next, openErr := unix.Openat(
			current,
			segment,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		closeFD(current)
		if openErr != nil {
			return -1, zeroIdentity, errors.New("task11 listener directory unavailable")
		}
		current = next
	}
	identity, err := identityFromFD(current)
	if err != nil || identity.mode&unix.S_IFMT != unix.S_IFDIR {
		closeFD(current)
		return -1, zeroIdentity, errors.New("task11 listener directory unavailable")
	}
	return current, identity, nil
}

func identityFromFD(fd int) (listenerFileIdentity, error) {
	var stat unix.Stat_t
	if fd < 0 || unix.Fstat(fd, &stat) != nil {
		return listenerFileIdentity{}, errors.New("task11 listener identity unavailable")
	}
	return identityFromStat(stat), nil
}

func identityAt(parentFD int, name string) (listenerFileIdentity, error) {
	var stat unix.Stat_t
	if parentFD < 0 ||
		!validLeaf(name) ||
		unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return listenerFileIdentity{}, errors.New("task11 listener identity unavailable")
	}
	return identityFromStat(stat), nil
}

func identityFromStat(stat unix.Stat_t) listenerFileIdentity {
	return listenerFileIdentity{
		device: uint64(stat.Dev),
		inode:  stat.Ino,
		mode:   uint32(stat.Mode),
		uid:    stat.Uid,
		gid:    stat.Gid,
		nlink:  uint64(stat.Nlink),
		size:   stat.Size,
	}
}

func (identity listenerFileIdentity) equal(
	other listenerFileIdentity,
) bool {
	return identity == other
}

func (identity listenerFileIdentity) sameObject(
	other listenerFileIdentity,
) bool {
	return identity.device == other.device &&
		identity.inode == other.inode &&
		identity.mode == other.mode &&
		identity.uid == other.uid &&
		identity.gid == other.gid &&
		identity.nlink == other.nlink
}

func (identity listenerFileIdentity) isRegular(
	mode uint32,
	uid uint32,
) bool {
	return identity.device != 0 &&
		identity.inode != 0 &&
		identity.mode&unix.S_IFMT == unix.S_IFREG &&
		identity.mode&0o777 == mode &&
		identity.uid == uid &&
		identity.nlink == 1
}

func (identity listenerFileIdentity) isDirectory(
	mode uint32,
	uid uint32,
) bool {
	return identity.device != 0 &&
		identity.inode != 0 &&
		identity.mode&unix.S_IFMT == unix.S_IFDIR &&
		identity.mode&0o777 == mode &&
		identity.uid == uid
}

func writeExactFD(fd int, payload []byte) error {
	for len(payload) > 0 {
		written, err := unix.Write(fd, payload)
		if err != nil || written <= 0 || written > len(payload) {
			return errors.New("task11 listener write unavailable")
		}
		payload = payload[written:]
	}
	return nil
}

func absentAt(parentFD int, name string) bool {
	var stat unix.Stat_t
	err := unix.Fstatat(
		parentFD,
		name,
		&stat,
		unix.AT_SYMLINK_NOFOLLOW,
	)
	return errors.Is(err, unix.ENOENT)
}

func removeExactFileAt(
	parentFD int,
	name string,
	want listenerFileIdentity,
) {
	current, err := identityAt(parentFD, name)
	if err == nil && current.equal(want) {
		_ = unix.Unlinkat(parentFD, name, 0)
		_ = syncDirectoryFD(parentFD)
	}
}

func removeExactDirectoryAt(parentFD int, name string) {
	_ = unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
	_ = syncDirectoryFD(parentFD)
}

func directoryContainsOnly(parentFD int, want string) bool {
	duplicate, err := unix.Dup(parentFD)
	if err != nil {
		return false
	}
	file := os.NewFile(uintptr(duplicate), "task11-directory")
	if file == nil {
		closeFD(duplicate)
		return false
	}
	names, readErr := file.Readdirnames(-1)
	closeErr := file.Close()
	return readErr == nil &&
		closeErr == nil &&
		len(names) == 1 &&
		names[0] == want
}

func canonicalAbsolutePath(path string) bool {
	return filepath.IsAbs(path) &&
		filepath.Clean(path) == path &&
		!strings.ContainsRune(path, 0)
}

func validLeaf(name string) bool {
	return name != "" &&
		name != "." &&
		name != ".." &&
		!strings.Contains(name, "/") &&
		!strings.ContainsRune(name, 0)
}

func closeFD(fd int) {
	if fd >= 0 {
		_ = unix.Close(fd)
	}
}

func readAllFile(file *os.File, maximum int64) ([]byte, error) {
	if file == nil || maximum <= 0 {
		return nil, errors.New("task11 listener read unavailable")
	}
	return io.ReadAll(io.LimitReader(file, maximum+1))
}
