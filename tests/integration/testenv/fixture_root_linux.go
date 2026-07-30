//go:build integration && linux

package testenv

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type linuxFixtureRootLeaseOperations struct {
	binding        FixtureBinding
	parent         *os.File
	root           *os.File
	basename       string
	parentIdentity inputDirectoryIdentity
	rootIdentity   inputDirectoryIdentity
	parentLocked   bool
	rootLocked     bool
}

func newLinuxFixtureRootAuthority(
	binding FixtureBinding,
) (*lockedFixtureRootAuthority, error) {
	if !validAbsolutePath(binding.Root) {
		return nil, ErrFixtureStart
	}
	return newLockedFixtureRootAuthority(
		&linuxFixtureRootLeaseOperations{binding: binding},
	)
}

func observeLinuxFixtureRoot(binding FixtureBinding) (string, error) {
	if !validAbsolutePath(binding.Root) ||
		binding.ParentDevice == 0 ||
		binding.ParentInode == 0 {
		return "", ErrStaticPreflight
	}
	parentPath := filepath.Dir(binding.Root)
	basename := filepath.Base(binding.Root)
	if basename == "." || basename == string(filepath.Separator) ||
		basename == "" || strings.ContainsRune(basename, filepath.Separator) {
		return "", ErrStaticPreflight
	}

	rootFD, err := unix.Open(
		string(filepath.Separator),
		unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return "", ErrStaticPreflight
	}
	defer unix.Close(rootFD)
	parentRelative := strings.TrimPrefix(
		parentPath,
		string(filepath.Separator),
	)
	if parentRelative == "" {
		parentRelative = "."
	}
	parentFD, err := unix.Openat2(rootFD, parentRelative, &unix.OpenHow{
		Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: uint64(
			unix.RESOLVE_BENEATH |
				unix.RESOLVE_NO_MAGICLINKS |
				unix.RESOLVE_NO_SYMLINKS,
		),
	})
	if err != nil {
		return "", ErrStaticPreflight
	}
	defer unix.Close(parentFD)
	parentIdentity, err := inputDirectoryIdentityFromFD(parentFD)
	if err != nil ||
		parentIdentity.device != binding.ParentDevice ||
		parentIdentity.inode != binding.ParentInode ||
		parentIdentity.uid != binding.ExecutionOwnerUID ||
		parentIdentity.mode&0o022 != 0 ||
		!localPOSIXDirectory(parentFD, parentIdentity) {
		return "", ErrStaticPreflight
	}

	fixtureFD, err := unix.Openat2(parentFD, basename, &unix.OpenHow{
		Flags: uint64(
			unix.O_RDONLY |
				unix.O_DIRECTORY |
				unix.O_CLOEXEC |
				unix.O_NONBLOCK,
		),
		Resolve: uint64(
			unix.RESOLVE_BENEATH |
				unix.RESOLVE_NO_MAGICLINKS |
				unix.RESOLVE_NO_SYMLINKS |
				unix.RESOLVE_NO_XDEV,
		),
	})
	if err != nil {
		return "", ErrStaticPreflight
	}
	fixture := os.NewFile(uintptr(fixtureFD), "portable-ghar-fixture-root")
	if fixture == nil {
		_ = unix.Close(fixtureFD)
		return "", ErrStaticPreflight
	}
	defer fixture.Close()
	fixtureIdentity, err := inputDirectoryIdentityFromFD(fixtureFD)
	if err != nil ||
		fixtureIdentity.device != parentIdentity.device ||
		fixtureIdentity.uid != binding.ExecutionOwnerUID ||
		fixtureIdentity.mode&0o7777 != 0o700 ||
		!localPOSIXDirectory(fixtureFD, fixtureIdentity) {
		return "", ErrStaticPreflight
	}
	pathIdentity, err := inputDirectoryIdentityFromAt(parentFD, basename)
	if err != nil || pathIdentity != fixtureIdentity {
		return "", ErrStaticPreflight
	}
	empty, err := linuxDirectoryEmpty(fixtureFD)
	if err != nil || !empty {
		return "", ErrStaticPreflight
	}
	after, err := inputDirectoryIdentityFromFD(fixtureFD)
	if err != nil || after != fixtureIdentity {
		return "", ErrStaticPreflight
	}
	pathIdentity, err = inputDirectoryIdentityFromAt(parentFD, basename)
	if err != nil || pathIdentity != fixtureIdentity {
		return "", ErrStaticPreflight
	}
	digest, err := computeFixtureEmptyDigest(fixtureRootObservation{
		SchemaVersion:  1,
		ParentDevice:   parentIdentity.device,
		ParentInode:    parentIdentity.inode,
		ParentOwnerUID: parentIdentity.uid,
		ParentMode:     parentIdentity.mode & 0o7777,
		RootDevice:     fixtureIdentity.device,
		RootInode:      fixtureIdentity.inode,
		OwnerUID:       fixtureIdentity.uid,
		Mode:           fixtureIdentity.mode & 0o7777,
	})
	if err != nil || digest != binding.RequiredEmptyDigest {
		return "", ErrStaticPreflight
	}
	return digest, nil
}

func (o *linuxFixtureRootLeaseOperations) Lock() error {
	if o == nil || o.parent != nil || o.root != nil ||
		!validAbsolutePath(o.binding.Root) {
		return ErrFixtureStart
	}
	parentPath := filepath.Dir(o.binding.Root)
	basename := filepath.Base(o.binding.Root)
	if basename == "." || basename == string(filepath.Separator) ||
		basename == "" || strings.ContainsRune(basename, filepath.Separator) {
		return ErrFixtureStart
	}
	rootFD, err := unix.Open(
		string(filepath.Separator),
		unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return ErrFixtureStart
	}
	defer unix.Close(rootFD)
	parentRelative := strings.TrimPrefix(
		parentPath,
		string(filepath.Separator),
	)
	if parentRelative == "" {
		parentRelative = "."
	}
	parentFD, err := unix.Openat2(rootFD, parentRelative, &unix.OpenHow{
		Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: uint64(
			unix.RESOLVE_BENEATH |
				unix.RESOLVE_NO_MAGICLINKS |
				unix.RESOLVE_NO_SYMLINKS,
		),
	})
	if err != nil {
		return ErrFixtureStart
	}
	parent := os.NewFile(uintptr(parentFD), "portable-ghar-fixture-parent")
	if parent == nil {
		_ = unix.Close(parentFD)
		return ErrFixtureStart
	}
	closeParent := true
	defer func() {
		if closeParent {
			_ = parent.Close()
		}
	}()
	parentIdentity, err := inputDirectoryIdentityFromFD(parentFD)
	if err != nil ||
		parentIdentity.device != o.binding.ParentDevice ||
		parentIdentity.inode != o.binding.ParentInode ||
		parentIdentity.uid != o.binding.ExecutionOwnerUID ||
		parentIdentity.mode&0o022 != 0 ||
		!localPOSIXDirectory(parentFD, parentIdentity) {
		return ErrFixtureStart
	}
	if err := unix.Flock(parentFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) ||
			errors.Is(err, unix.EAGAIN) {
			return ErrFixtureRootInUse
		}
		return ErrFixtureStart
	}
	unlockParent := true
	defer func() {
		if unlockParent {
			_ = unix.Flock(parentFD, unix.LOCK_UN)
		}
	}()

	fixtureFD, err := unix.Openat2(parentFD, basename, &unix.OpenHow{
		Flags: uint64(
			unix.O_RDONLY |
				unix.O_DIRECTORY |
				unix.O_CLOEXEC |
				unix.O_NONBLOCK,
		),
		Resolve: uint64(
			unix.RESOLVE_BENEATH |
				unix.RESOLVE_NO_MAGICLINKS |
				unix.RESOLVE_NO_SYMLINKS |
				unix.RESOLVE_NO_XDEV,
		),
	})
	if err != nil {
		return ErrFixtureStart
	}
	fixture := os.NewFile(uintptr(fixtureFD), "portable-ghar-fixture-root")
	if fixture == nil {
		_ = unix.Close(fixtureFD)
		return ErrFixtureStart
	}
	closeFixture := true
	defer func() {
		if closeFixture {
			_ = fixture.Close()
		}
	}()
	fixtureIdentity, err := inputDirectoryIdentityFromFD(fixtureFD)
	if err != nil ||
		fixtureIdentity.device != parentIdentity.device ||
		fixtureIdentity.uid != o.binding.ExecutionOwnerUID ||
		fixtureIdentity.mode&0o7777 != 0o700 ||
		!localPOSIXDirectory(fixtureFD, fixtureIdentity) {
		return ErrFixtureStart
	}
	if err := unix.Flock(fixtureFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) ||
			errors.Is(err, unix.EAGAIN) {
			return ErrFixtureRootInUse
		}
		return ErrFixtureStart
	}
	unlockFixture := true
	defer func() {
		if unlockFixture {
			_ = unix.Flock(fixtureFD, unix.LOCK_UN)
		}
	}()
	pathIdentity, err := inputDirectoryIdentityFromAt(parentFD, basename)
	if err != nil || pathIdentity != fixtureIdentity {
		return ErrFixtureStart
	}

	o.parent = parent
	o.root = fixture
	o.basename = basename
	o.parentIdentity = parentIdentity
	o.rootIdentity = fixtureIdentity
	o.parentLocked = true
	o.rootLocked = true
	closeParent = false
	closeFixture = false
	unlockParent = false
	unlockFixture = false
	return nil
}

func (o *linuxFixtureRootLeaseOperations) ObserveEmpty() (
	fixtureRootObservation,
	error,
) {
	if o == nil || o.parent == nil || o.root == nil ||
		o.basename == "" || !o.parentLocked || !o.rootLocked {
		return fixtureRootObservation{}, ErrFixtureStart
	}
	parent, err := inputDirectoryIdentityFromFD(int(o.parent.Fd()))
	if err != nil || parent != o.parentIdentity {
		return fixtureRootObservation{}, ErrFixtureStart
	}
	root, err := inputDirectoryIdentityFromFD(int(o.root.Fd()))
	if err != nil || root != o.rootIdentity {
		return fixtureRootObservation{}, ErrFixtureStart
	}
	path, err := inputDirectoryIdentityFromAt(
		int(o.parent.Fd()),
		o.basename,
	)
	if err != nil || path != o.rootIdentity {
		return fixtureRootObservation{}, ErrFixtureStart
	}
	empty, err := linuxDirectoryEmpty(int(o.root.Fd()))
	if err != nil {
		return fixtureRootObservation{}, ErrFixtureStart
	}
	if !empty {
		return fixtureRootObservation{}, ErrFixtureUnexpectedObject
	}
	parentAfter, err := inputDirectoryIdentityFromFD(int(o.parent.Fd()))
	if err != nil || parentAfter != o.parentIdentity {
		return fixtureRootObservation{}, ErrFixtureStart
	}
	rootAfter, err := inputDirectoryIdentityFromFD(int(o.root.Fd()))
	if err != nil || rootAfter != o.rootIdentity {
		return fixtureRootObservation{}, ErrFixtureStart
	}
	path, err = inputDirectoryIdentityFromAt(
		int(o.parent.Fd()),
		o.basename,
	)
	if err != nil || path != o.rootIdentity {
		return fixtureRootObservation{}, ErrFixtureStart
	}
	return fixtureRootObservation{
		SchemaVersion:  1,
		ParentDevice:   o.parentIdentity.device,
		ParentInode:    o.parentIdentity.inode,
		ParentOwnerUID: o.parentIdentity.uid,
		ParentMode:     o.parentIdentity.mode & 0o7777,
		RootDevice:     o.rootIdentity.device,
		RootInode:      o.rootIdentity.inode,
		OwnerUID:       o.rootIdentity.uid,
		Mode:           o.rootIdentity.mode & 0o7777,
	}, nil
}

func (o *linuxFixtureRootLeaseOperations) Remove() error {
	if o == nil || o.parent == nil || o.root == nil ||
		o.basename == "" {
		return ErrFixtureCleanup
	}
	if err := unix.Unlinkat(
		int(o.parent.Fd()),
		o.basename,
		unix.AT_REMOVEDIR,
	); err != nil {
		if errors.Is(err, unix.ENOTEMPTY) ||
			errors.Is(err, unix.EEXIST) {
			return ErrFixtureUnexpectedObject
		}
		return ErrFixtureCleanup
	}
	return nil
}

func (o *linuxFixtureRootLeaseOperations) SyncParent() error {
	if o == nil || o.parent == nil {
		return ErrFixtureCleanup
	}
	if err := unix.Fsync(int(o.parent.Fd())); err != nil {
		return ErrFixtureCleanup
	}
	return nil
}

func (o *linuxFixtureRootLeaseOperations) ProveAbsent() error {
	if o == nil || o.parent == nil || o.basename == "" {
		return ErrFixtureCleanup
	}
	var stat unix.Stat_t
	err := unix.Fstatat(
		int(o.parent.Fd()),
		o.basename,
		&stat,
		unix.AT_SYMLINK_NOFOLLOW,
	)
	if !errors.Is(err, unix.ENOENT) {
		return ErrFixtureCleanup
	}
	return nil
}

func (o *linuxFixtureRootLeaseOperations) Close() error {
	if o == nil {
		return ErrFixtureCleanup
	}
	var failed bool
	if o.root != nil {
		if o.rootLocked {
			if err := unix.Flock(
				int(o.root.Fd()),
				unix.LOCK_UN,
			); err != nil {
				failed = true
			}
			o.rootLocked = false
		}
		if err := o.root.Close(); err != nil {
			failed = true
		}
		o.root = nil
	}
	if o.parent != nil {
		if o.parentLocked {
			if err := unix.Flock(
				int(o.parent.Fd()),
				unix.LOCK_UN,
			); err != nil {
				failed = true
			}
			o.parentLocked = false
		}
		if err := o.parent.Close(); err != nil {
			failed = true
		}
		o.parent = nil
	}
	if failed {
		return ErrFixtureCleanup
	}
	return nil
}

func linuxDirectoryEmpty(fd int) (bool, error) {
	if fd < 0 {
		return false, ErrFixtureStart
	}
	if _, err := unix.Seek(fd, 0, 0); err != nil {
		return false, ErrFixtureStart
	}
	buffer := make([]byte, 4096)
	defer zeroLeaseBytes(buffer)
	for {
		count, err := unix.ReadDirent(fd, buffer)
		if err != nil {
			return false, ErrFixtureStart
		}
		if count == 0 {
			break
		}
		_, _, names := unix.ParseDirent(buffer[:count], -1, nil)
		for _, name := range names {
			if name != "." && name != ".." {
				return false, nil
			}
		}
	}
	if _, err := unix.Seek(fd, 0, 0); err != nil {
		return false, ErrFixtureStart
	}
	return true, nil
}

func inputDirectoryIdentityFromAt(
	parentFD int,
	basename string,
) (inputDirectoryIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(
		parentFD,
		basename,
		&stat,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return inputDirectoryIdentity{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		stat.Dev == 0 ||
		stat.Ino == 0 ||
		stat.Nlink == 0 {
		return inputDirectoryIdentity{}, ErrStaticPreflight
	}
	return inputDirectoryIdentity{
		device: uint64(stat.Dev),
		inode:  uint64(stat.Ino),
		mode:   uint32(stat.Mode),
		uid:    stat.Uid,
		gid:    stat.Gid,
		nlink:  uint64(stat.Nlink),
	}, nil
}
