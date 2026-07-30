//go:build integration && linux

package testenv

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	linuxWorkspaceStateDirectory     = "state"
	linuxWorkspaceRelayDirectory     = "relay"
	linuxWorkspaceAuthorityDirectory = "authority"
	linuxWorkspaceDatabase           = "controller.db"
	linuxWorkspaceDatabaseWAL        = "controller.db-wal"
	linuxWorkspaceDatabaseSHM        = "controller.db-shm"
)

type linuxFixtureWorkspaceOperations struct {
	binding           FixtureBinding
	parent            *os.File
	root              *os.File
	state             *os.File
	relay             *os.File
	authority         *os.File
	basename          string
	parentIdentity    inputDirectoryIdentity
	rootIdentity      inputDirectoryIdentity
	stateIdentity     inputDirectoryIdentity
	relayIdentity     inputDirectoryIdentity
	authorityIdentity inputDirectoryIdentity
	brokerUID         uint32
	brokerGID         uint32
	prepareAttempted  bool
	prepared          bool
	removed           bool
}

func newLinuxFixtureWorkspaceOperations(
	binding FixtureBinding,
) (*linuxFixtureWorkspaceOperations, error) {
	if !validAbsolutePath(binding.Root) ||
		binding.ParentDevice == 0 ||
		binding.ParentInode == 0 ||
		!isLowerHex(binding.RequiredEmptyDigest, 64) {
		return nil, ErrFixtureStart
	}
	return &linuxFixtureWorkspaceOperations{binding: binding}, nil
}

func (o *linuxFixtureWorkspaceOperations) Prepare(
	brokerUID uint32,
	brokerGID uint32,
) error {
	if o == nil || o.prepareAttempted || o.removed || brokerUID == 0 {
		return ErrFixtureStart
	}
	o.prepareAttempted = true
	parent, root, basename, parentIdentity, rootIdentity, err :=
		openLinuxFixtureWorkspaceRoot(o.binding)
	if err != nil {
		if errors.Is(err, ErrFixtureUnexpectedObject) {
			return ErrFixtureUnexpectedObject
		}
		return ErrFixtureStart
	}
	o.parent = parent
	o.root = root
	o.basename = basename
	o.parentIdentity = parentIdentity
	o.rootIdentity = rootIdentity
	o.brokerUID = brokerUID
	o.brokerGID = brokerGID

	state, stateIdentity, err := createLinuxWorkspaceDirectory(
		int(root.Fd()),
		rootIdentity,
		linuxWorkspaceStateDirectory,
		rootIdentity.uid,
		rootIdentity.gid,
	)
	if err != nil {
		return ErrFixtureStart
	}
	o.state = state
	o.stateIdentity = stateIdentity

	relay, relayIdentity, err := createLinuxWorkspaceDirectory(
		int(root.Fd()),
		rootIdentity,
		linuxWorkspaceRelayDirectory,
		brokerUID,
		brokerGID,
	)
	if err != nil {
		return ErrFixtureStart
	}
	o.relay = relay
	o.relayIdentity = relayIdentity

	authority, authorityIdentity, err := createLinuxWorkspaceDirectory(
		int(root.Fd()),
		rootIdentity,
		linuxWorkspaceAuthorityDirectory,
		brokerUID,
		brokerGID,
	)
	if err != nil {
		return ErrFixtureStart
	}
	o.authority = authority
	o.authorityIdentity = authorityIdentity
	if err := o.revalidateRoot(); err != nil {
		return ErrFixtureStart
	}
	o.prepared = true
	return nil
}

func (o *linuxFixtureWorkspaceOperations) StateDatabasePath() (
	string,
	error,
) {
	if o == nil || !o.prepared || o.removed ||
		o.state == nil || o.root == nil {
		return "", ErrFixtureStart
	}
	if err := o.revalidateRoot(); err != nil {
		return "", ErrFixtureStart
	}
	if err := validateLinuxWorkspaceDirectory(
		int(o.root.Fd()),
		linuxWorkspaceStateDirectory,
		o.state,
		o.stateIdentity,
		o.rootIdentity,
		o.rootIdentity.uid,
		o.rootIdentity.gid,
	); err != nil {
		return "", ErrFixtureStart
	}
	path := filepath.Join(
		o.binding.Root,
		linuxWorkspaceStateDirectory,
		linuxWorkspaceDatabase,
	)
	if !validAbsolutePath(path) {
		return "", ErrFixtureStart
	}
	return path, nil
}

func (o *linuxFixtureWorkspaceOperations) Remove() error {
	if o == nil || !o.prepareAttempted {
		return ErrFixtureCleanup
	}
	if o.removed {
		return nil
	}
	if o.root == nil {
		o.removed = true
		return nil
	}
	if err := o.revalidateRoot(); err != nil {
		return ErrFixtureCleanup
	}

	rootNames, err := linuxWorkspaceDirectoryNames(
		int(o.root.Fd()),
		3,
	)
	if err != nil {
		return normalizeLinuxWorkspaceRemovalError(err)
	}
	for _, name := range rootNames {
		switch name {
		case linuxWorkspaceStateDirectory,
			linuxWorkspaceRelayDirectory,
			linuxWorkspaceAuthorityDirectory:
		default:
			return ErrFixtureUnexpectedObject
		}
	}

	state, stateIdentity, statePresent, err :=
		o.openExpectedDirectory(linuxWorkspaceStateDirectory)
	if err != nil {
		return normalizeLinuxWorkspaceRemovalError(err)
	}
	relay, relayIdentity, relayPresent, err :=
		o.openExpectedDirectory(linuxWorkspaceRelayDirectory)
	if err != nil {
		return normalizeLinuxWorkspaceRemovalError(err)
	}
	authority, authorityIdentity, authorityPresent, err :=
		o.openExpectedDirectory(linuxWorkspaceAuthorityDirectory)
	if err != nil {
		return normalizeLinuxWorkspaceRemovalError(err)
	}

	stateNames, err := scanLinuxWorkspaceState(
		state,
		stateIdentity,
		o.rootIdentity,
	)
	if err != nil {
		return normalizeLinuxWorkspaceRemovalError(err)
	}
	if err := requireLinuxWorkspaceDirectoryEmpty(relay); err != nil {
		return normalizeLinuxWorkspaceRemovalError(err)
	}
	if err := requireLinuxWorkspaceDirectoryEmpty(authority); err != nil {
		return normalizeLinuxWorkspaceRemovalError(err)
	}

	if state != nil {
		for _, name := range []string{
			linuxWorkspaceDatabase,
			linuxWorkspaceDatabaseWAL,
			linuxWorkspaceDatabaseSHM,
		} {
			if !linuxWorkspaceNamePresent(stateNames, name) {
				continue
			}
			if err := unix.Unlinkat(int(state.Fd()), name, 0); err != nil {
				return ErrFixtureCleanup
			}
		}
		if err := unix.Fsync(int(state.Fd())); err != nil {
			return ErrFixtureCleanup
		}
		if err := requireLinuxWorkspaceDirectoryEmpty(state); err != nil {
			return normalizeLinuxWorkspaceRemovalError(err)
		}
	}

	for _, directory := range []struct {
		name     string
		file     *os.File
		identity inputDirectoryIdentity
		present  bool
	}{
		{
			name: linuxWorkspaceAuthorityDirectory,
			file: authority, identity: authorityIdentity,
			present: authorityPresent,
		},
		{
			name: linuxWorkspaceRelayDirectory,
			file: relay, identity: relayIdentity,
			present: relayPresent,
		},
		{
			name: linuxWorkspaceStateDirectory,
			file: state, identity: stateIdentity,
			present: statePresent,
		},
	} {
		if err := o.removeExpectedDirectory(
			directory.name,
			directory.file,
			directory.identity,
			directory.present,
		); err != nil {
			return normalizeLinuxWorkspaceRemovalError(err)
		}
	}
	if err := unix.Fsync(int(o.root.Fd())); err != nil {
		return ErrFixtureCleanup
	}
	empty, err := linuxDirectoryEmpty(int(o.root.Fd()))
	if err != nil {
		return ErrFixtureCleanup
	}
	if !empty {
		return ErrFixtureUnexpectedObject
	}
	if err := o.revalidateRoot(); err != nil {
		return ErrFixtureCleanup
	}
	o.removed = true
	return nil
}

func (o *linuxFixtureWorkspaceOperations) Close() error {
	if o == nil {
		return ErrFixtureCleanup
	}
	var failed bool
	for _, target := range []**os.File{
		&o.authority,
		&o.relay,
		&o.state,
		&o.root,
		&o.parent,
	} {
		if *target == nil {
			continue
		}
		if err := (*target).Close(); err != nil {
			failed = true
		}
		*target = nil
	}
	if failed {
		return ErrFixtureCleanup
	}
	return nil
}

func openLinuxFixtureWorkspaceRoot(
	binding FixtureBinding,
) (
	*os.File,
	*os.File,
	string,
	inputDirectoryIdentity,
	inputDirectoryIdentity,
	error,
) {
	parentPath := filepath.Dir(binding.Root)
	basename := filepath.Base(binding.Root)
	if basename == "." || basename == string(filepath.Separator) ||
		basename == "" || strings.ContainsRune(basename, filepath.Separator) {
		return nil, nil, "", inputDirectoryIdentity{},
			inputDirectoryIdentity{}, ErrFixtureStart
	}
	slashFD, err := unix.Open(
		string(filepath.Separator),
		unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, nil, "", inputDirectoryIdentity{},
			inputDirectoryIdentity{}, ErrFixtureStart
	}
	defer unix.Close(slashFD)
	parentRelative := strings.TrimPrefix(
		parentPath,
		string(filepath.Separator),
	)
	if parentRelative == "" {
		parentRelative = "."
	}
	parentFD, err := unix.Openat2(slashFD, parentRelative, &unix.OpenHow{
		Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: uint64(
			unix.RESOLVE_BENEATH |
				unix.RESOLVE_NO_MAGICLINKS |
				unix.RESOLVE_NO_SYMLINKS,
		),
	})
	if err != nil {
		return nil, nil, "", inputDirectoryIdentity{},
			inputDirectoryIdentity{}, ErrFixtureStart
	}
	parent := os.NewFile(uintptr(parentFD), "portable-ghar-workspace-parent")
	if parent == nil {
		_ = unix.Close(parentFD)
		return nil, nil, "", inputDirectoryIdentity{},
			inputDirectoryIdentity{}, ErrFixtureStart
	}
	closeParent := true
	defer func() {
		if closeParent {
			_ = parent.Close()
		}
	}()
	parentIdentity, err := inputDirectoryIdentityFromFD(parentFD)
	if err != nil ||
		parentIdentity.device != binding.ParentDevice ||
		parentIdentity.inode != binding.ParentInode ||
		parentIdentity.uid != binding.ExecutionOwnerUID ||
		parentIdentity.mode&0o022 != 0 ||
		!localPOSIXDirectory(parentFD, parentIdentity) {
		return nil, nil, "", inputDirectoryIdentity{},
			inputDirectoryIdentity{}, ErrFixtureStart
	}

	rootFD, err := unix.Openat2(parentFD, basename, &unix.OpenHow{
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
		return nil, nil, "", inputDirectoryIdentity{},
			inputDirectoryIdentity{}, ErrFixtureStart
	}
	root := os.NewFile(uintptr(rootFD), "portable-ghar-workspace-root")
	if root == nil {
		_ = unix.Close(rootFD)
		return nil, nil, "", inputDirectoryIdentity{},
			inputDirectoryIdentity{}, ErrFixtureStart
	}
	closeRoot := true
	defer func() {
		if closeRoot {
			_ = root.Close()
		}
	}()
	rootIdentity, err := inputDirectoryIdentityFromFD(rootFD)
	if err != nil ||
		rootIdentity.device != parentIdentity.device ||
		rootIdentity.uid != binding.ExecutionOwnerUID ||
		rootIdentity.mode&0o7777 != 0o700 ||
		!localPOSIXDirectory(rootFD, rootIdentity) {
		return nil, nil, "", inputDirectoryIdentity{},
			inputDirectoryIdentity{}, ErrFixtureStart
	}
	pathIdentity, err := inputDirectoryIdentityFromAt(parentFD, basename)
	if err != nil || pathIdentity != rootIdentity {
		return nil, nil, "", inputDirectoryIdentity{},
			inputDirectoryIdentity{}, ErrFixtureStart
	}
	empty, err := linuxDirectoryEmpty(rootFD)
	if err != nil {
		return nil, nil, "", inputDirectoryIdentity{},
			inputDirectoryIdentity{}, ErrFixtureStart
	}
	if !empty {
		return nil, nil, "", inputDirectoryIdentity{},
			inputDirectoryIdentity{}, ErrFixtureUnexpectedObject
	}
	observation := fixtureRootObservation{
		SchemaVersion:  1,
		ParentDevice:   parentIdentity.device,
		ParentInode:    parentIdentity.inode,
		ParentOwnerUID: parentIdentity.uid,
		ParentMode:     parentIdentity.mode & 0o7777,
		RootDevice:     rootIdentity.device,
		RootInode:      rootIdentity.inode,
		OwnerUID:       rootIdentity.uid,
		Mode:           rootIdentity.mode & 0o7777,
	}
	digest, err := computeFixtureEmptyDigest(observation)
	if err != nil ||
		!fixtureRootObservationMatches(binding, observation) ||
		digest != binding.RequiredEmptyDigest {
		return nil, nil, "", inputDirectoryIdentity{},
			inputDirectoryIdentity{}, ErrFixtureStart
	}
	closeParent = false
	closeRoot = false
	return parent, root, basename, parentIdentity, rootIdentity, nil
}

func createLinuxWorkspaceDirectory(
	rootFD int,
	rootIdentity inputDirectoryIdentity,
	name string,
	uid uint32,
	gid uint32,
) (*os.File, inputDirectoryIdentity, error) {
	if err := unix.Mkdirat(rootFD, name, 0o700); err != nil {
		return nil, inputDirectoryIdentity{}, ErrFixtureStart
	}
	childFD, err := unix.Openat2(rootFD, name, &unix.OpenHow{
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
		return nil, inputDirectoryIdentity{}, ErrFixtureStart
	}
	child := os.NewFile(uintptr(childFD), "portable-ghar-workspace-"+name)
	if child == nil {
		_ = unix.Close(childFD)
		return nil, inputDirectoryIdentity{}, ErrFixtureStart
	}
	closeChild := true
	defer func() {
		if closeChild {
			_ = child.Close()
		}
	}()
	if err := unix.Fchown(childFD, int(uid), int(gid)); err != nil {
		return nil, inputDirectoryIdentity{}, ErrFixtureStart
	}
	if err := unix.Fchmod(childFD, 0o700); err != nil {
		return nil, inputDirectoryIdentity{}, ErrFixtureStart
	}
	if err := unix.Fsync(childFD); err != nil {
		return nil, inputDirectoryIdentity{}, ErrFixtureStart
	}
	if err := unix.Fsync(rootFD); err != nil {
		return nil, inputDirectoryIdentity{}, ErrFixtureStart
	}
	identity, err := inputDirectoryIdentityFromFD(childFD)
	if err != nil ||
		identity.device != rootIdentity.device ||
		identity.uid != uid ||
		identity.gid != gid ||
		identity.mode&0o7777 != 0o700 ||
		!localPOSIXDirectory(childFD, identity) {
		return nil, inputDirectoryIdentity{}, ErrFixtureStart
	}
	pathIdentity, err := inputDirectoryIdentityFromAt(rootFD, name)
	if err != nil || pathIdentity != identity {
		return nil, inputDirectoryIdentity{}, ErrFixtureStart
	}
	closeChild = false
	return child, identity, nil
}

func (o *linuxFixtureWorkspaceOperations) revalidateRoot() error {
	if o == nil || o.parent == nil || o.root == nil || o.basename == "" {
		return ErrFixtureCleanup
	}
	parent, err := inputDirectoryIdentityFromFD(int(o.parent.Fd()))
	if err != nil || parent != o.parentIdentity {
		return ErrFixtureCleanup
	}
	root, err := inputDirectoryIdentityFromFD(int(o.root.Fd()))
	if err != nil || root != o.rootIdentity {
		return ErrFixtureCleanup
	}
	path, err := inputDirectoryIdentityFromAt(
		int(o.parent.Fd()),
		o.basename,
	)
	if err != nil || path != o.rootIdentity {
		return ErrFixtureCleanup
	}
	return nil
}

func (o *linuxFixtureWorkspaceOperations) openExpectedDirectory(
	name string,
) (*os.File, inputDirectoryIdentity, bool, error) {
	if o == nil || o.root == nil {
		return nil, inputDirectoryIdentity{}, false, ErrFixtureCleanup
	}
	file, identity, uid, gid := o.expectedDirectory(name)
	if file != nil {
		path, err := inputDirectoryIdentityFromAt(int(o.root.Fd()), name)
		if errors.Is(err, unix.ENOENT) {
			empty, emptyErr := linuxDirectoryEmpty(int(file.Fd()))
			if emptyErr != nil || !empty {
				return nil, inputDirectoryIdentity{}, false,
					ErrFixtureUnexpectedObject
			}
			return file, identity, false, nil
		}
		if err != nil || path != identity {
			return nil, inputDirectoryIdentity{}, false,
				ErrFixtureUnexpectedObject
		}
		if err := validateLinuxWorkspaceDirectory(
			int(o.root.Fd()),
			name,
			file,
			identity,
			o.rootIdentity,
			uid,
			gid,
		); err != nil {
			return nil, inputDirectoryIdentity{}, false, err
		}
		return file, identity, true, nil
	}

	childFD, err := unix.Openat2(int(o.root.Fd()), name, &unix.OpenHow{
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
	if errors.Is(err, unix.ENOENT) {
		return nil, inputDirectoryIdentity{}, false, nil
	}
	if err != nil {
		return nil, inputDirectoryIdentity{}, false,
			ErrFixtureUnexpectedObject
	}
	child := os.NewFile(uintptr(childFD), "portable-ghar-workspace-"+name)
	if child == nil {
		_ = unix.Close(childFD)
		return nil, inputDirectoryIdentity{}, false, ErrFixtureCleanup
	}
	identity, err = inputDirectoryIdentityFromFD(childFD)
	if err != nil {
		_ = child.Close()
		return nil, inputDirectoryIdentity{}, false,
			ErrFixtureUnexpectedObject
	}
	if err := validateLinuxWorkspaceDirectory(
		int(o.root.Fd()),
		name,
		child,
		identity,
		o.rootIdentity,
		uid,
		gid,
	); err != nil {
		_ = child.Close()
		return nil, inputDirectoryIdentity{}, false, err
	}
	o.setExpectedDirectory(name, child, identity)
	return child, identity, true, nil
}

func (o *linuxFixtureWorkspaceOperations) expectedDirectory(
	name string,
) (*os.File, inputDirectoryIdentity, uint32, uint32) {
	switch name {
	case linuxWorkspaceStateDirectory:
		return o.state, o.stateIdentity,
			o.rootIdentity.uid, o.rootIdentity.gid
	case linuxWorkspaceRelayDirectory:
		return o.relay, o.relayIdentity, o.brokerUID, o.brokerGID
	case linuxWorkspaceAuthorityDirectory:
		return o.authority, o.authorityIdentity,
			o.brokerUID, o.brokerGID
	default:
		return nil, inputDirectoryIdentity{}, 0, 0
	}
}

func (o *linuxFixtureWorkspaceOperations) setExpectedDirectory(
	name string,
	file *os.File,
	identity inputDirectoryIdentity,
) {
	switch name {
	case linuxWorkspaceStateDirectory:
		o.state = file
		o.stateIdentity = identity
	case linuxWorkspaceRelayDirectory:
		o.relay = file
		o.relayIdentity = identity
	case linuxWorkspaceAuthorityDirectory:
		o.authority = file
		o.authorityIdentity = identity
	}
}

func validateLinuxWorkspaceDirectory(
	rootFD int,
	name string,
	file *os.File,
	expected inputDirectoryIdentity,
	rootIdentity inputDirectoryIdentity,
	uid uint32,
	gid uint32,
) error {
	if file == nil || name == "" || expected.device == 0 ||
		expected.inode == 0 {
		return ErrFixtureUnexpectedObject
	}
	identity, err := inputDirectoryIdentityFromFD(int(file.Fd()))
	if err != nil ||
		identity != expected ||
		identity.device != rootIdentity.device ||
		identity.uid != uid ||
		identity.gid != gid ||
		identity.mode&0o7777 != 0o700 ||
		!localPOSIXDirectory(int(file.Fd()), identity) {
		return ErrFixtureUnexpectedObject
	}
	path, err := inputDirectoryIdentityFromAt(rootFD, name)
	if err != nil || path != expected {
		return ErrFixtureUnexpectedObject
	}
	return nil
}

func linuxWorkspaceDirectoryNames(
	fd int,
	maximum int,
) ([]string, error) {
	if fd < 0 || maximum < 0 {
		return nil, ErrFixtureCleanup
	}
	if _, err := unix.Seek(fd, 0, 0); err != nil {
		return nil, ErrFixtureCleanup
	}
	buffer := make([]byte, 4096)
	defer zeroLeaseBytes(buffer)
	var names []string
	for {
		count, err := unix.ReadDirent(fd, buffer)
		if err != nil {
			return nil, ErrFixtureCleanup
		}
		if count == 0 {
			break
		}
		_, _, parsed := unix.ParseDirent(buffer[:count], -1, nil)
		for _, name := range parsed {
			if name == "." || name == ".." {
				continue
			}
			if len(names) == maximum {
				return nil, ErrFixtureUnexpectedObject
			}
			names = append(names, name)
		}
	}
	if _, err := unix.Seek(fd, 0, 0); err != nil {
		return nil, ErrFixtureCleanup
	}
	return names, nil
}

func scanLinuxWorkspaceState(
	state *os.File,
	stateIdentity inputDirectoryIdentity,
	rootIdentity inputDirectoryIdentity,
) ([]string, error) {
	if state == nil {
		return nil, nil
	}
	names, err := linuxWorkspaceDirectoryNames(int(state.Fd()), 3)
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		switch name {
		case linuxWorkspaceDatabase,
			linuxWorkspaceDatabaseWAL,
			linuxWorkspaceDatabaseSHM:
		default:
			return nil, ErrFixtureUnexpectedObject
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(
			int(state.Fd()),
			name,
			&stat,
			unix.AT_SYMLINK_NOFOLLOW,
		); err != nil ||
			stat.Mode&unix.S_IFMT != unix.S_IFREG ||
			uint64(stat.Dev) != rootIdentity.device ||
			stat.Ino == 0 ||
			stat.Nlink != 1 ||
			stat.Uid != stateIdentity.uid ||
			stat.Gid != stateIdentity.gid ||
			uint32(stat.Mode)&0o022 != 0 {
			return nil, ErrFixtureUnexpectedObject
		}
	}
	return names, nil
}

func requireLinuxWorkspaceDirectoryEmpty(file *os.File) error {
	if file == nil {
		return nil
	}
	names, err := linuxWorkspaceDirectoryNames(int(file.Fd()), 0)
	if err != nil {
		return err
	}
	if len(names) != 0 {
		return ErrFixtureUnexpectedObject
	}
	return nil
}

func linuxWorkspaceNamePresent(names []string, expected string) bool {
	for _, name := range names {
		if name == expected {
			return true
		}
	}
	return false
}

func (o *linuxFixtureWorkspaceOperations) removeExpectedDirectory(
	name string,
	file *os.File,
	identity inputDirectoryIdentity,
	present bool,
) error {
	if file != nil {
		current, err := inputDirectoryIdentityFromFD(int(file.Fd()))
		if err != nil || current != identity {
			return ErrFixtureCleanup
		}
		empty, err := linuxDirectoryEmpty(int(file.Fd()))
		if err != nil {
			return ErrFixtureCleanup
		}
		if !empty {
			return ErrFixtureUnexpectedObject
		}
	}
	path, err := inputDirectoryIdentityFromAt(int(o.root.Fd()), name)
	if !present {
		if !errors.Is(err, unix.ENOENT) {
			return ErrFixtureUnexpectedObject
		}
		return nil
	}
	if err != nil || path != identity {
		return ErrFixtureUnexpectedObject
	}
	if err := unix.Unlinkat(
		int(o.root.Fd()),
		name,
		unix.AT_REMOVEDIR,
	); err != nil {
		if errors.Is(err, unix.ENOTEMPTY) ||
			errors.Is(err, unix.EEXIST) {
			return ErrFixtureUnexpectedObject
		}
		return ErrFixtureCleanup
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(
		int(o.root.Fd()),
		name,
		&stat,
		unix.AT_SYMLINK_NOFOLLOW,
	); !errors.Is(err, unix.ENOENT) {
		return ErrFixtureCleanup
	}
	return nil
}

func normalizeLinuxWorkspaceRemovalError(err error) error {
	if errors.Is(err, ErrFixtureUnexpectedObject) {
		return ErrFixtureUnexpectedObject
	}
	return ErrFixtureCleanup
}
