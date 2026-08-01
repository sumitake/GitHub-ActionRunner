//go:build integration && linux

package testenv

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

type linuxTask11SyntheticCycleRoot struct {
	mu sync.Mutex

	primary         *os.File
	root            *os.File
	primaryIdentity inputDirectoryIdentity
	rootIdentity    inputDirectoryIdentity
	path            string
	basename        string
	removed         bool
	closed          bool
}

func createLinuxTask11SyntheticCycleRoot(
	primary FixtureBinding,
	cycle task11SyntheticCycleIdentity,
) (*linuxTask11SyntheticCycleRoot, FixtureBinding, error) {
	if !validAbsolutePath(primary.Root) ||
		filepath.Dir(cycle.Root) != primary.Root ||
		filepath.Base(cycle.Root) != cycle.Composition.SlotIdentity ||
		cycle.Root == primary.Root ||
		primary.ExecutionOwnerUID == 0 &&
			os.Geteuid() != 0 {
		return nil, FixtureBinding{}, ErrFixtureStart
	}
	rootFD, err := unix.Open(
		string(filepath.Separator),
		unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, FixtureBinding{}, ErrFixtureStart
	}
	defer unix.Close(rootFD)
	relative := strings.TrimPrefix(
		primary.Root,
		string(filepath.Separator),
	)
	primaryFD, err := unix.Openat2(rootFD, relative, &unix.OpenHow{
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
		return nil, FixtureBinding{}, ErrFixtureStart
	}
	primaryFile := os.NewFile(
		uintptr(primaryFD),
		"portable-ghar-task11-primary-root",
	)
	if primaryFile == nil {
		_ = unix.Close(primaryFD)
		return nil, FixtureBinding{}, ErrFixtureStart
	}
	closePrimary := true
	defer func() {
		if closePrimary {
			_ = primaryFile.Close()
		}
	}()
	primaryIdentity, err := inputDirectoryIdentityFromFD(primaryFD)
	if err != nil ||
		primaryIdentity.uid != primary.ExecutionOwnerUID ||
		primaryIdentity.mode&0o7777 != 0o700 ||
		!localPOSIXDirectory(primaryFD, primaryIdentity) {
		return nil, FixtureBinding{}, ErrFixtureStart
	}
	basename := cycle.Composition.SlotIdentity
	if err := unix.Mkdirat(primaryFD, basename, 0o700); err != nil {
		return nil, FixtureBinding{}, ErrFixtureStart
	}
	created := true
	defer func() {
		if created {
			_ = unix.Unlinkat(primaryFD, basename, unix.AT_REMOVEDIR)
			_ = unix.Fsync(primaryFD)
		}
	}()
	if err := unix.Fsync(primaryFD); err != nil {
		return nil, FixtureBinding{}, ErrFixtureStart
	}
	cycleFD, err := unix.Openat2(primaryFD, basename, &unix.OpenHow{
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
		return nil, FixtureBinding{}, ErrFixtureStart
	}
	cycleFile := os.NewFile(
		uintptr(cycleFD),
		"portable-ghar-task11-cycle-root",
	)
	if cycleFile == nil {
		_ = unix.Close(cycleFD)
		return nil, FixtureBinding{}, ErrFixtureStart
	}
	closeCycle := true
	defer func() {
		if closeCycle {
			_ = cycleFile.Close()
		}
	}()
	cycleIdentity, err := inputDirectoryIdentityFromFD(cycleFD)
	if err != nil ||
		cycleIdentity.device != primaryIdentity.device ||
		cycleIdentity.uid != primary.ExecutionOwnerUID ||
		cycleIdentity.mode&0o7777 != 0o700 ||
		!localPOSIXDirectory(cycleFD, cycleIdentity) {
		return nil, FixtureBinding{}, ErrFixtureStart
	}
	pathIdentity, err := inputDirectoryIdentityFromAt(primaryFD, basename)
	empty, emptyErr := linuxDirectoryEmpty(cycleFD)
	if err != nil || pathIdentity != cycleIdentity ||
		emptyErr != nil || !empty {
		return nil, FixtureBinding{}, ErrFixtureStart
	}
	observation := fixtureRootObservation{
		SchemaVersion:  1,
		ParentDevice:   primaryIdentity.device,
		ParentInode:    primaryIdentity.inode,
		ParentOwnerUID: primaryIdentity.uid,
		ParentMode:     primaryIdentity.mode & 0o7777,
		RootDevice:     cycleIdentity.device,
		RootInode:      cycleIdentity.inode,
		OwnerUID:       cycleIdentity.uid,
		Mode:           cycleIdentity.mode & 0o7777,
	}
	digest, err := computeFixtureEmptyDigest(observation)
	if err != nil {
		return nil, FixtureBinding{}, ErrFixtureStart
	}
	binding := FixtureBinding{
		Root:                         cycle.Root,
		ParentDevice:                 primaryIdentity.device,
		ParentInode:                  primaryIdentity.inode,
		RequiredEmptyDigest:          digest,
		ExecutionOwnerUID:            primary.ExecutionOwnerUID,
		ExecutionOwnerIdentityDigest: primary.ExecutionOwnerIdentityDigest,
	}
	lease := &linuxTask11SyntheticCycleRoot{
		primary:         primaryFile,
		root:            cycleFile,
		primaryIdentity: primaryIdentity,
		rootIdentity:    cycleIdentity,
		path:            cycle.Root,
		basename:        basename,
	}
	closePrimary = false
	closeCycle = false
	created = false
	return lease, binding, nil
}

func (r *linuxTask11SyntheticCycleRoot) snapshotEntries() (
	[]string,
	error,
) {
	if r == nil {
		return nil, ErrFixtureStart
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.removed || r.root == nil || r.primary == nil {
		return nil, ErrFixtureStart
	}
	if !r.identityStableLocked() {
		return nil, ErrFixtureStart
	}
	entries, err := r.root.ReadDir(-1)
	if err != nil {
		return nil, ErrFixtureStart
	}
	if _, err := r.root.Seek(0, 0); err != nil {
		return nil, ErrFixtureStart
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Name() == "" ||
			strings.ContainsRune(entry.Name(), filepath.Separator) ||
			entry.Type()&os.ModeSymlink != 0 {
			return nil, ErrFixtureStart
		}
		names = append(names, entry.Name())
	}
	return names, nil
}

func (r *linuxTask11SyntheticCycleRoot) prepareBrokerDirectories() error {
	if r == nil {
		return ErrFixtureStart
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.removed || r.root == nil || r.primary == nil ||
		!r.identityStableLocked() {
		return ErrFixtureStart
	}
	empty, err := linuxDirectoryEmpty(int(r.root.Fd()))
	if err != nil || !empty {
		return ErrFixtureUnexpectedObject
	}
	created := make([]string, 0, 2)
	rollback := func() error {
		ok := true
		for index := len(created) - 1; index >= 0; index-- {
			if err := unix.Unlinkat(
				int(r.root.Fd()),
				created[index],
				unix.AT_REMOVEDIR,
			); err != nil {
				ok = false
			}
		}
		if err := unix.Fsync(int(r.root.Fd())); err != nil {
			ok = false
		}
		if !ok {
			return ErrFixtureCleanup
		}
		return ErrFixtureStart
	}
	for _, name := range []string{"authority", "relay"} {
		if err := unix.Mkdirat(
			int(r.root.Fd()),
			name,
			0o700,
		); err != nil {
			return rollback()
		}
		created = append(created, name)
		identity, err := inputDirectoryIdentityFromAt(
			int(r.root.Fd()),
			name,
		)
		if err != nil ||
			identity.device != r.rootIdentity.device ||
			identity.uid != r.rootIdentity.uid ||
			identity.gid != r.rootIdentity.gid ||
			identity.mode&0o7777 != 0o700 {
			return rollback()
		}
	}
	if err := unix.Fsync(int(r.root.Fd())); err != nil {
		return rollback()
	}
	entries, err := r.root.ReadDir(-1)
	if err != nil {
		return rollback()
	}
	if _, err := r.root.Seek(0, 0); err != nil {
		return rollback()
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	if len(names) != 2 ||
		names[0] != "authority" ||
		names[1] != "relay" {
		return rollback()
	}
	return nil
}

func (r *linuxTask11SyntheticCycleRoot) removeEmpty() error {
	if r == nil {
		return ErrFixtureCleanup
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		if r.removed {
			return nil
		}
		return ErrFixtureCleanup
	}
	if r.removed {
		return nil
	}
	if !r.identityStableLocked() {
		return ErrFixtureCleanup
	}
	entries, err := r.root.ReadDir(-1)
	if err != nil {
		return ErrFixtureCleanup
	}
	if _, err := r.root.Seek(0, 0); err != nil {
		return ErrFixtureCleanup
	}
	for _, entry := range entries {
		name := entry.Name()
		if name != "authority" && name != "relay" {
			return ErrFixtureUnexpectedObject
		}
		if err := r.requireEmptyChildLocked(name); err != nil {
			return err
		}
	}
	for _, entry := range entries {
		name := entry.Name()
		if err := unix.Unlinkat(
			int(r.root.Fd()),
			name,
			unix.AT_REMOVEDIR,
		); err != nil {
			if errors.Is(err, unix.ENOTEMPTY) ||
				errors.Is(err, unix.EEXIST) ||
				errors.Is(err, unix.ENOTDIR) {
				return ErrFixtureUnexpectedObject
			}
			return ErrFixtureCleanup
		}
	}
	if len(entries) != 0 {
		if err := unix.Fsync(int(r.root.Fd())); err != nil {
			return ErrFixtureCleanup
		}
	}
	empty, err := linuxDirectoryEmpty(int(r.root.Fd()))
	if err != nil || !empty {
		if err == nil {
			return ErrFixtureUnexpectedObject
		}
		return ErrFixtureCleanup
	}
	if err := unix.Unlinkat(
		int(r.primary.Fd()),
		r.basename,
		unix.AT_REMOVEDIR,
	); err != nil {
		if errors.Is(err, unix.ENOTEMPTY) ||
			errors.Is(err, unix.EEXIST) {
			return ErrFixtureUnexpectedObject
		}
		return ErrFixtureCleanup
	}
	if err := unix.Fsync(int(r.primary.Fd())); err != nil {
		return ErrFixtureCleanup
	}
	if _, err := inputDirectoryIdentityFromAt(
		int(r.primary.Fd()),
		r.basename,
	); !errors.Is(err, os.ErrNotExist) {
		return ErrFixtureCleanup
	}
	r.removed = true
	if err := r.root.Close(); err != nil {
		return ErrFixtureCleanup
	}
	r.root = nil
	if err := r.primary.Close(); err != nil {
		return ErrFixtureCleanup
	}
	r.primary = nil
	r.closed = true
	return nil
}

func (r *linuxTask11SyntheticCycleRoot) requireEmptyChildLocked(
	name string,
) error {
	if r == nil || r.root == nil ||
		(name != "authority" && name != "relay") {
		return ErrFixtureUnexpectedObject
	}
	identity, err := inputDirectoryIdentityFromAt(
		int(r.root.Fd()),
		name,
	)
	if err != nil ||
		identity.device != r.rootIdentity.device ||
		identity.uid != r.rootIdentity.uid ||
		identity.gid != r.rootIdentity.gid ||
		identity.mode&0o7777 != 0o700 {
		return ErrFixtureUnexpectedObject
	}
	childFD, err := unix.Openat2(
		int(r.root.Fd()),
		name,
		&unix.OpenHow{
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
		},
	)
	if err != nil {
		return ErrFixtureUnexpectedObject
	}
	defer unix.Close(childFD)
	opened, err := inputDirectoryIdentityFromFD(childFD)
	if err != nil || opened != identity {
		return ErrFixtureUnexpectedObject
	}
	empty, err := linuxDirectoryEmpty(childFD)
	if err != nil {
		return ErrFixtureCleanup
	}
	if !empty {
		return ErrFixtureUnexpectedObject
	}
	return nil
}

func (r *linuxTask11SyntheticCycleRoot) close() error {
	if r == nil {
		return ErrFixtureCleanup
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	var failed bool
	if r.root != nil && r.root.Close() != nil {
		failed = true
	}
	if r.primary != nil && r.primary.Close() != nil {
		failed = true
	}
	r.root = nil
	r.primary = nil
	r.closed = true
	if failed {
		return ErrFixtureCleanup
	}
	return nil
}

func (r *linuxTask11SyntheticCycleRoot) identityStableLocked() bool {
	if r == nil || r.primary == nil || r.root == nil ||
		r.basename == "" {
		return false
	}
	primary, err := inputDirectoryIdentityFromFD(int(r.primary.Fd()))
	if err != nil || primary != r.primaryIdentity {
		return false
	}
	root, err := inputDirectoryIdentityFromFD(int(r.root.Fd()))
	if err != nil || root != r.rootIdentity {
		return false
	}
	path, err := inputDirectoryIdentityFromAt(
		int(r.primary.Fd()),
		r.basename,
	)
	return err == nil && path == r.rootIdentity
}
