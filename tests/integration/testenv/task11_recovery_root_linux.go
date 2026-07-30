//go:build integration && linux

package testenv

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	task11RecoveryRootDomain = "portable-ghar.task11.recovery-root.v1\x00"
	task11RecoveryFenceDir   = "fence"
)

var task11RecoveryRootFiles = [...]string{
	linuxWorkspaceDatabase,
	linuxWorkspaceDatabaseWAL,
	linuxWorkspaceDatabaseSHM,
}

var task11RecoveryFenceFiles = [...]string{
	"fleet.json",
	"fleet.lock",
	"holders",
}

func deriveTask11RecoveryCycleIdentity(
	primary FixtureBinding,
	runDigest string,
) (task11SyntheticCycleIdentity, error) {
	if !validAbsolutePath(primary.Root) ||
		!isLowerHex(runDigest, sha256.Size*2) {
		return task11SyntheticCycleIdentity{}, ErrFixtureStart
	}
	raw, err := hex.DecodeString(runDigest)
	if err != nil || len(raw) != sha256.Size {
		return task11SyntheticCycleIdentity{}, ErrFixtureStart
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(task11RecoveryRootDomain))
	_, _ = digest.Write(raw)
	recoveryRun := hex.EncodeToString(digest.Sum(nil))
	composition, err := deriveCompositionIdentity(recoveryRun)
	if err != nil || composition.SlotIdentity == "" {
		return task11SyntheticCycleIdentity{}, ErrFixtureStart
	}
	root := filepath.Join(primary.Root, composition.SlotIdentity)
	if !validAbsolutePath(root) ||
		filepath.Dir(root) != primary.Root ||
		filepath.Base(root) != composition.SlotIdentity {
		return task11SyntheticCycleIdentity{}, ErrFixtureStart
	}
	return task11SyntheticCycleIdentity{
		RunDigest:   recoveryRun,
		Composition: composition,
		Root:        root,
	}, nil
}

func (r *linuxTask11SyntheticCycleRoot) prepareRecoveryState() (
	string,
	string,
	error,
) {
	if r == nil {
		return "", "", ErrFixtureStart
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.removed || r.root == nil || r.primary == nil ||
		!r.identityStableLocked() {
		return "", "", ErrFixtureStart
	}
	empty, err := linuxDirectoryEmpty(int(r.root.Fd()))
	if err != nil || !empty {
		return "", "", ErrFixtureUnexpectedObject
	}
	if err := unix.Mkdirat(
		int(r.root.Fd()),
		task11RecoveryFenceDir,
		0o700,
	); err != nil {
		return "", "", ErrFixtureStart
	}
	created := true
	defer func() {
		if created {
			_ = unix.Unlinkat(
				int(r.root.Fd()),
				task11RecoveryFenceDir,
				unix.AT_REMOVEDIR,
			)
			_ = unix.Fsync(int(r.root.Fd()))
		}
	}()
	if err := unix.Fsync(int(r.root.Fd())); err != nil {
		return "", "", ErrFixtureStart
	}
	identity, err := inputDirectoryIdentityFromAt(
		int(r.root.Fd()),
		task11RecoveryFenceDir,
	)
	if err != nil ||
		identity.device != r.rootIdentity.device ||
		identity.uid != r.rootIdentity.uid ||
		identity.gid != r.rootIdentity.gid ||
		identity.mode&0o7777 != 0o700 {
		return "", "", ErrFixtureStart
	}
	databasePath := filepath.Join(r.path, linuxWorkspaceDatabase)
	fencePath := filepath.Join(r.path, task11RecoveryFenceDir)
	if !validAbsolutePath(databasePath) || !validAbsolutePath(fencePath) {
		return "", "", ErrFixtureStart
	}
	created = false
	return databasePath, fencePath, nil
}

func (r *linuxTask11SyntheticCycleRoot) removeRecoveryState() error {
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
	names, err := task11ReadDirectoryNames(r.root)
	if err != nil {
		return ErrFixtureCleanup
	}
	for _, name := range names {
		if name != task11RecoveryFenceDir &&
			!task11StringIn(name, task11RecoveryRootFiles[:]) {
			return ErrFixtureUnexpectedObject
		}
	}
	for _, name := range task11RecoveryRootFiles {
		if !task11StringIn(name, names) {
			continue
		}
		if err := r.requireRecoveryRegularLocked(
			int(r.root.Fd()),
			name,
		); err != nil {
			return err
		}
	}
	if task11StringIn(task11RecoveryFenceDir, names) {
		if err := r.requireRecoveryFenceLocked(); err != nil {
			return err
		}
	}

	if task11StringIn(task11RecoveryFenceDir, names) {
		if err := r.removeRecoveryFenceLocked(); err != nil {
			return err
		}
	}
	for _, name := range task11RecoveryRootFiles {
		if !task11StringIn(name, names) {
			continue
		}
		if err := unix.Unlinkat(int(r.root.Fd()), name, 0); err != nil {
			return ErrFixtureCleanup
		}
	}
	if err := unix.Fsync(int(r.root.Fd())); err != nil {
		return ErrFixtureCleanup
	}
	empty, err := linuxDirectoryEmpty(int(r.root.Fd()))
	if err != nil || !empty {
		if err == nil {
			return ErrFixtureUnexpectedObject
		}
		return ErrFixtureCleanup
	}
	return r.removeRootLocked()
}

func (r *linuxTask11SyntheticCycleRoot) requireRecoveryFenceLocked() error {
	fenceFD, identity, err := r.openRecoveryFenceLocked()
	if err != nil {
		return err
	}
	defer unix.Close(fenceFD)
	names, err := linuxWorkspaceDirectoryNames(fenceFD, 3)
	if err != nil {
		return ErrFixtureCleanup
	}
	for _, name := range names {
		if !task11StringIn(name, task11RecoveryFenceFiles[:]) {
			return ErrFixtureUnexpectedObject
		}
	}
	for _, name := range []string{"fleet.json", "fleet.lock"} {
		if task11StringIn(name, names) {
			if err := r.requireRecoveryRegularLocked(
				fenceFD,
				name,
			); err != nil {
				return err
			}
		}
	}
	if task11StringIn("holders", names) {
		holderIdentity, err := inputDirectoryIdentityFromAt(
			fenceFD,
			"holders",
		)
		if err != nil ||
			holderIdentity.device != identity.device ||
			holderIdentity.uid != identity.uid ||
			holderIdentity.gid != identity.gid ||
			holderIdentity.mode&0o7777 != 0o700 {
			return ErrFixtureUnexpectedObject
		}
		holderFD, err := unix.Openat2(fenceFD, "holders", &unix.OpenHow{
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
			return ErrFixtureUnexpectedObject
		}
		defer unix.Close(holderFD)
		opened, err := inputDirectoryIdentityFromFD(holderFD)
		empty, emptyErr := linuxDirectoryEmpty(holderFD)
		if err != nil || opened != holderIdentity ||
			emptyErr != nil || !empty {
			return ErrFixtureUnexpectedObject
		}
	}
	return nil
}

func (r *linuxTask11SyntheticCycleRoot) removeRecoveryFenceLocked() error {
	fenceFD, _, err := r.openRecoveryFenceLocked()
	if err != nil {
		return err
	}
	names, err := linuxWorkspaceDirectoryNames(fenceFD, 3)
	if err != nil {
		_ = unix.Close(fenceFD)
		return ErrFixtureCleanup
	}
	for _, name := range []string{"fleet.json", "fleet.lock"} {
		if task11StringIn(name, names) {
			if err := unix.Unlinkat(fenceFD, name, 0); err != nil {
				_ = unix.Close(fenceFD)
				return ErrFixtureCleanup
			}
		}
	}
	if task11StringIn("holders", names) {
		if err := unix.Unlinkat(
			fenceFD,
			"holders",
			unix.AT_REMOVEDIR,
		); err != nil {
			_ = unix.Close(fenceFD)
			return ErrFixtureCleanup
		}
	}
	if err := unix.Fsync(fenceFD); err != nil {
		_ = unix.Close(fenceFD)
		return ErrFixtureCleanup
	}
	if err := unix.Close(fenceFD); err != nil {
		return ErrFixtureCleanup
	}
	if err := unix.Unlinkat(
		int(r.root.Fd()),
		task11RecoveryFenceDir,
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

func (r *linuxTask11SyntheticCycleRoot) openRecoveryFenceLocked() (
	int,
	inputDirectoryIdentity,
	error,
) {
	identity, err := inputDirectoryIdentityFromAt(
		int(r.root.Fd()),
		task11RecoveryFenceDir,
	)
	if err != nil ||
		identity.device != r.rootIdentity.device ||
		identity.uid != r.rootIdentity.uid ||
		identity.gid != r.rootIdentity.gid ||
		identity.mode&0o7777 != 0o700 {
		return -1, inputDirectoryIdentity{}, ErrFixtureUnexpectedObject
	}
	fd, err := unix.Openat2(
		int(r.root.Fd()),
		task11RecoveryFenceDir,
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
		return -1, inputDirectoryIdentity{}, ErrFixtureUnexpectedObject
	}
	opened, err := inputDirectoryIdentityFromFD(fd)
	if err != nil || opened != identity {
		_ = unix.Close(fd)
		return -1, inputDirectoryIdentity{}, ErrFixtureUnexpectedObject
	}
	return fd, identity, nil
}

func (r *linuxTask11SyntheticCycleRoot) requireRecoveryRegularLocked(
	parentFD int,
	name string,
) error {
	identity, err := inputIdentityFromAt(parentFD, name)
	if err != nil ||
		identity.device != r.rootIdentity.device ||
		identity.uid != r.rootIdentity.uid ||
		identity.nlink != 1 ||
		identity.mode&unix.S_IFMT != unix.S_IFREG {
		return ErrFixtureUnexpectedObject
	}
	return nil
}

func (r *linuxTask11SyntheticCycleRoot) removeRootLocked() error {
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

func task11ReadDirectoryNames(file *os.File) ([]string, error) {
	if file == nil {
		return nil, ErrFixtureCleanup
	}
	entries, err := file.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	if _, err := file.Seek(0, 0); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if name == "" ||
			strings.ContainsRune(name, filepath.Separator) ||
			entry.Type()&os.ModeSymlink != 0 {
			return nil, ErrFixtureUnexpectedObject
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func task11StringIn(value string, values []string) bool {
	for _, candidate := range values {
		if value == candidate {
			return true
		}
	}
	return false
}
