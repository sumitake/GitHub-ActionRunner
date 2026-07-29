//go:build darwin || linux

package hostruntime

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type lifecycleFileIdentity struct {
	device uint64
	inode  uint64
	mode   uint32
	uid    uint32
	nlink  uint64
	size   int64
}

type lifecycleDirectoryHandle struct {
	fd       int
	path     string
	identity lifecycleFileIdentity
}

type LifecycleStore struct {
	state *lifecycleStoreState
}

type lifecycleStoreState struct {
	mu           sync.RWMutex
	rootPath     string
	rootFD       int
	rootIdentity lifecycleFileIdentity
	directories  map[LifecycleDirectory]lifecycleDirectoryHandle
	lockFD       int
	lockIdentity lifecycleFileIdentity
	closed       bool
}

type LifecycleLease struct {
	mu       sync.Mutex
	fd       int
	identity lifecycleFileIdentity
	store    *LifecycleStore
	closed   bool
}

func OpenLifecycleStore(root string, bootstrap bool) (*LifecycleStore, error) {
	if !validLifecycleRootPath(root) {
		return nil, ErrLifecycleIntegrity
	}
	rootFD, rootIdentity, err := openLifecycleAbsoluteDirectory(root)
	if err != nil {
		return nil, err
	}
	state := &lifecycleStoreState{
		rootPath:     root,
		rootFD:       rootFD,
		rootIdentity: rootIdentity,
		directories:  make(map[LifecycleDirectory]lifecycleDirectoryHandle, 3),
		lockFD:       -1,
	}
	cleanup := func() {
		for _, handle := range state.directories {
			_ = unix.Close(handle.fd)
		}
		if state.lockFD >= 0 {
			_ = unix.Close(state.lockFD)
		}
		_ = unix.Close(rootFD)
	}
	for _, directory := range []LifecycleDirectory{
		LifecycleJournals,
		LifecycleReceipts,
		LifecycleReservations,
	} {
		handle, openErr := openLifecycleDirectory(rootFD, directory, bootstrap)
		if openErr != nil {
			cleanup()
			return nil, openErr
		}
		handle.path = filepath.Join(root, string(directory))
		state.directories[directory] = handle
	}
	lockFD, lockIdentity, err := openLifecycleLock(rootFD, bootstrap)
	if err != nil {
		cleanup()
		return nil, err
	}
	state.lockFD = lockFD
	state.lockIdentity = lockIdentity
	store := &LifecycleStore{state: state}
	state.mu.RLock()
	err = store.verifyStateLocked()
	state.mu.RUnlock()
	if err != nil {
		cleanup()
		return nil, err
	}
	return store, nil
}

// OpenLifecycleStoreLayout opens the exact private-overlay roots. The roots
// themselves must already exist as private directories. bootstrap controls
// only creation of the stable lock file in LockRoot.
func OpenLifecycleStoreLayout(
	layout LifecycleStoreLayout,
	bootstrap bool,
) (*LifecycleStore, error) {
	if !validLifecycleStoreLayout(layout) {
		return nil, ErrLifecycleIntegrity
	}
	rootFD, rootIdentity, err := openLifecycleAbsoluteDirectory(layout.LockRoot)
	if err != nil {
		return nil, err
	}
	state := &lifecycleStoreState{
		rootPath:     layout.LockRoot,
		rootFD:       rootFD,
		rootIdentity: rootIdentity,
		directories:  make(map[LifecycleDirectory]lifecycleDirectoryHandle, 3),
		lockFD:       -1,
	}
	cleanup := func() {
		for _, handle := range state.directories {
			_ = unix.Close(handle.fd)
		}
		if state.lockFD >= 0 {
			_ = unix.Close(state.lockFD)
		}
		_ = unix.Close(rootFD)
	}
	identities := map[string]struct{}{
		lifecycleDirectoryIdentityKey(rootIdentity): {},
	}
	for _, directory := range []LifecycleDirectory{
		LifecycleJournals,
		LifecycleReceipts,
		LifecycleReservations,
	} {
		path, ok := lifecycleLayoutPath(layout, directory)
		if !ok {
			cleanup()
			return nil, ErrLifecycleIntegrity
		}
		fd, identity, openErr := openLifecycleAbsoluteDirectory(path)
		if openErr != nil {
			cleanup()
			return nil, openErr
		}
		key := lifecycleDirectoryIdentityKey(identity)
		if _, exists := identities[key]; exists {
			_ = unix.Close(fd)
			cleanup()
			return nil, ErrLifecycleIntegrity
		}
		identities[key] = struct{}{}
		state.directories[directory] = lifecycleDirectoryHandle{
			fd:       fd,
			path:     path,
			identity: identity,
		}
	}
	lockFD, lockIdentity, err := openLifecycleLock(rootFD, bootstrap)
	if err != nil {
		cleanup()
		return nil, err
	}
	state.lockFD = lockFD
	state.lockIdentity = lockIdentity
	store := &LifecycleStore{state: state}
	state.mu.RLock()
	err = store.verifyStateLocked()
	state.mu.RUnlock()
	if err != nil {
		cleanup()
		return nil, err
	}
	return store, nil
}

func (store *LifecycleStore) Close() error {
	if store == nil || store.state == nil {
		return nil
	}
	state := store.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed {
		return nil
	}
	state.closed = true
	var result error
	for _, directory := range []LifecycleDirectory{
		LifecycleJournals,
		LifecycleReceipts,
		LifecycleReservations,
	} {
		handle := state.directories[directory]
		if handle.fd >= 0 {
			if err := unix.Close(handle.fd); err != nil && result == nil {
				result = ErrLifecycleIntegrity
			}
		}
	}
	if state.lockFD >= 0 {
		if err := unix.Close(state.lockFD); err != nil && result == nil {
			result = ErrLifecycleIntegrity
		}
	}
	if state.rootFD >= 0 {
		if err := unix.Close(state.rootFD); err != nil && result == nil {
			result = ErrLifecycleIntegrity
		}
	}
	return result
}

func (store *LifecycleStore) ReadCanonical(
	directory LifecycleDirectory,
	name string,
	maxBytes int,
) ([]byte, error) {
	if !validLifecycleDocumentRequest(directory, name, maxBytes, nil, false) {
		return nil, ErrLifecycleIntegrity
	}
	state, err := store.lockState()
	if err != nil {
		return nil, err
	}
	defer state.mu.RUnlock()
	if err := store.verifyStateLocked(); err != nil {
		return nil, err
	}
	document, _, err := readLifecycleDocument(
		state.directories[directory].fd,
		name,
		maxBytes,
	)
	return document, err
}

func (store *LifecycleStore) CreateCanonical(
	directory LifecycleDirectory,
	name string,
	document []byte,
	maxBytes int,
) error {
	if !validLifecycleDocumentRequest(directory, name, maxBytes, document, true) {
		return ErrLifecycleIntegrity
	}
	state, err := store.lockState()
	if err != nil {
		return err
	}
	defer state.mu.RUnlock()
	if err := store.verifyStateLocked(); err != nil {
		return err
	}
	dirFD := state.directories[directory].fd
	if _, err := lifecyclePathIdentity(dirFD, name, unix.S_IFREG, 0o600, true); err == nil {
		return ErrLifecycleStateExists
	} else if !errors.Is(err, ErrLifecycleStateAbsent) {
		return err
	}
	temp, err := writeLifecycleTemp(dirFD, document)
	if err != nil {
		return err
	}
	tempPresent := true
	defer func() {
		if tempPresent {
			_ = unix.Unlinkat(dirFD, temp, 0)
		}
	}()
	if err := unix.Linkat(dirFD, temp, dirFD, name, 0); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return ErrLifecycleStateExists
		}
		return ErrLifecycleIntegrity
	}
	if err := unix.Unlinkat(dirFD, temp, 0); err != nil {
		return ErrLifecycleIntegrity
	}
	tempPresent = false
	if err := unix.Fsync(dirFD); err != nil {
		return ErrLifecycleIntegrity
	}
	readback, _, err := readLifecycleDocument(dirFD, name, maxBytes)
	if err != nil || !bytes.Equal(readback, document) {
		return ErrLifecycleIntegrity
	}
	return store.verifyStateLocked()
}

func (store *LifecycleStore) ReplaceCanonical(
	directory LifecycleDirectory,
	name string,
	expected []byte,
	replacement []byte,
	maxBytes int,
) error {
	if !validLifecycleDocumentRequest(directory, name, maxBytes, expected, true) ||
		!validLifecycleDocumentRequest(directory, name, maxBytes, replacement, true) {
		return ErrLifecycleIntegrity
	}
	state, err := store.lockState()
	if err != nil {
		return err
	}
	defer state.mu.RUnlock()
	if err := store.verifyStateLocked(); err != nil {
		return err
	}
	dirFD := state.directories[directory].fd
	current, identity, err := readLifecycleDocument(dirFD, name, maxBytes)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, expected) {
		return ErrLifecycleStateConflict
	}
	temp, err := writeLifecycleTemp(dirFD, replacement)
	if err != nil {
		return err
	}
	tempPresent := true
	defer func() {
		if tempPresent {
			_ = unix.Unlinkat(dirFD, temp, 0)
		}
	}()
	pathIdentity, err := lifecyclePathIdentity(
		dirFD,
		name,
		unix.S_IFREG,
		0o600,
		true,
	)
	if err != nil || pathIdentity != identity {
		return ErrLifecycleStateConflict
	}
	if err := unix.Renameat(dirFD, temp, dirFD, name); err != nil {
		return ErrLifecycleIntegrity
	}
	tempPresent = false
	if err := unix.Fsync(dirFD); err != nil {
		return ErrLifecycleIntegrity
	}
	readback, _, err := readLifecycleDocument(dirFD, name, maxBytes)
	if err != nil || !bytes.Equal(readback, replacement) {
		return ErrLifecycleIntegrity
	}
	return store.verifyStateLocked()
}

func (store *LifecycleStore) RemoveCanonical(
	directory LifecycleDirectory,
	name string,
	expected []byte,
	maxBytes int,
) error {
	if !validLifecycleDocumentRequest(directory, name, maxBytes, expected, true) {
		return ErrLifecycleIntegrity
	}
	state, err := store.lockState()
	if err != nil {
		return err
	}
	defer state.mu.RUnlock()
	if err := store.verifyStateLocked(); err != nil {
		return err
	}
	dirFD := state.directories[directory].fd
	current, identity, err := readLifecycleDocument(dirFD, name, maxBytes)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, expected) {
		return ErrLifecycleStateConflict
	}
	pathIdentity, err := lifecyclePathIdentity(
		dirFD,
		name,
		unix.S_IFREG,
		0o600,
		true,
	)
	if err != nil || pathIdentity != identity {
		return ErrLifecycleStateConflict
	}
	if err := unix.Unlinkat(dirFD, name, 0); err != nil {
		return ErrLifecycleIntegrity
	}
	if err := unix.Fsync(dirFD); err != nil {
		return ErrLifecycleIntegrity
	}
	if _, err := lifecyclePathIdentity(
		dirFD,
		name,
		unix.S_IFREG,
		0o600,
		true,
	); !errors.Is(err, ErrLifecycleStateAbsent) {
		return ErrLifecycleIntegrity
	}
	return store.verifyStateLocked()
}

// ListCanonicalNames returns the complete, sorted regular-file inventory of a
// pinned lifecycle directory. Unexpected entries are integrity failures; a
// watchdog must never skip an unknown journal or reservation.
func (store *LifecycleStore) ListCanonicalNames(
	directory LifecycleDirectory,
) ([]string, error) {
	if !validLifecycleDirectory(directory) {
		return nil, ErrLifecycleIntegrity
	}
	state, err := store.lockState()
	if err != nil {
		return nil, err
	}
	defer state.mu.RUnlock()
	if err := store.verifyStateLocked(); err != nil {
		return nil, err
	}
	handle := state.directories[directory]
	duplicate, err := unix.Dup(handle.fd)
	if err != nil {
		return nil, ErrLifecycleIntegrity
	}
	if _, err := unix.Seek(duplicate, 0, 0); err != nil {
		_ = unix.Close(duplicate)
		return nil, ErrLifecycleIntegrity
	}
	file := os.NewFile(uintptr(duplicate), "portable-ghar-lifecycle-directory")
	if file == nil {
		_ = unix.Close(duplicate)
		return nil, ErrLifecycleIntegrity
	}
	entries, readErr := file.ReadDir(-1)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, ErrLifecycleIntegrity
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !validLifecycleLeafName(name) ||
			strings.HasPrefix(name, ".tmp-") {
			return nil, ErrLifecycleIntegrity
		}
		if _, err := lifecyclePathIdentity(
			handle.fd,
			name,
			unix.S_IFREG,
			0o600,
			true,
		); err != nil {
			return nil, ErrLifecycleIntegrity
		}
		names = append(names, name)
	}
	sort.Strings(names)
	if err := store.verifyStateLocked(); err != nil {
		return nil, err
	}
	return names, nil
}

func (store *LifecycleStore) Acquire(
	ctx context.Context,
	pollInterval time.Duration,
) (*LifecycleLease, error) {
	if ctx == nil || pollInterval <= 0 || pollInterval > time.Second {
		return nil, ErrLifecycleIntegrity
	}
	state, err := store.lockState()
	if err != nil {
		return nil, err
	}
	defer state.mu.RUnlock()
	if err := store.verifyStateLocked(); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(
		state.rootFD,
		lifecycleLockName,
		unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, ErrLifecycleIntegrity
	}
	identity, err := lifecycleIdentity(fd, unix.S_IFREG, 0o600, true)
	if err != nil || !samePinnedRegularIdentity(identity, state.lockIdentity) {
		_ = unix.Close(fd)
		return nil, ErrLifecycleIntegrity
	}
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		switch {
		case err == nil:
			if verifyErr := store.verifyStateLocked(); verifyErr != nil {
				_ = unix.Flock(fd, unix.LOCK_UN)
				_ = unix.Close(fd)
				return nil, verifyErr
			}
			return &LifecycleLease{
				fd:       fd,
				identity: identity,
				store:    store,
			}, nil
		case errors.Is(err, unix.EWOULDBLOCK), errors.Is(err, unix.EAGAIN):
		default:
			_ = unix.Close(fd)
			return nil, ErrLifecycleIntegrity
		}
		timer := time.NewTimer(pollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			_ = unix.Close(fd)
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func (lease *LifecycleLease) Validate() error {
	if lease == nil {
		return ErrLifecycleIntegrity
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed || lease.fd < 0 {
		return ErrLifecycleStoreClosed
	}
	identity, err := lifecycleIdentity(
		lease.fd,
		unix.S_IFREG,
		0o600,
		true,
	)
	if err != nil || !samePinnedRegularIdentity(identity, lease.identity) {
		return ErrLifecycleIntegrity
	}
	if lease.store == nil {
		return ErrLifecycleIntegrity
	}
	state, err := lease.store.lockState()
	if err != nil {
		return err
	}
	defer state.mu.RUnlock()
	return lease.store.verifyStateLocked()
}

func (lease *LifecycleLease) Close() error {
	if lease == nil {
		return nil
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return nil
	}
	lease.closed = true
	var result error
	if err := unix.Flock(lease.fd, unix.LOCK_UN); err != nil {
		result = ErrLifecycleIntegrity
	}
	if err := unix.Close(lease.fd); err != nil && result == nil {
		result = ErrLifecycleIntegrity
	}
	lease.fd = -1
	return result
}

func (store *LifecycleStore) lockState() (*lifecycleStoreState, error) {
	if store == nil || store.state == nil {
		return nil, ErrLifecycleStoreClosed
	}
	state := store.state
	state.mu.RLock()
	if state.closed {
		state.mu.RUnlock()
		return nil, ErrLifecycleStoreClosed
	}
	return state, nil
}

func (store *LifecycleStore) verifyStateLocked() error {
	state := store.state
	if state.closed {
		return ErrLifecycleStoreClosed
	}
	rootIdentity, err := lifecycleIdentity(
		state.rootFD,
		unix.S_IFDIR,
		0o700,
		false,
	)
	if err != nil || !samePinnedDirectoryIdentity(rootIdentity, state.rootIdentity) {
		return ErrLifecycleIntegrity
	}
	pathFD, pathIdentity, err := openLifecycleAbsoluteDirectory(state.rootPath)
	if err != nil {
		return ErrLifecycleIntegrity
	}
	closeErr := unix.Close(pathFD)
	if closeErr != nil ||
		!samePinnedDirectoryIdentity(pathIdentity, state.rootIdentity) {
		return ErrLifecycleIntegrity
	}
	for _, directory := range []LifecycleDirectory{
		LifecycleJournals,
		LifecycleReceipts,
		LifecycleReservations,
	} {
		handle, exists := state.directories[directory]
		if !exists {
			return ErrLifecycleIntegrity
		}
		fdIdentity, err := lifecycleIdentity(
			handle.fd,
			unix.S_IFDIR,
			0o700,
			false,
		)
		if err != nil ||
			!samePinnedDirectoryIdentity(fdIdentity, handle.identity) {
			return ErrLifecycleIntegrity
		}
		pathFD, pathIdentity, err := openLifecycleAbsoluteDirectory(handle.path)
		if err == nil {
			err = unix.Close(pathFD)
		}
		if err != nil ||
			!samePinnedDirectoryIdentity(pathIdentity, handle.identity) {
			return ErrLifecycleIntegrity
		}
	}
	lockIdentity, err := lifecycleIdentity(
		state.lockFD,
		unix.S_IFREG,
		0o600,
		true,
	)
	if err != nil ||
		!samePinnedRegularIdentity(lockIdentity, state.lockIdentity) {
		return ErrLifecycleIntegrity
	}
	pathLockIdentity, err := lifecyclePathIdentity(
		state.rootFD,
		lifecycleLockName,
		unix.S_IFREG,
		0o600,
		true,
	)
	if err != nil ||
		!samePinnedRegularIdentity(pathLockIdentity, state.lockIdentity) {
		return ErrLifecycleIntegrity
	}
	return nil
}

func openLifecycleDirectory(
	rootFD int,
	directory LifecycleDirectory,
	bootstrap bool,
) (lifecycleDirectoryHandle, error) {
	if !validLifecycleDirectory(directory) {
		return lifecycleDirectoryHandle{}, ErrLifecycleIntegrity
	}
	if bootstrap {
		err := unix.Mkdirat(rootFD, string(directory), 0o700)
		if err != nil && !errors.Is(err, unix.EEXIST) {
			return lifecycleDirectoryHandle{}, ErrLifecycleIntegrity
		}
		if err == nil && unix.Fsync(rootFD) != nil {
			return lifecycleDirectoryHandle{}, ErrLifecycleIntegrity
		}
	}
	fd, err := unix.Openat(
		rootFD,
		string(directory),
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return lifecycleDirectoryHandle{}, ErrLifecycleIntegrity
	}
	identity, err := lifecycleIdentity(fd, unix.S_IFDIR, 0o700, false)
	if err != nil {
		_ = unix.Close(fd)
		return lifecycleDirectoryHandle{}, err
	}
	return lifecycleDirectoryHandle{fd: fd, identity: identity}, nil
}

func openLifecycleAbsoluteDirectory(
	path string,
) (int, lifecycleFileIdentity, error) {
	if !validLifecycleRootPath(path) || path == "/" {
		return -1, lifecycleFileIdentity{}, ErrLifecycleIntegrity
	}
	fd, err := unix.Open(
		"/",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return -1, lifecycleFileIdentity{}, ErrLifecycleIntegrity
	}
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			_ = unix.Close(fd)
			return -1, lifecycleFileIdentity{}, ErrLifecycleIntegrity
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
			return -1, lifecycleFileIdentity{}, ErrLifecycleIntegrity
		}
		fd = next
	}
	identity, err := lifecycleIdentity(fd, unix.S_IFDIR, 0o700, false)
	if err != nil {
		_ = unix.Close(fd)
		return -1, lifecycleFileIdentity{}, err
	}
	return fd, identity, nil
}

func lifecycleDirectoryIdentityKey(identity lifecycleFileIdentity) string {
	return fmt.Sprintf("%d:%d", identity.device, identity.inode)
}

func openLifecycleLock(
	rootFD int,
	bootstrap bool,
) (int, lifecycleFileIdentity, error) {
	flags := unix.O_RDWR | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fd, err := unix.Openat(rootFD, lifecycleLockName, flags, 0)
	if errors.Is(err, unix.ENOENT) && bootstrap {
		fd, err = unix.Openat(
			rootFD,
			lifecycleLockName,
			flags|unix.O_CREAT|unix.O_EXCL,
			0o600,
		)
		if err == nil {
			if unix.Fchmod(fd, 0o600) != nil ||
				unix.Fsync(fd) != nil ||
				unix.Fsync(rootFD) != nil {
				_ = unix.Close(fd)
				return -1, lifecycleFileIdentity{}, ErrLifecycleIntegrity
			}
		}
	}
	if err != nil {
		return -1, lifecycleFileIdentity{}, ErrLifecycleIntegrity
	}
	identity, err := lifecycleIdentity(fd, unix.S_IFREG, 0o600, true)
	if err != nil {
		_ = unix.Close(fd)
		return -1, lifecycleFileIdentity{}, err
	}
	return fd, identity, nil
}

func readLifecycleDocument(
	dirFD int,
	name string,
	maxBytes int,
) ([]byte, lifecycleFileIdentity, error) {
	fd, err := unix.Openat(
		dirFD,
		name,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK,
		0,
	)
	if errors.Is(err, unix.ENOENT) {
		return nil, lifecycleFileIdentity{}, ErrLifecycleStateAbsent
	}
	if err != nil {
		return nil, lifecycleFileIdentity{}, ErrLifecycleIntegrity
	}
	defer unix.Close(fd)
	before, err := lifecycleIdentity(fd, unix.S_IFREG, 0o600, true)
	if err != nil || before.size <= 0 || before.size > int64(maxBytes) {
		return nil, lifecycleFileIdentity{}, ErrLifecycleIntegrity
	}
	document := make([]byte, 0, before.size)
	buffer := make([]byte, 4096)
	for {
		count, readErr := unix.Read(fd, buffer)
		if count > 0 {
			if len(document)+count > maxBytes {
				return nil, lifecycleFileIdentity{}, ErrLifecycleIntegrity
			}
			document = append(document, buffer[:count]...)
		}
		if readErr != nil {
			return nil, lifecycleFileIdentity{}, ErrLifecycleIntegrity
		}
		if count == 0 {
			break
		}
	}
	after, err := lifecycleIdentity(fd, unix.S_IFREG, 0o600, true)
	if err != nil || before != after || int64(len(document)) != before.size {
		return nil, lifecycleFileIdentity{}, ErrLifecycleIntegrity
	}
	pathIdentity, err := lifecyclePathIdentity(
		dirFD,
		name,
		unix.S_IFREG,
		0o600,
		true,
	)
	if err != nil || pathIdentity != before {
		return nil, lifecycleFileIdentity{}, ErrLifecycleIntegrity
	}
	return document, before, nil
}

func writeLifecycleTemp(dirFD int, document []byte) (string, error) {
	name, err := lifecycleTempName()
	if err != nil {
		return "", err
	}
	fd, err := unix.Openat(
		dirFD,
		name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0o600,
	)
	if err != nil {
		return "", ErrLifecycleIntegrity
	}
	present := true
	defer func() {
		_ = unix.Close(fd)
		if present {
			_ = unix.Unlinkat(dirFD, name, 0)
		}
	}()
	if err := unix.Fchmod(fd, 0o600); err != nil {
		return "", ErrLifecycleIntegrity
	}
	remaining := document
	for len(remaining) > 0 {
		count, writeErr := unix.Write(fd, remaining)
		if writeErr != nil || count <= 0 {
			return "", ErrLifecycleIntegrity
		}
		remaining = remaining[count:]
	}
	if err := unix.Fsync(fd); err != nil {
		return "", ErrLifecycleIntegrity
	}
	identity, err := lifecycleIdentity(fd, unix.S_IFREG, 0o600, true)
	if err != nil || identity.size != int64(len(document)) {
		return "", ErrLifecycleIntegrity
	}
	if err := unix.Close(fd); err != nil {
		return "", ErrLifecycleIntegrity
	}
	fd = -1
	present = false
	return name, nil
}

func lifecycleTempName() (string, error) {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", ErrLifecycleIntegrity
	}
	return ".tmp-" + hex.EncodeToString(token[:]), nil
}

func lifecycleIdentity(
	fd int,
	expectedKind uint32,
	expectedMode uint32,
	singleLink bool,
) (lifecycleFileIdentity, error) {
	if fd < 0 {
		return lifecycleFileIdentity{}, ErrLifecycleIntegrity
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return lifecycleFileIdentity{}, ErrLifecycleIntegrity
	}
	return validateLifecycleStat(&stat, expectedKind, expectedMode, singleLink)
}

func lifecyclePathIdentity(
	dirFD int,
	name string,
	expectedKind uint32,
	expectedMode uint32,
	singleLink bool,
) (lifecycleFileIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(
		dirFD,
		name,
		&stat,
		unix.AT_SYMLINK_NOFOLLOW,
	); errors.Is(err, unix.ENOENT) {
		return lifecycleFileIdentity{}, ErrLifecycleStateAbsent
	} else if err != nil {
		return lifecycleFileIdentity{}, ErrLifecycleIntegrity
	}
	return validateLifecycleStat(&stat, expectedKind, expectedMode, singleLink)
}

func validateLifecycleStat(
	stat *unix.Stat_t,
	expectedKind uint32,
	expectedMode uint32,
	singleLink bool,
) (lifecycleFileIdentity, error) {
	mode := uint32(stat.Mode)
	if mode&unix.S_IFMT != expectedKind ||
		mode&0o777 != expectedMode ||
		stat.Uid != uint32(unix.Geteuid()) ||
		(singleLink && uint64(stat.Nlink) != 1) ||
		stat.Ino == 0 ||
		int64(stat.Size) < 0 {
		return lifecycleFileIdentity{}, ErrLifecycleIntegrity
	}
	return lifecycleFileIdentity{
		device: uint64(stat.Dev),
		inode:  stat.Ino,
		mode:   mode,
		uid:    stat.Uid,
		nlink:  uint64(stat.Nlink),
		size:   int64(stat.Size),
	}, nil
}

func validLifecycleRootPath(root string) bool {
	return filepath.IsAbs(root) &&
		filepath.Clean(root) == root &&
		!strings.ContainsRune(root, 0)
}

func validLifecycleDocumentRequest(
	directory LifecycleDirectory,
	name string,
	maxBytes int,
	document []byte,
	requireDocument bool,
) bool {
	if !validLifecycleDirectory(directory) ||
		maxBytes <= 0 ||
		!validLifecycleLeafName(name) {
		return false
	}
	if !requireDocument {
		return true
	}
	return len(document) > 0 && len(document) <= maxBytes
}

func validLifecycleLeafName(name string) bool {
	return name != "" &&
		name != "." &&
		name != ".." &&
		filepath.Base(name) == name &&
		!strings.ContainsAny(name, "/\x00") &&
		!strings.HasPrefix(name, ".tmp-") &&
		len(name) <= 255
}

func samePinnedDirectoryIdentity(
	left lifecycleFileIdentity,
	right lifecycleFileIdentity,
) bool {
	return left.device == right.device &&
		left.inode == right.inode &&
		left.mode == right.mode &&
		left.uid == right.uid
}

func samePinnedRegularIdentity(
	left lifecycleFileIdentity,
	right lifecycleFileIdentity,
) bool {
	return samePinnedDirectoryIdentity(left, right) &&
		left.nlink == right.nlink &&
		left.size == right.size
}

func (identity lifecycleFileIdentity) String() string {
	return fmt.Sprintf("%d:%d", identity.device, identity.inode)
}
