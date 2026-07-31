//go:build darwin || linux

package productionruntime

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	processRecordName     = "controller.process.json"
	processRecordTempName = ".controller.process.tmp"
)

var ErrProcessRecordStore = errors.New(
	"productionruntime: process record store failed",
)

type processRecordFileIdentity struct {
	device uint64
	inode  uint64
	mode   uint32
	uid    uint32
	nlink  uint64
	size   int64
}

type PinnedProcessRecordStore struct {
	mu           sync.Mutex
	rootPath     string
	rootFD       int
	rootIdentity processRecordFileIdentity
	closed       bool
}

func OpenProcessRecordStore(
	root string,
) (*PinnedProcessRecordStore, error) {
	fd, identity, err := openProcessRecordRoot(root)
	if err != nil {
		return nil, ErrProcessRecordStore
	}
	store := &PinnedProcessRecordStore{
		rootPath:     root,
		rootFD:       fd,
		rootIdentity: identity,
	}
	store.mu.Lock()
	err = store.verifyRootLocked()
	store.mu.Unlock()
	if err != nil {
		_ = unix.Close(fd)
		return nil, ErrProcessRecordStore
	}
	return store, nil
}

func (store *PinnedProcessRecordStore) Read(
	ctx context.Context,
) (ProcessRecord, string, bool, error) {
	if store == nil || ctx == nil {
		return ProcessRecord{}, "", false, ErrProcessRecordStore
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.readyLocked(ctx); err != nil {
		return ProcessRecord{}, "", false, err
	}
	return store.readLocked(ctx)
}

func (store *PinnedProcessRecordStore) Create(
	ctx context.Context,
	record ProcessRecord,
) (string, error) {
	if store == nil || ctx == nil {
		return "", ErrProcessRecordStore
	}
	document, identity, err := MarshalProcessRecord(record)
	if err != nil {
		return "", ErrProcessRecordStore
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.readyLocked(ctx); err != nil {
		return "", err
	}
	if _, err := processRecordPathIdentity(
		store.rootFD,
		processRecordName,
	); err == nil || !errors.Is(err, unix.ENOENT) {
		return "", ErrProcessRecordStore
	}

	fd, err := unix.Openat(
		store.rootFD,
		processRecordTempName,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|
			unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0o600,
	)
	if err != nil {
		return "", ErrProcessRecordStore
	}
	tempPresent := true
	defer func() {
		_ = unix.Close(fd)
		if tempPresent {
			_ = unix.Unlinkat(store.rootFD, processRecordTempName, 0)
		}
	}()
	if unix.Fchmod(fd, 0o600) != nil ||
		writeProcessRecordDocument(fd, document) != nil ||
		unix.Fsync(fd) != nil {
		return "", ErrProcessRecordStore
	}
	tempIdentity, err := processRecordFDIdentity(
		fd,
		unix.S_IFREG,
		0o600,
		true,
	)
	if err != nil || tempIdentity.size != int64(len(document)) {
		return "", ErrProcessRecordStore
	}
	if err := unix.Close(fd); err != nil {
		return "", ErrProcessRecordStore
	}
	fd = -1
	if err := unix.Linkat(
		store.rootFD,
		processRecordTempName,
		store.rootFD,
		processRecordName,
		0,
	); err != nil {
		return "", ErrProcessRecordStore
	}
	if err := unix.Unlinkat(
		store.rootFD,
		processRecordTempName,
		0,
	); err != nil {
		return "", ErrProcessRecordStore
	}
	tempPresent = false
	if unix.Fsync(store.rootFD) != nil {
		return "", ErrProcessRecordStore
	}
	readback, readIdentity, present, err := store.readLocked(ctx)
	if err != nil ||
		!present ||
		readback != record ||
		readIdentity != identity {
		return "", ErrProcessRecordStore
	}
	return identity, nil
}

func (store *PinnedProcessRecordStore) Remove(
	ctx context.Context,
	expectedIdentity string,
) error {
	if store == nil ||
		ctx == nil ||
		!lowerHexDigest(expectedIdentity) {
		return ErrProcessRecordStore
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.readyLocked(ctx); err != nil {
		return err
	}
	_, identity, present, pinned, err := store.readPinnedLocked(ctx)
	if err != nil || !present || identity != expectedIdentity {
		return ErrProcessRecordStore
	}
	pathIdentity, err := processRecordPathIdentity(
		store.rootFD,
		processRecordName,
	)
	if err != nil || pathIdentity != pinned {
		return ErrProcessRecordStore
	}
	if unix.Unlinkat(store.rootFD, processRecordName, 0) != nil ||
		unix.Fsync(store.rootFD) != nil {
		return ErrProcessRecordStore
	}
	if _, err := processRecordPathIdentity(
		store.rootFD,
		processRecordName,
	); !errors.Is(err, unix.ENOENT) {
		return ErrProcessRecordStore
	}
	if err := store.verifyRootLocked(); err != nil {
		return err
	}
	return nil
}

func (store *PinnedProcessRecordStore) Close() error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	store.closed = true
	if store.rootFD < 0 {
		return nil
	}
	if err := unix.Close(store.rootFD); err != nil {
		return ErrProcessRecordStore
	}
	store.rootFD = -1
	return nil
}

func (store *PinnedProcessRecordStore) readLocked(
	ctx context.Context,
) (ProcessRecord, string, bool, error) {
	record, identity, present, _, err := store.readPinnedLocked(ctx)
	return record, identity, present, err
}

func (store *PinnedProcessRecordStore) readPinnedLocked(
	ctx context.Context,
) (
	ProcessRecord,
	string,
	bool,
	processRecordFileIdentity,
	error,
) {
	fd, err := unix.Openat(
		store.rootFD,
		processRecordName,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK,
		0,
	)
	if errors.Is(err, unix.ENOENT) {
		if store.verifyRootLocked() != nil {
			return ProcessRecord{}, "", false,
				processRecordFileIdentity{}, ErrProcessRecordStore
		}
		return ProcessRecord{}, "", false, processRecordFileIdentity{}, nil
	}
	if err != nil {
		return ProcessRecord{}, "", false,
			processRecordFileIdentity{}, ErrProcessRecordStore
	}
	defer unix.Close(fd)
	before, err := processRecordFDIdentity(
		fd,
		unix.S_IFREG,
		0o600,
		true,
	)
	if err != nil ||
		before.size <= 0 ||
		before.size > int64(MaxProcessRecordBytes) {
		return ProcessRecord{}, "", false,
			processRecordFileIdentity{}, ErrProcessRecordStore
	}
	document, err := readProcessRecordDocument(fd, int(before.size))
	if err != nil {
		return ProcessRecord{}, "", false,
			processRecordFileIdentity{}, ErrProcessRecordStore
	}
	after, err := processRecordFDIdentity(
		fd,
		unix.S_IFREG,
		0o600,
		true,
	)
	if err != nil ||
		before != after ||
		int64(len(document)) != before.size {
		return ProcessRecord{}, "", false,
			processRecordFileIdentity{}, ErrProcessRecordStore
	}
	pathIdentity, err := processRecordPathIdentity(
		store.rootFD,
		processRecordName,
	)
	if err != nil || pathIdentity != before {
		return ProcessRecord{}, "", false,
			processRecordFileIdentity{}, ErrProcessRecordStore
	}
	record, identity, err := ParseProcessRecord(
		document,
		MaxProcessRecordBytes,
	)
	if err != nil ||
		ctx.Err() != nil ||
		store.verifyRootLocked() != nil {
		return ProcessRecord{}, "", false,
			processRecordFileIdentity{}, ErrProcessRecordStore
	}
	return record, identity, true, before, nil
}

func (store *PinnedProcessRecordStore) readyLocked(
	ctx context.Context,
) error {
	if store.closed ||
		store.rootFD < 0 ||
		ctx.Err() != nil ||
		store.verifyRootLocked() != nil {
		return ErrProcessRecordStore
	}
	return nil
}

func (store *PinnedProcessRecordStore) verifyRootLocked() error {
	current, err := processRecordFDIdentity(
		store.rootFD,
		unix.S_IFDIR,
		0o700,
		false,
	)
	if err != nil ||
		!sameProcessRecordDirectory(current, store.rootIdentity) {
		return ErrProcessRecordStore
	}
	fd, pathIdentity, err := openProcessRecordRoot(store.rootPath)
	if err == nil {
		err = unix.Close(fd)
	}
	if err != nil ||
		!sameProcessRecordDirectory(pathIdentity, store.rootIdentity) {
		return ErrProcessRecordStore
	}
	return nil
}

func openProcessRecordRoot(
	path string,
) (int, processRecordFileIdentity, error) {
	if !filepath.IsAbs(path) ||
		filepath.Clean(path) != path ||
		path == "/" ||
		strings.ContainsRune(path, 0) {
		return -1, processRecordFileIdentity{}, ErrProcessRecordStore
	}
	fd, err := unix.Open(
		"/",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return -1, processRecordFileIdentity{}, ErrProcessRecordStore
	}
	for _, component := range strings.Split(
		strings.TrimPrefix(path, "/"),
		"/",
	) {
		if component == "" || component == "." || component == ".." {
			_ = unix.Close(fd)
			return -1, processRecordFileIdentity{}, ErrProcessRecordStore
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
			return -1, processRecordFileIdentity{}, ErrProcessRecordStore
		}
		fd = next
	}
	identity, err := processRecordFDIdentity(
		fd,
		unix.S_IFDIR,
		0o700,
		false,
	)
	if err != nil {
		_ = unix.Close(fd)
		return -1, processRecordFileIdentity{}, ErrProcessRecordStore
	}
	return fd, identity, nil
}

func processRecordFDIdentity(
	fd int,
	kind uint32,
	mode uint32,
	singleLink bool,
) (processRecordFileIdentity, error) {
	if fd < 0 {
		return processRecordFileIdentity{}, ErrProcessRecordStore
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return processRecordFileIdentity{}, ErrProcessRecordStore
	}
	return validateProcessRecordStat(&stat, kind, mode, singleLink)
}

func processRecordPathIdentity(
	dirFD int,
	name string,
) (processRecordFileIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(
		dirFD,
		name,
		&stat,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return processRecordFileIdentity{}, err
	}
	return validateProcessRecordStat(
		&stat,
		unix.S_IFREG,
		0o600,
		true,
	)
}

func validateProcessRecordStat(
	stat *unix.Stat_t,
	kind uint32,
	mode uint32,
	singleLink bool,
) (processRecordFileIdentity, error) {
	statMode := uint32(stat.Mode)
	if statMode&unix.S_IFMT != kind ||
		statMode&0o777 != mode ||
		stat.Uid != uint32(unix.Geteuid()) ||
		(singleLink && uint64(stat.Nlink) != 1) ||
		stat.Ino == 0 ||
		int64(stat.Size) < 0 {
		return processRecordFileIdentity{}, ErrProcessRecordStore
	}
	return processRecordFileIdentity{
		device: uint64(stat.Dev),
		inode:  stat.Ino,
		mode:   statMode,
		uid:    stat.Uid,
		nlink:  uint64(stat.Nlink),
		size:   int64(stat.Size),
	}, nil
}

func sameProcessRecordDirectory(
	left processRecordFileIdentity,
	right processRecordFileIdentity,
) bool {
	return left.device == right.device &&
		left.inode == right.inode &&
		left.mode == right.mode &&
		left.uid == right.uid
}

func writeProcessRecordDocument(fd int, document []byte) error {
	for len(document) > 0 {
		count, err := unix.Write(fd, document)
		if err != nil || count <= 0 || count > len(document) {
			return ErrProcessRecordStore
		}
		document = document[count:]
	}
	return nil
}

func readProcessRecordDocument(fd int, size int) ([]byte, error) {
	document := make([]byte, 0, size)
	buffer := make([]byte, 1024)
	for {
		count, err := unix.Read(fd, buffer)
		if err != nil || count < 0 || count > len(buffer) {
			return nil, ErrProcessRecordStore
		}
		if count == 0 {
			break
		}
		if len(document)+count > MaxProcessRecordBytes {
			return nil, ErrProcessRecordStore
		}
		document = append(document, buffer[:count]...)
	}
	return document, nil
}

var _ ProcessRecordStore = (*PinnedProcessRecordStore)(nil)
