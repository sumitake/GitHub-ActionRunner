//go:build darwin || linux

package upgrade

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const journalLockPollInterval = 10 * time.Millisecond

func openFileJournalStore(
	config StoreConfig,
) (*FileJournalStore, error) {
	rootFD, rootIdentity, err := openJournalRoot(config.Root)
	if err != nil {
		return nil, err
	}
	lockFD, lockIdentity, err := openJournalLock(rootFD, config.Bootstrap)
	if err != nil {
		_ = unix.Close(rootFD)
		return nil, err
	}
	return &FileJournalStore{
		root:             config.Root,
		rootFD:           rootFD,
		lockPinFD:        lockFD,
		rootIdentity:     rootIdentity,
		lockIdentity:     lockIdentity,
		maxDocumentBytes: config.MaxDocumentBytes,
	}, nil
}

func openJournalRoot(
	root string,
) (int, journalFileIdentity, error) {
	fd, err := unix.Open(
		root,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return -1, journalFileIdentity{}, ErrJournalIntegrity
	}
	identity, err := journalFstatPrivate(
		fd,
		unix.S_IFDIR,
		0o700,
		false,
	)
	if err != nil {
		_ = unix.Close(fd)
		return -1, journalFileIdentity{}, err
	}
	return fd, identity, nil
}

func openJournalLock(
	rootFD int,
	bootstrap bool,
) (int, journalFileIdentity, error) {
	flags := unix.O_RDWR | unix.O_NOFOLLOW | unix.O_CLOEXEC
	created := false
	if bootstrap {
		fd, err := unix.Openat(
			rootFD,
			journalLockName,
			flags|unix.O_CREAT|unix.O_EXCL,
			0o600,
		)
		switch {
		case err == nil:
			created = true
			if err := unix.Fchmod(fd, 0o600); err != nil ||
				unix.Fsync(fd) != nil ||
				unix.Fsync(rootFD) != nil {
				_ = unix.Close(fd)
				return -1, journalFileIdentity{}, ErrJournalIntegrity
			}
			identity, err := journalFstatPrivate(
				fd,
				unix.S_IFREG,
				0o600,
				true,
			)
			if err != nil {
				_ = unix.Close(fd)
				return -1, journalFileIdentity{}, err
			}
			return fd, identity, nil
		case errors.Is(err, syscall.EEXIST):
		default:
			return -1, journalFileIdentity{}, ErrJournalIntegrity
		}
	}
	fd, err := unix.Openat(rootFD, journalLockName, flags, 0)
	if err != nil {
		return -1, journalFileIdentity{}, ErrJournalIntegrity
	}
	identity, err := journalFstatPrivate(
		fd,
		unix.S_IFREG,
		0o600,
		true,
	)
	if err != nil {
		_ = unix.Close(fd)
		return -1, journalFileIdentity{}, err
	}
	if created {
		return -1, journalFileIdentity{}, ErrJournalIntegrity
	}
	return fd, identity, nil
}

func journalFstatPrivate(
	fd int,
	kind uint32,
	mode uint32,
	singleLink bool,
) (journalFileIdentity, error) {
	if fd < 0 {
		return journalFileIdentity{}, ErrJournalStoreClosed
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return journalFileIdentity{}, ErrJournalIntegrity
	}
	statMode := uint32(stat.Mode)
	if statMode&unix.S_IFMT != kind ||
		statMode&0o777 != mode ||
		stat.Uid != uint32(os.Geteuid()) ||
		(singleLink && stat.Nlink != 1) {
		return journalFileIdentity{}, ErrJournalIntegrity
	}
	return journalFileIdentity{
		device: uint64(stat.Dev),
		inode:  stat.Ino,
	}, nil
}

func duplicateJournalFD(fd int) (int, error) {
	duplicate, err := unix.FcntlInt(
		uintptr(fd),
		unix.F_DUPFD_CLOEXEC,
		0,
	)
	if err != nil {
		return -1, ErrJournalStoreClosed
	}
	return duplicate, nil
}

func (store *FileJournalStore) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	store.closed = true
	var result error
	if store.lockPinFD >= 0 {
		if err := unix.Close(store.lockPinFD); err != nil {
			result = errors.Join(result, ErrJournalIntegrity)
		}
		store.lockPinFD = -1
	}
	if store.rootFD >= 0 {
		if err := unix.Close(store.rootFD); err != nil {
			result = errors.Join(result, ErrJournalIntegrity)
		}
		store.rootFD = -1
	}
	return result
}

func (store *FileJournalStore) Acquire(
	ctx context.Context,
) (JournalLease, error) {
	if ctx == nil {
		return nil, ErrJournalDeadlineRequired
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, ErrJournalDeadlineRequired
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(ErrJournalLeaseUnavailable, err)
	}

	store.mu.Lock()
	if store.closed {
		store.mu.Unlock()
		return nil, ErrJournalStoreClosed
	}
	rootFD, lockPinFD, duplicateErr := duplicateJournalAcquireFDs(
		store.rootFD,
		store.lockPinFD,
		duplicateJournalFD,
	)
	rootIdentity := store.rootIdentity
	lockIdentity := store.lockIdentity
	rootPath := store.root
	store.mu.Unlock()
	if duplicateErr != nil {
		return nil, duplicateErr
	}
	cleanupRoot := true
	defer func() {
		if cleanupRoot {
			_ = unix.Close(rootFD)
		}
	}()
	cleanupPin := true
	defer func() {
		if cleanupPin {
			_ = unix.Close(lockPinFD)
		}
	}()

	if err := verifyJournalRoot(rootFD, rootPath, rootIdentity); err != nil {
		return nil, err
	}
	pinnedLock, err := journalFstatPrivate(
		lockPinFD,
		unix.S_IFREG,
		0o600,
		true,
	)
	if err != nil || pinnedLock != lockIdentity {
		return nil, ErrJournalIntegrity
	}
	lockFD, observedLock, err := openJournalLock(rootFD, false)
	if err != nil {
		return nil, err
	}
	cleanupLock := true
	defer func() {
		if cleanupLock {
			_ = unix.Close(lockFD)
		}
	}()
	if observedLock != lockIdentity {
		return nil, ErrJournalIntegrity
	}
	if err := flockJournal(ctx, lockFD); err != nil {
		return nil, err
	}
	pinCloseErr := unix.Close(lockPinFD)
	cleanupPin = false
	if pinCloseErr != nil {
		cleanupLock = false
		return nil, errors.Join(
			ErrJournalIntegrity,
			releaseProspectiveJournalLock(
				lockFD,
				func(fd int) error {
					return unix.Flock(fd, unix.LOCK_UN)
				},
				unix.Close,
			),
		)
	}
	if err := verifyJournalRoot(rootFD, rootPath, rootIdentity); err != nil ||
		verifyJournalLock(rootFD, lockIdentity) != nil {
		cleanupLock = false
		return nil, errors.Join(
			ErrJournalIntegrity,
			releaseProspectiveJournalLock(
				lockFD,
				func(fd int) error {
					return unix.Flock(fd, unix.LOCK_UN)
				},
				unix.Close,
			),
		)
	}

	cleanupRoot = false
	cleanupLock = false
	return &fileJournalLease{
		store:        store,
		rootFD:       rootFD,
		lockFD:       lockFD,
		rootIdentity: rootIdentity,
		lockIdentity: lockIdentity,
	}, nil
}

func releaseProspectiveJournalLock(
	fd int,
	unlock func(int) error,
	closeFD func(int) error,
) error {
	if fd < 0 || unlock == nil || closeFD == nil {
		return ErrJournalIntegrity
	}
	var result error
	if err := unlock(fd); err != nil {
		result = errors.Join(result, ErrJournalIntegrity)
	}
	if err := closeFD(fd); err != nil {
		result = errors.Join(result, ErrJournalIntegrity)
	}
	return result
}

func duplicateJournalAcquireFDs(
	rootFD int,
	lockPinFD int,
	duplicate func(int) (int, error),
) (int, int, error) {
	if duplicate == nil {
		return -1, -1, ErrJournalStoreClosed
	}
	rootDuplicate, err := duplicate(rootFD)
	if err != nil {
		return -1, -1, err
	}
	lockPinDuplicate, err := duplicate(lockPinFD)
	if err != nil {
		if closeErr := unix.Close(rootDuplicate); closeErr != nil {
			return -1, -1, errors.Join(err, ErrJournalIntegrity)
		}
		return -1, -1, err
	}
	return rootDuplicate, lockPinDuplicate, nil
}

func verifyJournalRoot(
	rootFD int,
	rootPath string,
	expected journalFileIdentity,
) error {
	identity, err := journalFstatPrivate(
		rootFD,
		unix.S_IFDIR,
		0o700,
		false,
	)
	if err != nil || identity != expected {
		return ErrJournalIntegrity
	}
	pathFD, pathIdentity, err := openJournalRoot(rootPath)
	if err != nil {
		return ErrJournalIntegrity
	}
	defer unix.Close(pathFD)
	if pathIdentity != expected {
		return ErrJournalIntegrity
	}
	return nil
}

func verifyJournalLock(
	rootFD int,
	expected journalFileIdentity,
) error {
	fd, identity, err := openJournalLock(rootFD, false)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if identity != expected {
		return ErrJournalIntegrity
	}
	return nil
}

func flockJournal(ctx context.Context, fd int) error {
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) &&
			!errors.Is(err, syscall.EAGAIN) {
			return ErrJournalIntegrity
		}
		timer := time.NewTimer(journalLockPollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return errors.Join(ErrJournalLeaseUnavailable, ctx.Err())
		case <-timer.C:
		}
	}
}

func (lease *fileJournalLease) Close() error {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return nil
	}
	lease.closed = true
	var result error
	if lease.lockFD >= 0 {
		if err := unix.Flock(lease.lockFD, unix.LOCK_UN); err != nil {
			result = errors.Join(result, ErrJournalIntegrity)
		}
		if err := unix.Close(lease.lockFD); err != nil {
			result = errors.Join(result, ErrJournalIntegrity)
		}
		lease.lockFD = -1
	}
	if lease.rootFD >= 0 {
		if err := unix.Close(lease.rootFD); err != nil {
			result = errors.Join(result, ErrJournalIntegrity)
		}
		lease.rootFD = -1
	}
	return result
}

func (lease *fileJournalLease) operationRoot() (int, error) {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed || lease.rootFD < 0 || lease.lockFD < 0 {
		return -1, ErrJournalStoreClosed
	}
	if err := verifyJournalRoot(
		lease.rootFD,
		lease.store.root,
		lease.rootIdentity,
	); err != nil ||
		verifyJournalLock(lease.rootFD, lease.lockIdentity) != nil {
		return -1, ErrJournalIntegrity
	}
	return lease.rootFD, nil
}

func (lease *fileJournalLease) Read() ([]byte, error) {
	rootFD, err := lease.operationRoot()
	if err != nil {
		return nil, err
	}
	return readJournalDocument(
		rootFD,
		lease.store.maxDocumentBytes,
	)
}

func readJournalDocument(
	rootFD int,
	maximum int,
) ([]byte, error) {
	fd, err := unix.Openat(
		rootFD,
		journalFileName,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK,
		0,
	)
	if errors.Is(err, syscall.ENOENT) {
		return nil, ErrJournalAbsent
	}
	if err != nil {
		return nil, ErrJournalIntegrity
	}
	if _, err := journalFstatPrivate(
		fd,
		unix.S_IFREG,
		0o600,
		true,
	); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	file := os.NewFile(uintptr(fd), journalFileName)
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrJournalIntegrity
	}
	defer file.Close()
	document, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || !validJournalDocument(document, maximum) {
		return nil, ErrJournalIntegrity
	}
	return document, nil
}

func (lease *fileJournalLease) Create(document []byte) error {
	if !validJournalDocument(
		document,
		lease.store.maxDocumentBytes,
	) {
		return ErrJournalIntegrity
	}
	rootFD, err := lease.operationRoot()
	if err != nil {
		return err
	}
	if _, err := readJournalDocument(
		rootFD,
		lease.store.maxDocumentBytes,
	); err == nil {
		return ErrJournalConflict
	} else if !errors.Is(err, ErrJournalAbsent) {
		return err
	}

	temp, err := writeJournalTemp(lease.store, rootFD, document)
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = unix.Unlinkat(rootFD, temp, 0)
		}
	}()
	if lease.store.injectJournalFault("create-install") != nil {
		return ErrJournalIntegrity
	}
	if err := renameJournalNoReplace(
		rootFD,
		temp,
		journalFileName,
	); err != nil {
		if errors.Is(err, syscall.EEXIST) {
			return ErrJournalConflict
		}
		return ErrJournalIntegrity
	}
	cleanup = false
	if lease.store.injectJournalFault("create-after-install") != nil {
		// Model abrupt process termination after the directory entry becomes
		// visible: ordinary deferred temp cleanup would not run.
		return ErrJournalIntegrity
	}
	if lease.store.injectJournalFault("root-fsync") != nil {
		return ErrJournalIntegrity
	}
	if err := unix.Fsync(rootFD); err != nil {
		return ErrJournalIntegrity
	}
	readback, err := readJournalDocument(
		rootFD,
		lease.store.maxDocumentBytes,
	)
	if err != nil || !bytes.Equal(readback, document) {
		return ErrJournalIntegrity
	}
	return nil
}

func (lease *fileJournalLease) Replace(
	expected, replacement []byte,
) error {
	if !validJournalDocument(
		expected,
		lease.store.maxDocumentBytes,
	) ||
		!validJournalDocument(
			replacement,
			lease.store.maxDocumentBytes,
		) {
		return ErrJournalIntegrity
	}
	rootFD, err := lease.operationRoot()
	if err != nil {
		return err
	}
	current, err := readJournalDocument(
		rootFD,
		lease.store.maxDocumentBytes,
	)
	if errors.Is(err, ErrJournalAbsent) ||
		err == nil && !bytes.Equal(current, expected) {
		return ErrJournalConflict
	}
	if err != nil {
		return err
	}
	temp, err := writeJournalTemp(lease.store, rootFD, replacement)
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = unix.Unlinkat(rootFD, temp, 0)
		}
	}()

	current, err = readJournalDocument(
		rootFD,
		lease.store.maxDocumentBytes,
	)
	if err != nil || !bytes.Equal(current, expected) {
		if errors.Is(err, ErrJournalAbsent) ||
			err == nil {
			return ErrJournalConflict
		}
		return err
	}
	if lease.store.injectJournalFault("replace-install") != nil {
		return ErrJournalIntegrity
	}
	if err := unix.Renameat(
		rootFD,
		temp,
		rootFD,
		journalFileName,
	); err != nil {
		return ErrJournalIntegrity
	}
	cleanup = false
	if lease.store.injectJournalFault("root-fsync") != nil {
		return ErrJournalIntegrity
	}
	if err := unix.Fsync(rootFD); err != nil {
		return ErrJournalIntegrity
	}
	readback, err := readJournalDocument(
		rootFD,
		lease.store.maxDocumentBytes,
	)
	if err != nil || !bytes.Equal(readback, replacement) {
		return ErrJournalIntegrity
	}
	return nil
}

func writeJournalTemp(
	store *FileJournalStore,
	rootFD int,
	document []byte,
) (string, error) {
	name := fmt.Sprintf(
		".runner-upgrade.tmp-%d-%d",
		os.Getpid(),
		store.tempSequence.Add(1),
	)
	fd, err := unix.Openat(
		rootFD,
		name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|
			unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0o600,
	)
	if err != nil {
		return "", ErrJournalIntegrity
	}
	cleanup := true
	defer func() {
		_ = unix.Close(fd)
		if cleanup {
			_ = unix.Unlinkat(rootFD, name, 0)
		}
	}()
	if err := unix.Fchmod(fd, 0o600); err != nil ||
		store.injectJournalFault("write") != nil ||
		writeJournalAll(fd, document) != nil ||
		store.injectJournalFault("file-fsync") != nil ||
		unix.Fsync(fd) != nil {
		return "", ErrJournalIntegrity
	}
	if err := unix.Close(fd); err != nil {
		return "", ErrJournalIntegrity
	}
	fd = -1
	cleanup = false
	return name, nil
}

func (store *FileJournalStore) injectJournalFault(
	point string,
) error {
	if store.fault == nil {
		return nil
	}
	return store.fault(point)
}

func writeJournalAll(fd int, document []byte) error {
	for len(document) > 0 {
		written, err := unix.Write(fd, document)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		document = document[written:]
	}
	return nil
}
