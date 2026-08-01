//go:build darwin || linux

package fleetfence

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	lockShared    = unix.LOCK_SH
	lockExclusive = unix.LOCK_EX
)

func openPrivateRoot(root string) (int, fileIdentity, error) {
	fd, err := unix.Open(
		root,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return -1, fileIdentity{}, fmt.Errorf("%w: root", ErrInvalidState)
	}
	identity, err := fstatPrivate(fd, unix.S_IFDIR, 0o700, false)
	if err != nil {
		_ = unix.Close(fd)
		return -1, fileIdentity{}, err
	}
	return fd, identity, nil
}

func (s *Store) operationFDs(bootstrap bool) (int, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return -1, -1, ErrStoreClosed
	}
	if _, err := fstatPrivate(s.rootFD, unix.S_IFDIR, 0o700, false); err != nil {
		return -1, -1, err
	}
	if s.holderFD < 0 {
		fd, err := openHolderDirectory(s.rootFD, bootstrap)
		if err != nil {
			return -1, -1, err
		}
		s.holderFD = fd
	}
	if _, err := fstatPrivate(s.holderFD, unix.S_IFDIR, 0o700, false); err != nil {
		return -1, -1, err
	}
	return s.rootFD, s.holderFD, nil
}

func (s *Store) inspectBootstrapState() (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return false, ErrStoreClosed
	}
	if _, err := fstatPrivate(
		s.rootFD,
		unix.S_IFDIR,
		0o700,
		false,
	); err != nil {
		return false, err
	}
	present := 0
	for _, name := range [...]string{
		lockName,
		headerName,
		holderDirName,
	} {
		var stat unix.Stat_t
		err := unix.Fstatat(
			s.rootFD,
			name,
			&stat,
			unix.AT_SYMLINK_NOFOLLOW,
		)
		switch {
		case err == nil:
			present++
		case errors.Is(err, syscall.ENOENT):
		default:
			return false, ErrInvalidState
		}
	}
	switch present {
	case 0:
		return false, nil
	case 3:
		return true, nil
	default:
		return false, ErrInvalidState
	}
}

func openHolderDirectory(rootFD int, bootstrap bool) (int, error) {
	if bootstrap {
		err := unix.Mkdirat(rootFD, holderDirName, 0o700)
		switch {
		case err == nil:
			if err := unix.Fsync(rootFD); err != nil {
				return -1, err
			}
		case errors.Is(err, syscall.EEXIST):
		default:
			return -1, fmt.Errorf("%w: holder directory", ErrInvalidState)
		}
	}
	fd, err := unix.Openat(
		rootFD,
		holderDirName,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return -1, fmt.Errorf("%w: holder directory", ErrInvalidState)
	}
	if _, err := fstatPrivate(fd, unix.S_IFDIR, 0o700, false); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func openStableLock(rootFD int, bootstrap bool) (int, fileIdentity, error) {
	flags := unix.O_RDWR | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if bootstrap {
		fd, err := unix.Openat(rootFD, lockName, flags|unix.O_CREAT|unix.O_EXCL, 0o600)
		switch {
		case err == nil:
			if err := unix.Fchmod(fd, 0o600); err != nil {
				_ = unix.Close(fd)
				return -1, fileIdentity{}, err
			}
			if err := unix.Fsync(fd); err != nil {
				_ = unix.Close(fd)
				return -1, fileIdentity{}, err
			}
			if err := unix.Fsync(rootFD); err != nil {
				_ = unix.Close(fd)
				return -1, fileIdentity{}, err
			}
			identity, err := fstatRegular(fd, 0o600)
			return fd, identity, err
		case errors.Is(err, syscall.EEXIST):
		default:
			return -1, fileIdentity{}, fmt.Errorf("%w: create lock", ErrInvalidState)
		}
	}
	fd, err := unix.Openat(rootFD, lockName, flags, 0)
	if err != nil {
		return -1, fileIdentity{}, fmt.Errorf("%w: open lock", ErrInvalidState)
	}
	identity, err := fstatRegular(fd, 0o600)
	if err != nil {
		_ = unix.Close(fd)
		return -1, fileIdentity{}, err
	}
	return fd, identity, nil
}

func fstatRegular(fd int, mode uint32) (fileIdentity, error) {
	return fstatPrivate(fd, unix.S_IFREG, mode, true)
}

func fstatDirectory(fd int) (fileIdentity, error) {
	return fstatPrivate(fd, unix.S_IFDIR, 0o700, false)
}

func fstatPrivate(
	fd int,
	kind uint32,
	mode uint32,
	singleLink bool,
) (fileIdentity, error) {
	if fd < 0 {
		return fileIdentity{}, ErrStoreClosed
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fileIdentity{}, ErrInvalidState
	}
	statMode := uint32(stat.Mode)
	if statMode&unix.S_IFMT != kind ||
		statMode&0o777 != mode ||
		stat.Uid != uint32(os.Geteuid()) ||
		(singleLink && stat.Nlink != 1) {
		return fileIdentity{}, ErrInvalidState
	}
	return fileIdentity{device: uint64(stat.Dev), inode: stat.Ino}, nil
}

func readHeader(rootFD int) (Header, error) {
	header, exists, err := readOptionalHeader(rootFD)
	if err != nil {
		return Header{}, err
	}
	if !exists {
		return Header{}, ErrInvalidState
	}
	return header, nil
}

func readOptionalHeader(rootFD int) (Header, bool, error) {
	document, exists, err := readPrivateFile(rootFD, headerName)
	if err != nil || !exists {
		return Header{}, exists, err
	}
	var header Header
	if err := decodeCanonical(document, &header); err != nil ||
		validateHeader(header) != nil {
		return Header{}, true, ErrInvalidState
	}
	return header, true, nil
}

func readHolder(holderFD int, name string) (HolderRecord, error) {
	document, exists, err := readPrivateFile(holderFD, name)
	if err != nil || !exists {
		return HolderRecord{}, ErrInvalidState
	}
	var record HolderRecord
	if err := decodeCanonical(document, &record); err != nil ||
		validateHolder(record) != nil ||
		holderRecordName(record.Identity) != name {
		return HolderRecord{}, ErrInvalidState
	}
	return record, nil
}

func readPrivateFile(dirFD int, name string) ([]byte, bool, error) {
	fd, err := unix.Openat(
		dirFD,
		name,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if errors.Is(err, syscall.ENOENT) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, ErrInvalidState
	}
	if _, err := fstatRegular(fd, 0o600); err != nil {
		_ = unix.Close(fd)
		return nil, false, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, false, ErrInvalidState
	}
	defer file.Close()
	reader := io.LimitReader(file, maxStateBytes+1)
	document, err := io.ReadAll(reader)
	if err != nil || len(document) > maxStateBytes {
		return nil, false, ErrInvalidState
	}
	return document, true, nil
}

func writeCanonicalAtomic(s *Store, dirFD int, name string, value any) error {
	document, err := canonicalBytes(value)
	if err != nil {
		return err
	}
	temp := s.nextTempName()
	fd, err := unix.Openat(
		dirFD,
		temp,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0o600,
	)
	if err != nil {
		return ErrInvalidState
	}
	cleanup := true
	open := true
	defer func() {
		if open {
			_ = unix.Close(fd)
		}
		if cleanup {
			_ = unix.Unlinkat(dirFD, temp, 0)
		}
	}()
	if err := unix.Fchmod(fd, 0o600); err != nil ||
		writeAll(fd, document) != nil ||
		unix.Fsync(fd) != nil {
		return ErrInvalidState
	}
	closeErr := unix.Close(fd)
	open = false
	if closeErr != nil {
		return ErrInvalidState
	}
	if err := unix.Renameat(dirFD, temp, dirFD, name); err != nil {
		return ErrInvalidState
	}
	cleanup = false
	if err := unix.Fsync(dirFD); err != nil {
		return ErrInvalidState
	}
	return nil
}

func createCanonicalExclusive(
	s *Store,
	dirFD int,
	name string,
	value any,
) error {
	document, err := canonicalBytes(value)
	if err != nil {
		return err
	}
	temp := s.nextTempName()
	fd, err := unix.Openat(
		dirFD,
		temp,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0o600,
	)
	if err != nil {
		return ErrInvalidState
	}
	cleanup := true
	open := true
	defer func() {
		if open {
			_ = unix.Close(fd)
		}
		if cleanup {
			_ = unix.Unlinkat(dirFD, temp, 0)
		}
	}()
	if err := unix.Fchmod(fd, 0o600); err != nil ||
		writeAll(fd, document) != nil ||
		unix.Fsync(fd) != nil {
		return ErrInvalidState
	}
	closeErr := unix.Close(fd)
	open = false
	if closeErr != nil {
		return ErrInvalidState
	}
	if err := unix.Linkat(dirFD, temp, dirFD, name, 0); err != nil {
		if errors.Is(err, syscall.EEXIST) {
			return ErrAuthorityConflict
		}
		return ErrInvalidState
	}
	if err := unix.Unlinkat(dirFD, temp, 0); err != nil ||
		unix.Fsync(dirFD) != nil {
		return ErrInvalidState
	}
	cleanup = false
	return nil
}

func (s *Store) nextTempName() string {
	return fmt.Sprintf(".tmp-%d-%d", os.Getpid(), s.tempSequence.Add(1))
}

func writeAll(fd int, document []byte) error {
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

func readAllHolders(holderFD int) ([]HolderRecord, error) {
	names, err := directoryNames(holderFD)
	if err != nil {
		return nil, err
	}
	records := make([]HolderRecord, 0, len(names))
	for _, name := range names {
		if strings.HasPrefix(name, ".tmp-") {
			return nil, ErrInvalidState
		}
		record, err := readHolder(holderFD, name)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		return holderRecordName(records[i].Identity) <
			holderRecordName(records[j].Identity)
	})
	return records, nil
}

func retireAllHolders(holderFD int) error {
	names, err := directoryNames(holderFD)
	if err != nil {
		return err
	}
	for _, name := range names {
		if strings.HasPrefix(name, ".tmp-") {
			document, exists, err := readPrivateFile(holderFD, name)
			if err != nil || !exists || len(document) > maxStateBytes {
				return ErrInvalidState
			}
		} else {
			if _, err := readHolder(holderFD, name); err != nil {
				return err
			}
		}
		if err := unix.Unlinkat(holderFD, name, 0); err != nil {
			return ErrInvalidState
		}
	}
	if err := unix.Fsync(holderFD); err != nil {
		return ErrInvalidState
	}
	remaining, err := directoryNames(holderFD)
	if err != nil || len(remaining) != 0 {
		return ErrInvalidState
	}
	return nil
}

func directoryNames(dirFD int) ([]string, error) {
	duplicate, err := unix.Openat(
		dirFD,
		".",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, ErrInvalidState
	}
	if _, err := fstatDirectory(duplicate); err != nil {
		_ = unix.Close(duplicate)
		return nil, err
	}
	file := os.NewFile(uintptr(duplicate), "fleetfence-dir")
	if file == nil {
		_ = unix.Close(duplicate)
		return nil, ErrInvalidState
	}
	entries, err := file.ReadDir(-1)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return nil, ErrInvalidState
	}
	names := make([]string, len(entries))
	for index, entry := range entries {
		if entry.Name() == "." || entry.Name() == ".." || entry.IsDir() {
			return nil, ErrInvalidState
		}
		names[index] = entry.Name()
	}
	sort.Strings(names)
	return names, nil
}

func unlinkAndSync(dirFD int, name string) error {
	if err := unix.Unlinkat(dirFD, name, 0); err != nil {
		return ErrInvalidState
	}
	if err := unix.Fsync(dirFD); err != nil {
		return ErrInvalidState
	}
	return nil
}

func flockContext(
	ctx context.Context,
	fd int,
	operation int,
	interval time.Duration,
) error {
	for {
		err := unix.Flock(fd, operation|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) &&
			!errors.Is(err, syscall.EAGAIN) {
			return ErrInvalidState
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func unlockFD(fd int) error {
	if fd < 0 {
		return nil
	}
	return unix.Flock(fd, unix.LOCK_UN)
}

func closeFD(fd int) error {
	if fd < 0 {
		return nil
	}
	return unix.Close(fd)
}

func duplicateCloseOnExec(fd int) (int, error) {
	duplicate, err := unix.Dup(fd)
	if err != nil {
		return -1, err
	}
	unix.CloseOnExec(duplicate)
	return duplicate, nil
}

func unlockAndClose(fd int) error {
	return errors.Join(unlockFD(fd), closeFD(fd))
}
