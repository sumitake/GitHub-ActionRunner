//go:build integration && linux

package testenv

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const maximumConformanceInputBytes = int64(1 << 20)

type inputDirectoryIdentity struct {
	device uint64
	inode  uint64
	mode   uint32
	uid    uint32
	gid    uint32
	nlink  uint64
}

type linuxInputLeaseOperations struct {
	parent         *os.File
	input          *os.File
	basename       string
	parentIdentity inputDirectoryIdentity
	inputIdentity  inputFileIdentity
}

func acquireConformanceInputLease(
	path string,
	options ConformanceInputReadOptions,
) (*conformanceInputLease, error) {
	if !validInputReadOptions(path, options) {
		return nil, ErrConformanceInputFile
	}
	parentPath := filepath.Dir(path)
	basename := filepath.Base(path)
	if basename == "." || basename == string(filepath.Separator) ||
		basename == "" || strings.ContainsRune(basename, filepath.Separator) {
		return nil, ErrConformanceInputFile
	}

	rootFD, err := unix.Open(
		string(filepath.Separator),
		unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, ErrConformanceInputFile
	}
	defer unix.Close(rootFD)
	parentRelative := strings.TrimPrefix(parentPath, string(filepath.Separator))
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
		return nil, ErrConformanceInputFile
	}
	parent := os.NewFile(uintptr(parentFD), "conformance-input-parent")
	if parent == nil {
		_ = unix.Close(parentFD)
		return nil, ErrConformanceInputFile
	}
	closeParent := true
	defer func() {
		if closeParent {
			_ = parent.Close()
		}
	}()
	parentIdentity, err := inputDirectoryIdentityFromFD(parentFD)
	if err != nil || !localPOSIXDirectory(parentFD, parentIdentity) {
		return nil, ErrConformanceInputFile
	}

	inputFD, err := unix.Openat2(parentFD, basename, &unix.OpenHow{
		Flags: uint64(
			unix.O_RDONLY |
				unix.O_CLOEXEC |
				unix.O_NONBLOCK,
		),
		Resolve: uint64(
			unix.RESOLVE_BENEATH |
				unix.RESOLVE_NO_MAGICLINKS |
				unix.RESOLVE_NO_SYMLINKS,
		),
	})
	if err != nil {
		return nil, ErrConformanceInputFile
	}
	input := os.NewFile(uintptr(inputFD), "conformance-input")
	if input == nil {
		_ = unix.Close(inputFD)
		return nil, ErrConformanceInputFile
	}
	closeInput := true
	defer func() {
		if closeInput {
			_ = input.Close()
		}
	}()
	if err := unix.Flock(inputFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) ||
			errors.Is(err, unix.EAGAIN) {
			return nil, ErrAuthorizationInUse
		}
		return nil, ErrConformanceInputFile
	}
	unlock := true
	defer func() {
		if unlock {
			_ = unix.Flock(inputFD, unix.LOCK_UN)
		}
	}()

	before, err := inputIdentityFromFD(inputFD)
	if err != nil ||
		!validOpenedInputIdentity(before, options) ||
		before.device != parentIdentity.device {
		return nil, ErrConformanceInputFile
	}
	pathIdentity, err := inputIdentityFromAt(parentFD, basename)
	if err != nil || pathIdentity != before {
		return nil, ErrConformanceInputFile
	}
	if options.afterOpen != nil {
		options.afterOpen()
	}
	document, err := io.ReadAll(
		io.LimitReader(input, options.MaximumBytes+1),
	)
	if err != nil ||
		int64(len(document)) != before.size ||
		int64(len(document)) > options.MaximumBytes {
		zeroLeaseBytes(document)
		return nil, ErrConformanceInputFile
	}
	defer zeroLeaseBytes(document)
	if options.afterRead != nil {
		options.afterRead()
	}
	after, err := inputIdentityFromFD(inputFD)
	if err != nil || after != before {
		return nil, ErrConformanceInputFile
	}
	pathIdentity, err = inputIdentityFromAt(parentFD, basename)
	if err != nil || pathIdentity != before {
		return nil, ErrConformanceInputFile
	}
	inputValue, err := parseConformanceInput(document)
	if err != nil {
		return nil, err
	}
	if err := validateConformanceInput(
		inputValue,
		options.Now().UTC(),
		options.Usage,
	); err != nil {
		return nil, err
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(inputDigestDomain))
	_, _ = digest.Write(document)
	parsed := ParsedConformanceInput{
		Input:    inputValue,
		Document: append([]byte(nil), document...),
		Digest:   hex.EncodeToString(digest.Sum(nil)),
	}
	operations := &linuxInputLeaseOperations{
		parent:         parent,
		input:          input,
		basename:       basename,
		parentIdentity: parentIdentity,
		inputIdentity:  before,
	}
	lease, err := newConformanceInputLease(parsed, operations)
	zeroLeaseBytes(parsed.Document)
	if err != nil {
		return nil, err
	}
	unlock = false
	closeInput = false
	closeParent = false
	return lease, nil
}

func (o *linuxInputLeaseOperations) Revalidate() error {
	if o == nil || o.parent == nil || o.input == nil ||
		o.basename == "" {
		return ErrAuthorizationLease
	}
	parent, err := inputDirectoryIdentityFromFD(int(o.parent.Fd()))
	if err != nil || parent != o.parentIdentity {
		return ErrAuthorizationLease
	}
	input, err := inputIdentityFromFD(int(o.input.Fd()))
	if err != nil || input != o.inputIdentity {
		return ErrAuthorizationLease
	}
	path, err := inputIdentityFromAt(int(o.parent.Fd()), o.basename)
	if err != nil || path != o.inputIdentity {
		return ErrAuthorizationLease
	}
	return nil
}

func (o *linuxInputLeaseOperations) Unlink() error {
	if o == nil || o.parent == nil || o.basename == "" {
		return ErrAuthorizationLease
	}
	if err := unix.Unlinkat(
		int(o.parent.Fd()),
		o.basename,
		0,
	); err != nil {
		return ErrAuthorizationLease
	}
	return nil
}

func (o *linuxInputLeaseOperations) SyncParent() error {
	if o == nil || o.parent == nil {
		return ErrAuthorizationConsumedRunAborted
	}
	if err := unix.Fsync(int(o.parent.Fd())); err != nil {
		return ErrAuthorizationConsumedRunAborted
	}
	return nil
}

func (o *linuxInputLeaseOperations) ProveAbsent() error {
	if o == nil || o.parent == nil || o.basename == "" {
		return ErrAuthorizationConsumedRunAborted
	}
	var stat unix.Stat_t
	err := unix.Fstatat(
		int(o.parent.Fd()),
		o.basename,
		&stat,
		unix.AT_SYMLINK_NOFOLLOW,
	)
	if !errors.Is(err, unix.ENOENT) {
		return ErrAuthorizationConsumedRunAborted
	}
	return nil
}

func (o *linuxInputLeaseOperations) Close() error {
	if o == nil {
		return ErrAuthorizationLease
	}
	var failed bool
	if o.input != nil {
		if err := unix.Flock(int(o.input.Fd()), unix.LOCK_UN); err != nil {
			failed = true
		}
		if err := o.input.Close(); err != nil {
			failed = true
		}
		o.input = nil
	}
	if o.parent != nil {
		if err := o.parent.Close(); err != nil {
			failed = true
		}
		o.parent = nil
	}
	if failed {
		return ErrAuthorizationLease
	}
	return nil
}

func inputDirectoryIdentityFromFD(
	fd int,
) (inputDirectoryIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return inputDirectoryIdentity{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		stat.Dev == 0 ||
		stat.Ino == 0 ||
		stat.Nlink == 0 {
		return inputDirectoryIdentity{}, ErrConformanceInputFile
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

func inputIdentityFromAt(
	parentFD int,
	basename string,
) (inputFileIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(
		parentFD,
		basename,
		&stat,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return inputFileIdentity{}, err
	}
	return normalizeInputIdentity(stat), nil
}

func localPOSIXDirectory(
	fd int,
	identity inputDirectoryIdentity,
) bool {
	if identity.device == 0 || identity.inode == 0 {
		return false
	}
	var stat unix.Statfs_t
	if unix.Fstatfs(fd, &stat) != nil {
		return false
	}
	switch uint64(stat.Type) {
	case unix.EXT4_SUPER_MAGIC,
		unix.TMPFS_MAGIC,
		unix.XFS_SUPER_MAGIC,
		unix.BTRFS_SUPER_MAGIC:
		return true
	default:
		return false
	}
}

func zeroLeaseBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
