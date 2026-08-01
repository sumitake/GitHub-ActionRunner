package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/sumitake/portable-ghar/internal/runtimelock"
	"golang.org/x/sys/unix"
)

const maxTreeLockBytes = 32 << 20

type listenerIdentity struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   uint64 `json:"size"`
	Mode   uint32 `json:"mode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
}

var lowerHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func verifyListener(want listenerIdentity) (*os.File, error) {
	if !filepath.IsAbs(want.Path) || filepath.Clean(want.Path) != want.Path || strings.IndexByte(want.Path, 0) >= 0 ||
		!lowerHex64.MatchString(want.SHA256) || want.Size == 0 || want.Mode != 0o555 {
		return nil, errors.New("runner-gate: listener expectation invalid")
	}
	resolved, err := filepath.EvalSymlinks(want.Path)
	if err != nil || resolved != want.Path {
		return nil, errors.New("runner-gate: listener path indirect")
	}
	fd, err := unix.Open(want.Path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("runner-gate: listener open failed")
	}
	file := os.NewFile(uintptr(fd), "verified-listener")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("runner-gate: listener descriptor invalid")
	}
	before, err := gateFstat(file)
	if err != nil || uint32(before.Mode)&unix.S_IFMT != unix.S_IFREG || uint32(before.Mode)&0o777 != want.Mode || before.Uid != want.UID || before.Gid != want.GID || before.Size < 0 || uint64(before.Size) != want.Size {
		file.Close()
		return nil, errors.New("runner-gate: listener identity differs")
	}
	hash := sha256.New()
	count, hashErr := io.Copy(hash, io.LimitReader(file, before.Size+1))
	after, afterErr := gateFstat(file)
	if hashErr != nil || afterErr != nil || count != before.Size || !stableGateStat(before, after) || hex.EncodeToString(hash.Sum(nil)) != want.SHA256 {
		file.Close()
		return nil, errors.New("runner-gate: listener content differs")
	}
	return file, nil
}

func gateFstat(file *os.File) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if file == nil || unix.Fstat(int(file.Fd()), &stat) != nil {
		return stat, errors.New("runner-gate: listener fstat failed")
	}
	return stat, nil
}

func stableGateStat(a, b unix.Stat_t) bool {
	return uint64(a.Dev) == uint64(b.Dev) && a.Ino == b.Ino && a.Nlink == b.Nlink &&
		a.Size == b.Size && uint32(a.Mode) == uint32(b.Mode) && a.Uid == b.Uid && a.Gid == b.Gid &&
		a.Mtim.Sec == b.Mtim.Sec && a.Mtim.Nsec == b.Mtim.Nsec && a.Ctim.Sec == b.Ctim.Sec && a.Ctim.Nsec == b.Ctim.Nsec
}

func loadGateRuntimeLock(lockPath, treePath string) (listenerIdentity, error) {
	lockData, err := readLockedFile(lockPath, 64<<10)
	if err != nil {
		return listenerIdentity{}, err
	}
	defer zero(lockData)
	lock, err := runtimelock.Load(bytes.NewReader(lockData))
	if err != nil {
		return listenerIdentity{}, errors.New("runner-gate: runtime lock invalid")
	}
	treeData, err := readLockedFile(treePath, maxTreeLockBytes)
	if err != nil {
		return listenerIdentity{}, err
	}
	defer zero(treeData)
	treeDigest := sha256.Sum256(treeData)
	if hex.EncodeToString(treeDigest[:]) != lock.TreeLockSHA256 {
		return listenerIdentity{}, errors.New("runner-gate: tree lock digest differs")
	}
	entry, err := parseListenerTreeEntry(treeData)
	if err != nil || entry.Path != lock.Listener.Path || entry.SHA256 != lock.Listener.SHA256 || entry.Size != lock.Listener.Size || entry.Mode != lock.Listener.Mode {
		return listenerIdentity{}, errors.New("runner-gate: listener tree entry differs")
	}
	entry.UID = lock.Listener.UID
	entry.GID = lock.Listener.GID
	return entry, nil
}

func readLockedFile(path string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || limit <= 0 {
		return nil, errors.New("runner-gate: lock path invalid")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return nil, errors.New("runner-gate: lock path indirect")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("runner-gate: lock open failed")
	}
	file := os.NewFile(uintptr(fd), "runtime-lock-input")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("runner-gate: lock descriptor invalid")
	}
	defer file.Close()
	before, err := gateFstat(file)
	if err != nil || uint32(before.Mode)&unix.S_IFMT != unix.S_IFREG || uint32(before.Mode)&0o777 != 0o444 || before.Nlink != 1 || before.Size <= 0 || before.Size > limit {
		return nil, errors.New("runner-gate: lock identity invalid")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	after, afterErr := gateFstat(file)
	if err != nil || afterErr != nil || int64(len(data)) != before.Size || !stableGateStat(before, after) {
		zero(data)
		return nil, errors.New("runner-gate: lock changed during read")
	}
	return data, nil
}

func parseListenerTreeEntry(data []byte) (listenerIdentity, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	if !scanner.Scan() || scanner.Text() != "PGHAR-RUNNER-TREE-LOCK-V1" {
		return listenerIdentity{}, errors.New("runner-gate: tree lock header invalid")
	}
	var listener listenerIdentity
	count := 0
	entries := make(map[string]byte)
	type treeLink struct {
		name   string
		target string
	}
	var links []treeLink
	lastPath := ""
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, "\t")
		if len(fields) < 3 || len(fields[0]) != 1 ||
			(fields[0] != "D" && fields[0] != "F" && fields[0] != "L") ||
			!validRunnerTreePath(fields[1]) || fields[1] <= lastPath ||
			len(entries) >= 16_384 {
			return listenerIdentity{}, errors.New("runner-gate: tree lock line invalid")
		}
		lastPath = fields[1]
		kind := fields[0][0]
		entries[fields[1]] = kind
		switch kind {
		case 'D':
			if len(fields) != 3 {
				return listenerIdentity{}, errors.New("runner-gate: tree directory line invalid")
			}
			mode, modeErr := strconv.ParseUint(fields[2], 8, 32)
			if modeErr != nil || mode != 0o555 || fields[2] != "0555" {
				return listenerIdentity{}, errors.New("runner-gate: tree directory identity invalid")
			}
		case 'F':
			if len(fields) != 5 {
				return listenerIdentity{}, errors.New("runner-gate: tree file line invalid")
			}
			mode, modeErr := strconv.ParseUint(fields[2], 8, 32)
			size, sizeErr := strconv.ParseUint(fields[3], 10, 64)
			if modeErr != nil || (mode != 0o444 && mode != 0o555) ||
				(fields[2] != "0444" && fields[2] != "0555") ||
				sizeErr != nil || strconv.FormatUint(size, 10) != fields[3] ||
				!lowerHex64.MatchString(fields[4]) {
				return listenerIdentity{}, errors.New("runner-gate: tree file identity invalid")
			}
			if fields[1] == "bin/Runner.Listener" {
				count++
				listener = listenerIdentity{
					Path: "/opt/actions-runner/bin/Runner.Listener", SHA256: fields[4], Size: size, Mode: uint32(mode),
				}
			}
		case 'L':
			if len(fields) != 6 || fields[2] != "0000" || !validRunnerTreeLink(fields[5]) {
				return listenerIdentity{}, errors.New("runner-gate: tree symlink line invalid")
			}
			size, sizeErr := strconv.ParseUint(fields[3], 10, 64)
			digest := sha256.Sum256([]byte(fields[5]))
			if sizeErr != nil || size == 0 || strconv.FormatUint(size, 10) != fields[3] ||
				size != uint64(len(fields[5])) || !lowerHex64.MatchString(fields[4]) ||
				hex.EncodeToString(digest[:]) != fields[4] {
				return listenerIdentity{}, errors.New("runner-gate: tree symlink identity invalid")
			}
			links = append(links, treeLink{name: fields[1], target: fields[5]})
		}
	}
	if scanner.Err() != nil || count != 1 || listener.Size == 0 || listener.Mode != 0o555 {
		return listenerIdentity{}, errors.New("runner-gate: listener tree entry missing or ambiguous")
	}
	for _, link := range links {
		resolved := path.Clean(path.Join(path.Dir(link.name), link.target))
		if resolved == "." || resolved == ".." || strings.HasPrefix(resolved, "../") || entries[resolved] != 'F' {
			return listenerIdentity{}, errors.New("runner-gate: tree symlink target invalid")
		}
	}
	return listener, nil
}

func validRunnerTreePath(value string) bool {
	if value == "" || len(value) > 512 || strings.HasPrefix(value, "/") ||
		strings.ContainsAny(value, "\\\x00") || path.Clean(value) != value ||
		value == "." || value == ".." || strings.HasPrefix(value, "../") ||
		!printableASCII(value) {
		return false
	}
	parts := strings.Split(value, "/")
	if parts[0] != "bin" && parts[0] != "externals" {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func validRunnerTreeLink(value string) bool {
	return value != "" && len(value) <= 512 && !strings.HasPrefix(value, "/") &&
		!strings.ContainsAny(value, "\\\x00") && path.Clean(value) == value &&
		value != "." && printableASCII(value)
}

func printableASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] > 0x7e {
			return false
		}
	}
	return true
}
