//go:build linux

package hostruntime

import (
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

var errSlotDirectories = errors.New("hostruntime: slot directories unavailable")

// slotChildDirectories are created fresh for every job, in this order.
var slotChildDirectories = []string{"relay", "authority"}

// CreateSlotDirectories creates <brokerRoot>/<slotIdentity>/relay and
// .../authority for one job. brokerRoot must be a directory owned by this
// process's user with mode 0700. The slot directory may already exist, for
// example after an interrupted cleanup, but must then have the same owner and
// mode; cleanup removes it once it is empty. The
// relay and authority directories must not exist; a leftover means cleanup
// did not finish, so the call fails rather than reuse it. Both are created
// empty, owned by the broker user, mode 0700. Every path is resolved beneath
// brokerRoot without following symlinks or crossing mounts. On failure the
// call removes the directories it created.
func CreateSlotDirectories(brokerRoot, slotIdentity string, brokerUID, brokerGID uint32) error {
	if brokerUID == 0 || !validSlotDirectoryName(slotIdentity) {
		return errSlotDirectories
	}
	owner := uint32(os.Geteuid())
	rootFD, root, err := openBrokerRoot(brokerRoot)
	if err != nil {
		return errSlotDirectories
	}
	defer unix.Close(rootFD)

	slotCreated := false
	if err := unix.Mkdirat(rootFD, slotIdentity, 0o700); err == nil {
		slotCreated = true
	} else if !errors.Is(err, unix.EEXIST) {
		return errSlotDirectories
	}
	// rollback removes only what this call created, the slot directory last.
	var created []string
	rollback := func(slotFD int) error {
		if slotFD >= 0 {
			for index := len(created) - 1; index >= 0; index-- {
				_ = unix.Unlinkat(slotFD, created[index], unix.AT_REMOVEDIR)
			}
			_ = unix.Fsync(slotFD)
		}
		if slotCreated {
			_ = unix.Unlinkat(rootFD, slotIdentity, unix.AT_REMOVEDIR)
			_ = unix.Fsync(rootFD)
		}
		return errSlotDirectories
	}
	// Make a new slot entry durable before anything is created inside it.
	if slotCreated && unix.Fsync(rootFD) != nil {
		return rollback(-1)
	}
	slotFD, err := openBeneath(rootFD, slotIdentity)
	if err != nil {
		return rollback(-1)
	}
	defer unix.Close(slotFD)
	slot, err := privateDirectoryStat(slotFD, owner, 0, false)
	if err != nil || slot.Dev != root.Dev {
		return rollback(slotFD)
	}
	for _, name := range slotChildDirectories {
		made, err := createBrokerDirectory(slotFD, name, brokerUID, brokerGID, root.Dev)
		if made {
			created = append(created, name)
		}
		if err != nil {
			return rollback(slotFD)
		}
	}
	return nil
}

// openBrokerRoot opens the broker root the same way the quiescence proof
// does: one component at a time without following any symlink, ending in a
// 0700 directory owned by this process's user.
func openBrokerRoot(path string) (int, unix.Stat_t, error) {
	fd, _, err := openLifecycleAbsoluteDirectory(path)
	if err != nil {
		return -1, unix.Stat_t{}, errSlotDirectories
	}
	owner := uint32(os.Geteuid())
	stat, err := privateDirectoryStat(fd, owner, 0, false)
	if err != nil {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, errSlotDirectories
	}
	return fd, stat, nil
}

// RemoveEmptySlotDirectories undoes CreateSlotDirectories after a failed
// prepare. It removes authority, relay and then the slot directory, and fsyncs
// the broker root. rmdir refuses a directory that holds anything, so whatever a
// started broker or adapter left there stays in place and the call fails: a
// slot that remains blocks broker-root quiescence and needs an operator.
// Directories already gone are not an error.
func RemoveEmptySlotDirectories(brokerRoot, slotIdentity string) error {
	if !validSlotDirectoryName(slotIdentity) {
		return errSlotDirectories
	}
	rootFD, _, err := openBrokerRoot(brokerRoot)
	if err != nil {
		return errSlotDirectories
	}
	defer unix.Close(rootFD)
	slotFD, err := openBeneath(rootFD, slotIdentity)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return errSlotDirectories
	}
	defer unix.Close(slotFD)
	for index := len(slotChildDirectories) - 1; index >= 0; index-- {
		if err := removeEmptyDirectory(slotFD, slotChildDirectories[index]); err != nil {
			return err
		}
	}
	if err := removeEmptyDirectory(rootFD, slotIdentity); err != nil {
		return err
	}
	if unix.Fsync(rootFD) != nil {
		return errSlotDirectories
	}
	return nil
}

// maxBrokerRootEntries bounds the startup listing of the broker root, which
// holds at most one directory per capacity slot.
const maxBrokerRootEntries = 4096

// RemoveUnreferencedSlotDirectories removes, at startup and before any work
// is admitted, every slot directory under brokerRoot whose name is not in
// referenced. A crash between an assignment's terminal record and its
// directory cleanup leaves such a slot behind. Each removal is
// RemoveEmptySlotDirectories, so a slot that still holds anything stays in
// place and the call fails.
func RemoveUnreferencedSlotDirectories(brokerRoot string, referenced map[string]bool) error {
	rootFD, _, err := openBrokerRoot(brokerRoot)
	if err != nil {
		return errSlotDirectories
	}
	duplicate, err := unix.Dup(rootFD)
	unix.Close(rootFD)
	if err != nil {
		return errSlotDirectories
	}
	directory := os.NewFile(uintptr(duplicate), "broker-root")
	names, err := directory.Readdirnames(maxBrokerRootEntries + 1)
	directory.Close()
	if (err != nil && !errors.Is(err, io.EOF)) || len(names) > maxBrokerRootEntries {
		return errSlotDirectories
	}
	for _, name := range names {
		if referenced[name] {
			continue
		}
		if err := RemoveEmptySlotDirectories(brokerRoot, name); err != nil {
			return err
		}
	}
	return nil
}

func removeEmptyDirectory(parentFD int, name string) error {
	err := unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
	if err == nil || errors.Is(err, unix.ENOENT) {
		return nil
	}
	return errSlotDirectories
}

// createBrokerDirectory reports whether it created name, so a failed call
// removes only what it made.
func createBrokerDirectory(parentFD int, name string, uid, gid uint32, device uint64) (bool, error) {
	if err := unix.Mkdirat(parentFD, name, 0o700); err != nil {
		return false, errSlotDirectories
	}
	childFD, err := openBeneath(parentFD, name)
	if err != nil {
		return true, errSlotDirectories
	}
	defer unix.Close(childFD)
	if unix.Fchown(childFD, int(uid), int(gid)) != nil ||
		unix.Fchmod(childFD, 0o700) != nil ||
		unix.Fsync(childFD) != nil ||
		unix.Fsync(parentFD) != nil {
		return true, errSlotDirectories
	}
	child, err := privateDirectoryStat(childFD, uid, gid, true)
	if err != nil || child.Dev != device || !directoryEmpty(childFD) {
		return true, errSlotDirectories
	}
	return true, nil
}

func openBeneath(parentFD int, name string) (int, error) {
	return unix.Openat2(parentFD, name, &unix.OpenHow{
		Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: uint64(unix.RESOLVE_BENEATH |
			unix.RESOLVE_NO_MAGICLINKS |
			unix.RESOLVE_NO_SYMLINKS |
			unix.RESOLVE_NO_XDEV),
	})
}

// privateDirectoryStat requires a directory with mode 0700 owned by uid, and
// by gid when checkGroup is set.
func privateDirectoryStat(fd int, uid, gid uint32, checkGroup bool) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil ||
		stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		stat.Mode&0o7777 != 0o700 ||
		stat.Uid != uid ||
		(checkGroup && stat.Gid != gid) {
		return unix.Stat_t{}, errSlotDirectories
	}
	return stat, nil
}

// directoryEmpty reads through a duplicate so closing it leaves fd open.
func directoryEmpty(fd int) bool {
	duplicate, err := unix.Dup(fd)
	if err != nil {
		return false
	}
	directory := os.NewFile(uintptr(duplicate), "slot-directory")
	if directory == nil {
		_ = unix.Close(duplicate)
		return false
	}
	defer directory.Close()
	names, err := directory.Readdirnames(1)
	return len(names) == 0 && errors.Is(err, io.EOF)
}

func validSlotDirectoryName(name string) bool {
	return name != "" && name != "." && name != ".." &&
		!strings.ContainsAny(name, "/\x00")
}
