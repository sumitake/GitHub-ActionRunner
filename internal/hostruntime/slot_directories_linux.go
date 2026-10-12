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
// process's user with mode 0700. The slot directory may already exist,
// because cleanup keeps it when it removes relay and authority, but must then
// have the same owner and mode. The
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
	rootFD, err := unix.Open(brokerRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errSlotDirectories
	}
	defer unix.Close(rootFD)
	root, err := privateDirectoryStat(rootFD, owner, owner, false)
	if err != nil {
		return errSlotDirectories
	}

	if err := unix.Mkdirat(rootFD, slotIdentity, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return errSlotDirectories
	}
	slotFD, err := openBeneath(rootFD, slotIdentity)
	if err != nil {
		return errSlotDirectories
	}
	defer unix.Close(slotFD)
	slot, err := privateDirectoryStat(slotFD, owner, 0, false)
	if err != nil || slot.Dev != root.Dev {
		return errSlotDirectories
	}

	var created []string
	for _, name := range slotChildDirectories {
		made, err := createBrokerDirectory(slotFD, name, brokerUID, brokerGID, root.Dev)
		if made {
			created = append(created, name)
		}
		if err != nil {
			for index := len(created) - 1; index >= 0; index-- {
				_ = unix.Unlinkat(slotFD, created[index], unix.AT_REMOVEDIR)
			}
			_ = unix.Fsync(slotFD)
			return errSlotDirectories
		}
	}
	return nil
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
