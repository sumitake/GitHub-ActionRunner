//go:build linux

package hostruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type linuxProcessStartObserver struct {
	procRoot string
}

func ObserveLinuxProcessStartIdentity(
	pid uint64,
) (ProcessStartObservation, string, error) {
	return ObserveStableProcessStartIdentity(
		linuxProcessStartObserver{procRoot: "/proc"},
		pid,
	)
}

func (observer linuxProcessStartObserver) ObserveProcessStart(
	pid uint64,
) (ProcessStartObservation, error) {
	if pid == 0 || observer.procRoot == "" {
		return ProcessStartObservation{}, ErrProcessIdentityUnavailable
	}
	pidComponent := strconv.FormatUint(pid, 10)
	bootDocument, err := os.ReadFile(
		filepath.Join(observer.procRoot, "sys/kernel/random/boot_id"),
	)
	if err != nil {
		return ProcessStartObservation{}, ErrProcessIdentityUnavailable
	}
	bootID := strings.TrimSuffix(string(bootDocument), "\n")
	if !validCanonicalBootID(bootID) ||
		string(bootDocument) != bootID+"\n" {
		return ProcessStartObservation{}, ErrProcessIdentityUnavailable
	}
	namespaceInfo, err := os.Stat(
		filepath.Join(observer.procRoot, pidComponent, "ns/pid"),
	)
	if err != nil {
		return ProcessStartObservation{}, ErrProcessIdentityUnavailable
	}
	namespaceStat, ok := namespaceInfo.Sys().(*syscall.Stat_t)
	if !ok || namespaceStat.Ino == 0 {
		return ProcessStartObservation{}, ErrProcessIdentityUnavailable
	}
	statDocument, err := os.ReadFile(
		filepath.Join(observer.procRoot, pidComponent, "stat"),
	)
	if err != nil {
		return ProcessStartObservation{}, ErrProcessIdentityUnavailable
	}
	statDocument = []byte(strings.TrimSuffix(string(statDocument), "\n"))
	startTime, err := ParseLinuxProcStatStartTime(statDocument)
	if err != nil {
		return ProcessStartObservation{}, err
	}
	executable, err := os.Open(
		filepath.Join(observer.procRoot, pidComponent, "exe"),
	)
	if err != nil {
		return ProcessStartObservation{}, ErrProcessIdentityUnavailable
	}
	defer executable.Close()
	before, err := executable.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 0 {
		return ProcessStartObservation{}, ErrProcessIdentityUnavailable
	}
	beforeStat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || beforeStat.Dev == 0 || beforeStat.Ino == 0 {
		return ProcessStartObservation{}, ErrProcessIdentityUnavailable
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, executable); err != nil {
		return ProcessStartObservation{}, ErrProcessIdentityUnavailable
	}
	after, err := executable.Stat()
	if err != nil {
		return ProcessStartObservation{}, ErrProcessIdentityUnavailable
	}
	afterStat, ok := after.Sys().(*syscall.Stat_t)
	if !ok ||
		afterStat.Dev != beforeStat.Dev ||
		afterStat.Ino != beforeStat.Ino ||
		after.Size() != before.Size() {
		return ProcessStartObservation{}, ErrProcessIdentityUnavailable
	}
	return ProcessStartObservation{
		BootID:             bootID,
		PIDNamespaceInode:  namespaceStat.Ino,
		PID:                pid,
		StartTimeTicks:     startTime,
		ExecutableDigest:   hex.EncodeToString(hasher.Sum(nil)),
		ExecutableDevice:   uint64(beforeStat.Dev),
		ExecutableInode:    beforeStat.Ino,
		ExecutableFileSize: uint64(before.Size()),
	}, nil
}
