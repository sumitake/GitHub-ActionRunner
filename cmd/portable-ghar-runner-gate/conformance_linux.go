//go:build linux

package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/sumitake/portable-ghar/internal/linuxcap"
	"github.com/sumitake/portable-ghar/internal/networkjail"
	"github.com/sumitake/portable-ghar/internal/runtimeenv"
	"golang.org/x/sys/unix"
)

const maxRunnerProcDocument = 1 << 20

var runnerMaskedProcPaths = []string{
	"/proc/acpi",
	"/proc/kcore",
	"/proc/keys",
	"/proc/latency_stats",
	"/proc/scsi",
	"/proc/timer_list",
	"/proc/timer_stats",
	"/sys/firmware",
}

var runnerControllerDatabasePaths = []string{
	"/run/portable-ghar/controller.sqlite",
	"/var/lib/portable-ghar/controller.db",
	"/var/lib/portable-ghar/controller.sqlite",
}

var runnerDockerAuthorityPaths = []string{
	"/run/docker.sock",
	"/var/run/docker.sock",
}

var runnerHostControlPaths = []string{
	"/dev/kvm",
	"/dev/mem",
	"/run/portable-ghar/host-control",
}

var runnerSecretPaths = []string{
	"/root/.docker/config.json",
	"/run/secrets",
	"/runner/.docker/config.json",
	"/var/run/secrets",
}

var runnerSyntheticTokenPaths = []string{
	"/run/portable-ghar/synthetic-token",
	"/runner/.portable-ghar/synthetic-token",
}

func defaultRunnerConformance() (runnerConformanceWire, error) {
	return observeRunnerConformance(runnerConformanceProbeRuntime{
		identity: func() (uint64, uint64, error) {
			return uint64(os.Geteuid()), uint64(os.Getegid()), nil
		},
		capabilities: linuxcap.ReadSelf,
		namespace:    inspectRunnerNetworkNamespace,
		rawSocket:    probeRunnerRawSocket,
		bpf:          probeRunnerBPF,
		unshare:      probeRunnerUnshare,
		setns:        probeRunnerSetNS,
		clone3:       probeRunnerClone3,
		proc:         inspectRunnerProcFacts,
		projections:  inspectRunnerProjectionFacts,
	})
}

func inspectRunnerNetworkNamespace() (networkjail.NamespaceIdentity, error) {
	var stat unix.Stat_t
	if unix.Lstat("/proc/self/ns/net", &stat) != nil ||
		uint32(stat.Mode)&unix.S_IFMT != unix.S_IFLNK ||
		uint64(stat.Dev) == 0 ||
		stat.Ino == 0 {
		return networkjail.NamespaceIdentity{}, errRunnerConformance
	}
	return networkjail.NamespaceIdentity{
		Device: uint64(stat.Dev),
		Inode:  stat.Ino,
	}, nil
}

func probeRunnerRawSocket() error {
	descriptor, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_RAW|unix.SOCK_CLOEXEC,
		unix.IPPROTO_ICMP,
	)
	if err == nil {
		_ = unix.Close(descriptor)
	}
	return err
}

func probeRunnerBPF() error {
	_, _, errno := unix.RawSyscall6(
		unix.SYS_BPF,
		uintptr(unix.BPF_MAP_CREATE),
		0,
		0,
		0,
		0,
		0,
	)
	if errno == 0 {
		return nil
	}
	return errno
}

func probeRunnerUnshare() error {
	return unix.Unshare(unix.CLONE_NEWNET)
}

func probeRunnerSetNS() error {
	file, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return err
	}
	defer file.Close()
	return unix.Setns(int(file.Fd()), unix.CLONE_NEWNET)
}

func probeRunnerClone3() error {
	_, _, errno := unix.RawSyscall(
		unix.SYS_CLONE3,
		0,
		0,
		0,
	)
	if errno == 0 {
		return nil
	}
	return errno
}

func inspectRunnerProcFacts() (runnerProcFacts, error) {
	document, err := readRunnerProcDocument("/proc/self/mountinfo")
	if err != nil {
		return runnerProcFacts{}, errRunnerConformance
	}
	defer zero(document)
	mounts := make(map[string][]string)
	for _, line := range bytes.Split(bytes.TrimSuffix(document, []byte{'\n'}), []byte{'\n'}) {
		fields := strings.Fields(string(line))
		if len(fields) < 10 || fields[4] == "" {
			return runnerProcFacts{}, errRunnerConformance
		}
		if _, duplicate := mounts[fields[4]]; duplicate {
			return runnerProcFacts{}, errRunnerConformance
		}
		mounts[fields[4]] = strings.Split(fields[5], ",")
	}
	sysOptions, found := mounts["/proc/sys"]
	if !found || !slicesContain(sysOptions, "ro") ||
		!runnerPathIsDirect("/proc/sys") {
		return runnerProcFacts{}, errRunnerConformance
	}
	for _, path := range runnerMaskedProcPaths {
		if _, found := mounts[path]; !found || !runnerPathIsDirect(path) {
			return runnerProcFacts{}, errRunnerConformance
		}
	}
	return runnerProcFacts{SysReadOnly: true, MasksPresent: true}, nil
}

func inspectRunnerProjectionFacts() (runnerProjectionFacts, error) {
	environment := os.Environ()
	if !runtimeenv.MatchesImage(environment) {
		for index := range environment {
			environment[index] = ""
		}
		return runnerProjectionFacts{}, errRunnerConformance
	}
	for index := range environment {
		environment[index] = ""
	}
	facts := runnerProjectionFacts{
		ControllerDatabaseAbsent: runnerPathsAbsent(
			runnerControllerDatabasePaths,
		),
		DockerAuthorityAbsent: runnerPathsAbsent(
			runnerDockerAuthorityPaths,
		),
		HostControlAbsent: runnerPathsAbsent(
			runnerHostControlPaths,
		),
		SecretEnvironmentAbsent: true,
		JITEnvironmentAbsent:    true,
		SyntheticTokenAbsent: runnerPathsAbsent(
			runnerSyntheticTokenPaths,
		),
	}
	if !runnerPathsAbsent(runnerSecretPaths) {
		return runnerProjectionFacts{}, errRunnerConformance
	}
	if !facts.ControllerDatabaseAbsent ||
		!facts.DockerAuthorityAbsent ||
		!facts.HostControlAbsent ||
		!facts.SyntheticTokenAbsent {
		return runnerProjectionFacts{}, errRunnerConformance
	}
	return facts, nil
}

func readRunnerProcDocument(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errRunnerConformance
	}
	document, readErr := io.ReadAll(
		io.LimitReader(file, maxRunnerProcDocument+1),
	)
	closeErr := file.Close()
	if readErr != nil ||
		closeErr != nil ||
		len(document) == 0 ||
		len(document) > maxRunnerProcDocument ||
		document[len(document)-1] != '\n' {
		zero(document)
		return nil, errRunnerConformance
	}
	return document, nil
}

func runnerPathsAbsent(paths []string) bool {
	if len(paths) == 0 {
		return false
	}
	for _, path := range paths {
		var stat unix.Stat_t
		err := unix.Lstat(path, &stat)
		if err == nil || !errors.Is(err, unix.ENOENT) {
			return false
		}
	}
	return true
}

func runnerPathIsDirect(path string) bool {
	var stat unix.Stat_t
	return unix.Lstat(path, &stat) == nil &&
		uint32(stat.Mode)&unix.S_IFMT != unix.S_IFLNK &&
		uint64(stat.Dev) != 0 &&
		stat.Ino != 0
}

func slicesContain(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
