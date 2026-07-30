//go:build linux

package main

import (
	"bytes"
	"io"
	"math"
	"math/bits"
	"os"
	"strconv"

	"github.com/sumitake/portable-ghar/internal/task11synthetic"
	"golang.org/x/sys/unix"
)

const (
	task11ProcRoot          = "/proc"
	task11SelfCgroupPath    = "/proc/self/cgroup"
	task11SelfMountinfoPath = "/proc/self/mountinfo"
)

type stableLinuxDirectory struct {
	fd       int
	identity listenerFileIdentity
}

type stableLinuxMount struct {
	directory stableLinuxDirectory
	fileType  int64
	fileID    unix.Fsid
}

type linuxMeasurementSource struct {
	layout            cgroupLayout
	cgroupDocument    []byte
	mountinfoDocument []byte
	selfPID           uint64

	unified *stableLinuxDirectory
	memory  *stableLinuxDirectory
	pids    *stableLinuxDirectory
	proc    stableLinuxDirectory

	runner  stableLinuxMount
	tmp     stableLinuxMount
	scratch stableLinuxMount
}

func newSystemObserver() (listenerObserver, error) {
	source, err := newLinuxMeasurementSource()
	if err != nil {
		return nil, errListenerObservation
	}
	return newHighWaterObserver(source.layout.version, source.sample), nil
}

func newLinuxMeasurementSource() (*linuxMeasurementSource, error) {
	cgroupDocument, err := readLinuxPathDocument(
		task11SelfCgroupPath,
		maximumProcControlDocumentBytes,
		false,
	)
	if err != nil {
		return nil, errListenerObservation
	}
	mountinfoDocument, err := readLinuxPathDocument(
		task11SelfMountinfoPath,
		maximumProcControlDocumentBytes,
		false,
	)
	if err != nil {
		return nil, errListenerObservation
	}
	layout, err := parseCgroupLayout(
		cgroupDocument,
		mountinfoDocument,
	)
	if err != nil {
		return nil, errListenerObservation
	}
	source := &linuxMeasurementSource{
		layout:            layout,
		cgroupDocument:    cgroupDocument,
		mountinfoDocument: mountinfoDocument,
		selfPID:           uint64(os.Getpid()),
		proc:              stableLinuxDirectory{fd: -1},
		runner: stableLinuxMount{
			directory: stableLinuxDirectory{fd: -1},
		},
		tmp: stableLinuxMount{
			directory: stableLinuxDirectory{fd: -1},
		},
		scratch: stableLinuxMount{
			directory: stableLinuxDirectory{fd: -1},
		},
	}
	success := false
	defer func() {
		if !success {
			source.close()
		}
	}()
	if source.selfPID == 0 {
		return nil, errListenerObservation
	}
	source.proc, err = openStableLinuxDirectory(task11ProcRoot)
	if err != nil {
		return nil, errListenerObservation
	}
	switch layout.version {
	case task11synthetic.CgroupV2:
		directory, openErr := openStableLinuxDirectory(
			layout.unifiedPath,
		)
		if openErr != nil {
			return nil, errListenerObservation
		}
		source.unified = &directory
	case task11synthetic.CgroupV1:
		directory, openErr := openStableLinuxDirectory(
			layout.memoryPath,
		)
		if openErr != nil {
			return nil, errListenerObservation
		}
		source.memory = &directory
		if layout.pidsPath == layout.memoryPath {
			source.pids = source.memory
		} else {
			pidsDirectory, pidsErr := openStableLinuxDirectory(
				layout.pidsPath,
			)
			if pidsErr != nil {
				return nil, errListenerObservation
			}
			source.pids = &pidsDirectory
		}
	default:
		return nil, errListenerObservation
	}
	source.runner, err = openStableLinuxMount("/runner")
	if err != nil {
		return nil, errListenerObservation
	}
	source.tmp, err = openStableLinuxMount("/tmp")
	if err != nil {
		return nil, errListenerObservation
	}
	source.scratch, err = openStableLinuxMount("/scratch")
	if err != nil {
		return nil, errListenerObservation
	}
	if err := source.verifyStaticDocuments(); err != nil {
		return nil, errListenerObservation
	}
	success = true
	return source, nil
}

func (source *linuxMeasurementSource) sample() (
	listenerMeasurement,
	error,
) {
	if source == nil || source.verifyStaticDocuments() != nil {
		return listenerMeasurement{}, errListenerObservation
	}
	var measurement listenerMeasurement
	var processDocument []byte
	var err error
	switch source.layout.version {
	case task11synthetic.CgroupV2:
		if source.unified == nil ||
			verifyStableLinuxDirectory(*source.unified) != nil {
			return listenerMeasurement{}, errListenerObservation
		}
		memoryDocument, memoryErr := readLinuxFileAt(
			source.unified.fd,
			"memory.peak",
			maximumProcControlDocumentBytes,
			false,
		)
		swapDocument, swapErr := readLinuxFileAt(
			source.unified.fd,
			"memory.swap.peak",
			maximumProcControlDocumentBytes,
			false,
		)
		processDocument, err = readLinuxFileAt(
			source.unified.fd,
			"cgroup.procs",
			maximumProcControlDocumentBytes,
			false,
		)
		if memoryErr != nil || swapErr != nil || err != nil {
			return listenerMeasurement{}, errListenerObservation
		}
		measurement.memoryBytes, err =
			parseCanonicalUint64Document(memoryDocument)
		if err != nil {
			return listenerMeasurement{}, errListenerObservation
		}
		measurement.swapBytes, err =
			parseCanonicalUint64Document(swapDocument)
		if err != nil {
			return listenerMeasurement{}, errListenerObservation
		}
	case task11synthetic.CgroupV1:
		if source.memory == nil ||
			source.pids == nil ||
			verifyStableLinuxDirectory(*source.memory) != nil ||
			verifyStableLinuxDirectory(*source.pids) != nil {
			return listenerMeasurement{}, errListenerObservation
		}
		maximumDocument, maximumErr := readLinuxFileAt(
			source.memory.fd,
			"memory.max_usage_in_bytes",
			maximumProcControlDocumentBytes,
			false,
		)
		memoryFirst, memoryFirstErr := readLinuxFileAt(
			source.memory.fd,
			"memory.usage_in_bytes",
			maximumProcControlDocumentBytes,
			false,
		)
		memswFirst, memswFirstErr := readLinuxFileAt(
			source.memory.fd,
			"memory.memsw.usage_in_bytes",
			maximumProcControlDocumentBytes,
			false,
		)
		memorySecond, memorySecondErr := readLinuxFileAt(
			source.memory.fd,
			"memory.usage_in_bytes",
			maximumProcControlDocumentBytes,
			false,
		)
		memswSecond, memswSecondErr := readLinuxFileAt(
			source.memory.fd,
			"memory.memsw.usage_in_bytes",
			maximumProcControlDocumentBytes,
			false,
		)
		processDocument, err = readLinuxFileAt(
			source.pids.fd,
			"cgroup.procs",
			maximumProcControlDocumentBytes,
			false,
		)
		if maximumErr != nil ||
			memoryFirstErr != nil ||
			memswFirstErr != nil ||
			memorySecondErr != nil ||
			memswSecondErr != nil ||
			err != nil {
			return listenerMeasurement{}, errListenerObservation
		}
		measurement.memoryBytes, measurement.swapBytes, err =
			parseV1MemorySample(
				maximumDocument,
				memoryFirst,
				memswFirst,
				memorySecond,
				memswSecond,
			)
		if err != nil {
			return listenerMeasurement{}, errListenerObservation
		}
	default:
		return listenerMeasurement{}, errListenerObservation
	}

	pids, err := parseCanonicalPIDDocument(processDocument)
	if err != nil {
		return listenerMeasurement{}, errListenerObservation
	}
	measurement.processes = uint64(len(pids))
	measurement.containers = 1
	measurement.fileDescriptors, measurement.namespaces, err =
		source.inspectProcesses(pids)
	if err != nil {
		return listenerMeasurement{}, errListenerObservation
	}
	measurement.conntrackRows, err = source.inspectConntrack()
	if err != nil {
		return listenerMeasurement{}, errListenerObservation
	}

	runnerBytes, runnerInodes, err := sampleStableLinuxMount(
		source.runner,
	)
	if err != nil {
		return listenerMeasurement{}, errListenerObservation
	}
	tmpBytes, tmpInodes, err := sampleStableLinuxMount(source.tmp)
	if err != nil {
		return listenerMeasurement{}, errListenerObservation
	}
	scratchBytes, scratchInodes, err := sampleStableLinuxMount(
		source.scratch,
	)
	if err != nil {
		return listenerMeasurement{}, errListenerObservation
	}
	measurement.runnerTmpfsBytes = runnerBytes
	measurement.tmpBytes = tmpBytes
	measurement.scratchBytes = scratchBytes
	measurement.inodes, err = checkedAddUint64(
		runnerInodes,
		tmpInodes,
		scratchInodes,
	)
	if err != nil ||
		source.verifyStableDirectories() != nil ||
		source.verifyStaticDocuments() != nil {
		return listenerMeasurement{}, errListenerObservation
	}
	return measurement, nil
}

func (source *linuxMeasurementSource) inspectProcesses(
	pids []uint64,
) (uint64, uint64, error) {
	if len(pids) == 0 {
		return 0, 0, errListenerObservation
	}
	selfFound := false
	namespaceSet := make(map[[2]uint64]struct{})
	var descriptorCount uint64
	for _, pid := range pids {
		if pid == source.selfPID {
			selfFound = true
		}
		pidName := strconv.FormatUint(pid, 10)
		pidFD, err := unix.Openat(
			source.proc.fd,
			pidName,
			unix.O_RDONLY|unix.O_DIRECTORY|
				unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		if err != nil {
			return 0, 0, errListenerObservation
		}
		before, identityErr := identityFromFD(pidFD)
		beforeCgroup, cgroupErr := readLinuxFileAt(
			pidFD,
			"cgroup",
			maximumProcControlDocumentBytes,
			false,
		)
		if identityErr != nil || cgroupErr != nil {
			closeFD(pidFD)
			return 0, 0, errListenerObservation
		}
		layout, layoutErr := parseCgroupLayout(
			beforeCgroup,
			source.mountinfoDocument,
		)
		if layoutErr != nil || layout != source.layout {
			closeFD(pidFD)
			return 0, 0, errListenerObservation
		}
		count, countErr := inspectLinuxFDDirectory(pidFD)
		if countErr != nil {
			closeFD(pidFD)
			return 0, 0, errListenerObservation
		}
		descriptorCount, err = checkedAddUint64(
			descriptorCount,
			count,
		)
		if err != nil {
			closeFD(pidFD)
			return 0, 0, errListenerObservation
		}
		if inspectLinuxNamespaceDirectory(
			pidFD,
			namespaceSet,
		) != nil {
			closeFD(pidFD)
			return 0, 0, errListenerObservation
		}
		afterCgroup, afterCgroupErr := readLinuxFileAt(
			pidFD,
			"cgroup",
			maximumProcControlDocumentBytes,
			false,
		)
		after, afterErr := identityFromFD(pidFD)
		closeErr := unix.Close(pidFD)
		if afterCgroupErr != nil ||
			afterErr != nil ||
			closeErr != nil ||
			!before.equal(after) ||
			!bytes.Equal(beforeCgroup, afterCgroup) {
			return 0, 0, errListenerObservation
		}
	}
	if !selfFound {
		return 0, 0, errListenerObservation
	}
	return descriptorCount, uint64(len(namespaceSet)), nil
}

func (source *linuxMeasurementSource) inspectConntrack() (
	uint64,
	error,
) {
	pidFD, err := unix.Openat(
		source.proc.fd,
		strconv.FormatUint(source.selfPID, 10),
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return 0, errListenerObservation
	}
	defer closeFD(pidFD)
	netFD, err := unix.Openat(
		pidFD,
		"net",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return 0, errListenerObservation
	}
	defer closeFD(netFD)
	document, err := readLinuxFileAt(
		netFD,
		"nf_conntrack",
		maximumProcControlDocumentBytes,
		true,
	)
	if err != nil {
		return 0, errListenerObservation
	}
	if len(document) == 0 {
		return 0, nil
	}
	lines, err := canonicalProcLines(document)
	if err != nil {
		return 0, errListenerObservation
	}
	return uint64(len(lines)), nil
}

func (source *linuxMeasurementSource) verifyStaticDocuments() error {
	if source == nil {
		return errListenerObservation
	}
	cgroupDocument, err := readLinuxPathDocument(
		task11SelfCgroupPath,
		maximumProcControlDocumentBytes,
		false,
	)
	if err != nil || !bytes.Equal(
		cgroupDocument,
		source.cgroupDocument,
	) {
		return errListenerObservation
	}
	mountinfoDocument, err := readLinuxPathDocument(
		task11SelfMountinfoPath,
		maximumProcControlDocumentBytes,
		false,
	)
	if err != nil || !bytes.Equal(
		mountinfoDocument,
		source.mountinfoDocument,
	) {
		return errListenerObservation
	}
	return nil
}

func (source *linuxMeasurementSource) verifyStableDirectories() error {
	if source == nil ||
		verifyStableLinuxDirectory(source.proc) != nil ||
		verifyStableLinuxDirectory(source.runner.directory) != nil ||
		verifyStableLinuxDirectory(source.tmp.directory) != nil ||
		verifyStableLinuxDirectory(source.scratch.directory) != nil {
		return errListenerObservation
	}
	if source.unified != nil &&
		verifyStableLinuxDirectory(*source.unified) != nil {
		return errListenerObservation
	}
	if source.memory != nil &&
		verifyStableLinuxDirectory(*source.memory) != nil {
		return errListenerObservation
	}
	if source.pids != nil &&
		source.pids != source.memory &&
		verifyStableLinuxDirectory(*source.pids) != nil {
		return errListenerObservation
	}
	return nil
}

func (source *linuxMeasurementSource) close() {
	if source == nil {
		return
	}
	closed := make(map[int]struct{})
	closeDirectory := func(directory *stableLinuxDirectory) {
		if directory == nil ||
			directory.fd < 0 ||
			directory.identity.device == 0 ||
			directory.identity.inode == 0 {
			return
		}
		if _, duplicate := closed[directory.fd]; !duplicate {
			closeFD(directory.fd)
			closed[directory.fd] = struct{}{}
		}
		directory.fd = -1
	}
	closeDirectory(source.unified)
	closeDirectory(source.memory)
	closeDirectory(source.pids)
	closeDirectory(&source.proc)
	closeDirectory(&source.runner.directory)
	closeDirectory(&source.tmp.directory)
	closeDirectory(&source.scratch.directory)
}

func openStableLinuxDirectory(
	path string,
) (stableLinuxDirectory, error) {
	fd, identity, err := openExactDirectory(path)
	if err != nil {
		return stableLinuxDirectory{fd: -1}, errListenerObservation
	}
	return stableLinuxDirectory{fd: fd, identity: identity}, nil
}

func verifyStableLinuxDirectory(directory stableLinuxDirectory) error {
	current, err := identityFromFD(directory.fd)
	if err != nil ||
		current.device != directory.identity.device ||
		current.inode != directory.identity.inode ||
		current.mode&unix.S_IFMT != unix.S_IFDIR {
		return errListenerObservation
	}
	return nil
}

func openStableLinuxMount(path string) (stableLinuxMount, error) {
	directory, err := openStableLinuxDirectory(path)
	if err != nil {
		return stableLinuxMount{}, errListenerObservation
	}
	var stat unix.Statfs_t
	if unix.Fstatfs(directory.fd, &stat) != nil ||
		stat.Type != unix.TMPFS_MAGIC {
		closeFD(directory.fd)
		return stableLinuxMount{}, errListenerObservation
	}
	return stableLinuxMount{
		directory: directory,
		fileType:  stat.Type,
		fileID:    stat.Fsid,
	}, nil
}

func sampleStableLinuxMount(
	mount stableLinuxMount,
) (uint64, uint64, error) {
	if verifyStableLinuxDirectory(mount.directory) != nil {
		return 0, 0, errListenerObservation
	}
	var stat unix.Statfs_t
	if unix.Fstatfs(mount.directory.fd, &stat) != nil ||
		stat.Type != unix.TMPFS_MAGIC ||
		stat.Type != mount.fileType ||
		stat.Fsid != mount.fileID ||
		stat.Bsize <= 0 ||
		stat.Blocks < stat.Bfree ||
		stat.Files < stat.Ffree {
		return 0, 0, errListenerObservation
	}
	high, usedBytes := bits.Mul64(
		stat.Blocks-stat.Bfree,
		uint64(stat.Bsize),
	)
	if high != 0 {
		return 0, 0, errListenerObservation
	}
	return usedBytes, stat.Files - stat.Ffree, nil
}

func inspectLinuxFDDirectory(pidFD int) (uint64, error) {
	fd, err := unix.Openat(
		pidFD,
		"fd",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return 0, errListenerObservation
	}
	file := os.NewFile(uintptr(fd), "task11-proc-fd")
	if file == nil {
		closeFD(fd)
		return 0, errListenerObservation
	}
	names, readErr := file.Readdirnames(-1)
	if readErr != nil {
		_ = file.Close()
		return 0, errListenerObservation
	}
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if !canonicalUnsigned(name) {
			_ = file.Close()
			return 0, errListenerObservation
		}
		if _, duplicate := seen[name]; duplicate {
			_ = file.Close()
			return 0, errListenerObservation
		}
		var stat unix.Stat_t
		if unix.Fstatat(
			fd,
			name,
			&stat,
			unix.AT_SYMLINK_NOFOLLOW,
		) != nil ||
			uint32(stat.Mode)&unix.S_IFMT != unix.S_IFLNK {
			_ = file.Close()
			return 0, errListenerObservation
		}
		seen[name] = struct{}{}
	}
	if file.Close() != nil {
		return 0, errListenerObservation
	}
	return uint64(len(names)), nil
}

func inspectLinuxNamespaceDirectory(
	pidFD int,
	namespaceSet map[[2]uint64]struct{},
) error {
	if namespaceSet == nil {
		return errListenerObservation
	}
	fd, err := unix.Openat(
		pidFD,
		"ns",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return errListenerObservation
	}
	file := os.NewFile(uintptr(fd), "task11-proc-ns")
	if file == nil {
		closeFD(fd)
		return errListenerObservation
	}
	names, readErr := file.Readdirnames(-1)
	if readErr != nil || len(names) == 0 {
		_ = file.Close()
		return errListenerObservation
	}
	seen := make(map[string]struct{}, len(names))
	required := map[string]bool{
		"cgroup": false,
		"ipc":    false,
		"mnt":    false,
		"net":    false,
		"pid":    false,
		"user":   false,
		"uts":    false,
	}
	for _, name := range names {
		if !canonicalNamespaceName(name) {
			_ = file.Close()
			return errListenerObservation
		}
		if _, duplicate := seen[name]; duplicate {
			_ = file.Close()
			return errListenerObservation
		}
		var before, after unix.Stat_t
		if unix.Fstatat(fd, name, &before, 0) != nil ||
			unix.Fstatat(fd, name, &after, 0) != nil ||
			uint64(before.Dev) == 0 ||
			before.Ino == 0 ||
			before.Dev != after.Dev ||
			before.Ino != after.Ino {
			_ = file.Close()
			return errListenerObservation
		}
		namespaceSet[[2]uint64{
			uint64(before.Dev),
			before.Ino,
		}] = struct{}{}
		seen[name] = struct{}{}
		if _, found := required[name]; found {
			required[name] = true
		}
	}
	for _, found := range required {
		if !found {
			_ = file.Close()
			return errListenerObservation
		}
	}
	if file.Close() != nil {
		return errListenerObservation
	}
	return nil
}

func canonicalNamespaceName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, character := range name {
		if (character < 'a' || character > 'z') &&
			character != '_' {
			return false
		}
	}
	return true
}

func readLinuxPathDocument(
	path string,
	maximum int,
	allowEmpty bool,
) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errListenerObservation
	}
	document, readErr := io.ReadAll(
		io.LimitReader(file, int64(maximum)+1),
	)
	closeErr := file.Close()
	if readErr != nil ||
		closeErr != nil ||
		len(document) > maximum ||
		(!allowEmpty && len(document) == 0) {
		return nil, errListenerObservation
	}
	return document, nil
}

func readLinuxFileAt(
	parentFD int,
	name string,
	maximum int,
	allowEmpty bool,
) ([]byte, error) {
	if parentFD < 0 ||
		!validLeaf(name) ||
		maximum <= 0 {
		return nil, errListenerObservation
	}
	fd, err := unix.Openat(
		parentFD,
		name,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, errListenerObservation
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil ||
		uint32(stat.Mode)&unix.S_IFMT != unix.S_IFREG {
		closeFD(fd)
		return nil, errListenerObservation
	}
	file := os.NewFile(uintptr(fd), "task11-proc-control")
	if file == nil {
		closeFD(fd)
		return nil, errListenerObservation
	}
	document, readErr := io.ReadAll(
		io.LimitReader(file, int64(maximum)+1),
	)
	closeErr := file.Close()
	if readErr != nil ||
		closeErr != nil ||
		len(document) > maximum ||
		(!allowEmpty && len(document) == 0) {
		return nil, errListenerObservation
	}
	return document, nil
}

func checkedAddUint64(values ...uint64) (uint64, error) {
	var result uint64
	for _, value := range values {
		if value > math.MaxUint64-result {
			return 0, errListenerObservation
		}
		result += value
	}
	return result, nil
}
