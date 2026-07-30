package main

import (
	"errors"
	"path"
	"strconv"
	"strings"

	"github.com/sumitake/portable-ghar/internal/task11synthetic"
)

const maximumProcControlDocumentBytes = 1 << 20

var errListenerObservation = errors.New(
	"task11 listener observation unavailable",
)

type cgroupLayout struct {
	version task11synthetic.CgroupVersion

	unifiedPath string
	memoryPath  string
	pidsPath    string
}

type cgroupMembership struct {
	controllers []string
	path        string
}

type cgroupMount struct {
	root        string
	mountPoint  string
	fileSystem  string
	controllers []string
}

type listenerMeasurement struct {
	memoryBytes      uint64
	swapBytes        uint64
	runnerTmpfsBytes uint64
	tmpBytes         uint64
	scratchBytes     uint64
	containers       uint64
	processes        uint64
	fileDescriptors  uint64
	namespaces       uint64
	conntrackRows    uint64
	inodes           uint64
}

type highWaterObserver struct {
	version task11synthetic.CgroupVersion
	sample  func() (listenerMeasurement, error)

	highWater listenerMeasurement
	last      listenerObservationPoint
	failed    bool
}

func newHighWaterObserver(
	version task11synthetic.CgroupVersion,
	sample func() (listenerMeasurement, error),
) *highWaterObserver {
	return &highWaterObserver{version: version, sample: sample}
}

func (observer *highWaterObserver) CgroupVersion() task11synthetic.CgroupVersion {
	if observer == nil {
		return ""
	}
	return observer.version
}

func (observer *highWaterObserver) Sample(
	point listenerObservationPoint,
) error {
	if observer == nil ||
		observer.failed ||
		observer.sample == nil ||
		!validListenerCgroupVersion(observer.version) ||
		point < observationListenerEntry ||
		point > observationBeforeIntentionalExit ||
		point <= observer.last ||
		observer.last == observationBeforeTerminal ||
		observer.last == observationBeforeIntentionalExit {
		if observer != nil {
			observer.failed = true
		}
		return errListenerObservation
	}
	measurement, err := observer.sample()
	if err != nil || measurement.containers != 1 {
		observer.failed = true
		return errListenerObservation
	}
	observer.highWater.maximum(measurement)
	observer.last = point
	return nil
}

func (observer *highWaterObserver) HighWater() (
	[]task11synthetic.ResourceHighWater,
	error,
) {
	if observer == nil ||
		observer.failed ||
		observer.last != observationBeforeTerminal {
		return nil, errListenerObservation
	}
	return observer.highWater.vector(), nil
}

func (measurement *listenerMeasurement) maximum(
	candidate listenerMeasurement,
) {
	measurement.memoryBytes = maximumUint64(
		measurement.memoryBytes,
		candidate.memoryBytes,
	)
	measurement.swapBytes = maximumUint64(
		measurement.swapBytes,
		candidate.swapBytes,
	)
	measurement.runnerTmpfsBytes = maximumUint64(
		measurement.runnerTmpfsBytes,
		candidate.runnerTmpfsBytes,
	)
	measurement.tmpBytes = maximumUint64(
		measurement.tmpBytes,
		candidate.tmpBytes,
	)
	measurement.scratchBytes = maximumUint64(
		measurement.scratchBytes,
		candidate.scratchBytes,
	)
	measurement.containers = maximumUint64(
		measurement.containers,
		candidate.containers,
	)
	measurement.processes = maximumUint64(
		measurement.processes,
		candidate.processes,
	)
	measurement.fileDescriptors = maximumUint64(
		measurement.fileDescriptors,
		candidate.fileDescriptors,
	)
	measurement.namespaces = maximumUint64(
		measurement.namespaces,
		candidate.namespaces,
	)
	measurement.conntrackRows = maximumUint64(
		measurement.conntrackRows,
		candidate.conntrackRows,
	)
	measurement.inodes = maximumUint64(
		measurement.inodes,
		candidate.inodes,
	)
}

func (measurement listenerMeasurement) vector() []task11synthetic.ResourceHighWater {
	return []task11synthetic.ResourceHighWater{
		{
			Resource:  task11synthetic.ResourceMemoryBytes,
			HighWater: measurement.memoryBytes,
		},
		{
			Resource:  task11synthetic.ResourceSwapBytes,
			HighWater: measurement.swapBytes,
		},
		{
			Resource:  task11synthetic.ResourceRunnerTmpfsBytes,
			HighWater: measurement.runnerTmpfsBytes,
		},
		{
			Resource:  task11synthetic.ResourceTmpBytes,
			HighWater: measurement.tmpBytes,
		},
		{
			Resource:  task11synthetic.ResourceScratchBytes,
			HighWater: measurement.scratchBytes,
		},
		{
			Resource:  task11synthetic.ResourceContainers,
			HighWater: measurement.containers,
		},
		{
			Resource:  task11synthetic.ResourceProcesses,
			HighWater: measurement.processes,
		},
		{
			Resource:  task11synthetic.ResourceFileDescriptors,
			HighWater: measurement.fileDescriptors,
		},
		{
			Resource:  task11synthetic.ResourceNamespaces,
			HighWater: measurement.namespaces,
		},
		{
			Resource:  task11synthetic.ResourceConntrackRows,
			HighWater: measurement.conntrackRows,
		},
		{
			Resource:  task11synthetic.ResourceInodes,
			HighWater: measurement.inodes,
		},
	}
}

func maximumUint64(left, right uint64) uint64 {
	if right > left {
		return right
	}
	return left
}

func parseCgroupLayout(
	cgroupDocument []byte,
	mountinfoDocument []byte,
) (cgroupLayout, error) {
	memberships, unified, allControllers, err :=
		parseCgroupMemberships(cgroupDocument)
	if err != nil {
		return cgroupLayout{}, errListenerObservation
	}
	mounts, err := parseCgroupMounts(
		mountinfoDocument,
		allControllers,
	)
	if err != nil {
		return cgroupLayout{}, errListenerObservation
	}
	var v1Mounts, v2Mounts []cgroupMount
	for _, mount := range mounts {
		switch mount.fileSystem {
		case "cgroup":
			v1Mounts = append(v1Mounts, mount)
		case "cgroup2":
			v2Mounts = append(v2Mounts, mount)
		}
	}
	if unified != nil {
		if len(memberships) != 0 ||
			len(v1Mounts) != 0 ||
			len(v2Mounts) != 1 {
			return cgroupLayout{}, errListenerObservation
		}
		resolved, err := resolveCgroupPath(
			v2Mounts[0].root,
			v2Mounts[0].mountPoint,
			unified.path,
		)
		if err != nil {
			return cgroupLayout{}, errListenerObservation
		}
		return cgroupLayout{
			version:     task11synthetic.CgroupV2,
			unifiedPath: resolved,
		}, nil
	}
	if len(v2Mounts) != 0 {
		return cgroupLayout{}, errListenerObservation
	}

	memoryMembership, pidsMembership, err :=
		selectV1Memberships(memberships)
	if err != nil {
		return cgroupLayout{}, errListenerObservation
	}
	memoryMount, err := selectV1Mount(
		v1Mounts,
		memoryMembership.controllers,
	)
	if err != nil {
		return cgroupLayout{}, errListenerObservation
	}
	pidsMount, err := selectV1Mount(
		v1Mounts,
		pidsMembership.controllers,
	)
	if err != nil {
		return cgroupLayout{}, errListenerObservation
	}
	memoryPath, err := resolveCgroupPath(
		memoryMount.root,
		memoryMount.mountPoint,
		memoryMembership.path,
	)
	if err != nil {
		return cgroupLayout{}, errListenerObservation
	}
	pidsPath, err := resolveCgroupPath(
		pidsMount.root,
		pidsMount.mountPoint,
		pidsMembership.path,
	)
	if err != nil {
		return cgroupLayout{}, errListenerObservation
	}
	return cgroupLayout{
		version:    task11synthetic.CgroupV1,
		memoryPath: memoryPath,
		pidsPath:   pidsPath,
	}, nil
}

func parseCgroupMemberships(
	document []byte,
) ([]cgroupMembership, *cgroupMembership, map[string]struct{}, error) {
	lines, err := canonicalProcLines(document)
	if err != nil {
		return nil, nil, nil, errListenerObservation
	}
	var memberships []cgroupMembership
	var unified *cgroupMembership
	allControllers := make(map[string]struct{})
	for _, line := range lines {
		fields := strings.Split(line, ":")
		if len(fields) != 3 ||
			!canonicalUnsigned(fields[0]) ||
			!canonicalAbsoluteLinuxPath(fields[2]) {
			return nil, nil, nil, errListenerObservation
		}
		if fields[0] == "0" {
			if fields[1] != "" || unified != nil {
				return nil, nil, nil, errListenerObservation
			}
			value := cgroupMembership{path: fields[2]}
			unified = &value
			continue
		}
		if fields[1] == "" {
			return nil, nil, nil, errListenerObservation
		}
		controllers := strings.Split(fields[1], ",")
		seen := make(map[string]struct{}, len(controllers))
		for _, controller := range controllers {
			if !canonicalControllerName(controller) {
				return nil, nil, nil, errListenerObservation
			}
			if _, duplicate := seen[controller]; duplicate {
				return nil, nil, nil, errListenerObservation
			}
			seen[controller] = struct{}{}
			allControllers[controller] = struct{}{}
		}
		memberships = append(memberships, cgroupMembership{
			controllers: controllers,
			path:        fields[2],
		})
	}
	return memberships, unified, allControllers, nil
}

func parseCgroupMounts(
	document []byte,
	allControllers map[string]struct{},
) ([]cgroupMount, error) {
	lines, err := canonicalProcLines(document)
	if err != nil {
		return nil, errListenerObservation
	}
	var mounts []cgroupMount
	for _, line := range lines {
		fields := strings.Split(line, " ")
		if len(fields) < 10 ||
			strings.Join(fields, " ") != line {
			return nil, errListenerObservation
		}
		separator := -1
		for index, field := range fields {
			if field == "-" {
				if separator != -1 {
					return nil, errListenerObservation
				}
				separator = index
			}
		}
		if separator < 6 || separator+3 >= len(fields) ||
			!canonicalAbsoluteLinuxPath(fields[3]) ||
			!canonicalAbsoluteLinuxPath(fields[4]) ||
			strings.Contains(fields[3], "\\") ||
			strings.Contains(fields[4], "\\") {
			return nil, errListenerObservation
		}
		fileSystem := fields[separator+1]
		if fileSystem != "cgroup" && fileSystem != "cgroup2" {
			continue
		}
		mount := cgroupMount{
			root:       fields[3],
			mountPoint: fields[4],
			fileSystem: fileSystem,
		}
		if fileSystem == "cgroup" {
			for _, option := range strings.Split(
				fields[separator+3],
				",",
			) {
				if _, controller := allControllers[option]; controller {
					mount.controllers = append(
						mount.controllers,
						option,
					)
				}
			}
			if len(mount.controllers) == 0 {
				continue
			}
		}
		mounts = append(mounts, mount)
	}
	return mounts, nil
}

func selectV1Memberships(
	memberships []cgroupMembership,
) (cgroupMembership, cgroupMembership, error) {
	var memory, pids *cgroupMembership
	for index := range memberships {
		membership := &memberships[index]
		hasMemory := stringSliceContains(
			membership.controllers,
			"memory",
		)
		hasPids := stringSliceContains(
			membership.controllers,
			"pids",
		)
		if !hasMemory && !hasPids {
			continue
		}
		if len(membership.controllers) != 1 &&
			!(len(membership.controllers) == 2 &&
				hasMemory &&
				hasPids) {
			return cgroupMembership{}, cgroupMembership{},
				errListenerObservation
		}
		if hasMemory {
			if memory != nil {
				return cgroupMembership{}, cgroupMembership{},
					errListenerObservation
			}
			memory = membership
		}
		if hasPids {
			if pids != nil {
				return cgroupMembership{}, cgroupMembership{},
					errListenerObservation
			}
			pids = membership
		}
	}
	if memory == nil || pids == nil {
		return cgroupMembership{}, cgroupMembership{},
			errListenerObservation
	}
	return *memory, *pids, nil
}

func selectV1Mount(
	mounts []cgroupMount,
	controllers []string,
) (cgroupMount, error) {
	var selected *cgroupMount
	for index := range mounts {
		mount := &mounts[index]
		if !sameStringSet(mount.controllers, controllers) {
			continue
		}
		if selected != nil {
			return cgroupMount{}, errListenerObservation
		}
		selected = mount
	}
	if selected == nil {
		return cgroupMount{}, errListenerObservation
	}
	return *selected, nil
}

func resolveCgroupPath(
	root string,
	mountPoint string,
	membership string,
) (string, error) {
	if !canonicalAbsoluteLinuxPath(root) ||
		!canonicalAbsoluteLinuxPath(mountPoint) ||
		!canonicalAbsoluteLinuxPath(membership) {
		return "", errListenerObservation
	}
	var relative string
	switch {
	case root == "/":
		relative = strings.TrimPrefix(membership, "/")
	case membership == root:
		relative = ""
	case strings.HasPrefix(membership, root+"/"):
		relative = strings.TrimPrefix(membership, root+"/")
	default:
		return "", errListenerObservation
	}
	resolved := mountPoint
	if relative != "" {
		resolved = path.Join(mountPoint, relative)
	}
	if !canonicalAbsoluteLinuxPath(resolved) {
		return "", errListenerObservation
	}
	return resolved, nil
}

func canonicalProcLines(document []byte) ([]string, error) {
	if len(document) == 0 ||
		len(document) > maximumProcControlDocumentBytes ||
		document[len(document)-1] != '\n' ||
		strings.ContainsRune(string(document), '\r') {
		return nil, errListenerObservation
	}
	raw := strings.TrimSuffix(string(document), "\n")
	if raw == "" {
		return nil, errListenerObservation
	}
	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		if line == "" {
			return nil, errListenerObservation
		}
	}
	return lines, nil
}

func parseCanonicalUint64Document(document []byte) (uint64, error) {
	lines, err := canonicalProcLines(document)
	if err != nil || len(lines) != 1 || !canonicalUnsigned(lines[0]) {
		return 0, errListenerObservation
	}
	value, err := strconv.ParseUint(lines[0], 10, 64)
	if err != nil {
		return 0, errListenerObservation
	}
	return value, nil
}

func parseCanonicalPIDDocument(document []byte) ([]uint64, error) {
	lines, err := canonicalProcLines(document)
	if err != nil {
		return nil, errListenerObservation
	}
	result := make([]uint64, 0, len(lines))
	seen := make(map[uint64]struct{}, len(lines))
	for _, line := range lines {
		if !canonicalUnsigned(line) {
			return nil, errListenerObservation
		}
		pid, parseErr := strconv.ParseUint(line, 10, 64)
		if parseErr != nil || pid == 0 {
			return nil, errListenerObservation
		}
		if _, duplicate := seen[pid]; duplicate {
			return nil, errListenerObservation
		}
		seen[pid] = struct{}{}
		result = append(result, pid)
	}
	return result, nil
}

func parseV1MemorySample(
	maximumDocument []byte,
	memoryFirstDocument []byte,
	memswFirstDocument []byte,
	memorySecondDocument []byte,
	memswSecondDocument []byte,
) (uint64, uint64, error) {
	maximum, err := parseCanonicalUint64Document(maximumDocument)
	if err != nil {
		return 0, 0, errListenerObservation
	}
	memoryFirst, err := parseCanonicalUint64Document(
		memoryFirstDocument,
	)
	if err != nil {
		return 0, 0, errListenerObservation
	}
	memswFirst, err := parseCanonicalUint64Document(memswFirstDocument)
	if err != nil {
		return 0, 0, errListenerObservation
	}
	memorySecond, err := parseCanonicalUint64Document(
		memorySecondDocument,
	)
	if err != nil {
		return 0, 0, errListenerObservation
	}
	memswSecond, err := parseCanonicalUint64Document(
		memswSecondDocument,
	)
	if err != nil ||
		memoryFirst != memorySecond ||
		memswFirst != memswSecond ||
		memswFirst < memoryFirst {
		return 0, 0, errListenerObservation
	}
	return maximum, memswFirst - memoryFirst, nil
}

func canonicalUnsigned(value string) bool {
	if value == "" ||
		(len(value) > 1 && value[0] == '0') {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func canonicalControllerName(value string) bool {
	if value == "" ||
		strings.ContainsAny(value, "/:\\ \t\r\n") {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') &&
			character != '_' &&
			character != '-' &&
			character != '=' {
			return false
		}
	}
	return true
}

func canonicalAbsoluteLinuxPath(value string) bool {
	return value != "" &&
		value[0] == '/' &&
		(value == "/" || !strings.HasSuffix(value, "/")) &&
		!strings.Contains(value, "//") &&
		path.Clean(value) == value
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	counts := make(map[string]uint8, len(left))
	for _, value := range left {
		counts[value]++
	}
	for _, value := range right {
		if counts[value] != 1 {
			return false
		}
		counts[value]--
	}
	for _, count := range counts {
		if count != 0 {
			return false
		}
	}
	return true
}
