package testenv

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/sumitake/portable-ghar/internal/task11synthetic"
)

type task11SyntheticStructuralMount struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Driver      string `json:"driver"`
	Mode        string `json:"mode"`
	RW          bool   `json:"rw"`
	Propagation string `json:"propagation"`
}

type task11SyntheticStructuralInspect struct {
	ID         string
	Name       string
	ImageID    string
	Running    bool
	PID        int
	SandboxKey string
	Mounts     []task11SyntheticStructuralMount
	Tmpfs      map[string]string
}

type task11SyntheticStructuralInspectWire struct {
	ID         string                           `json:"id"`
	Name       string                           `json:"name"`
	Image      string                           `json:"image"`
	Running    bool                             `json:"running"`
	PID        int64                            `json:"pid"`
	SandboxKey string                           `json:"sandbox_key"`
	Mounts     []task11SyntheticStructuralMount `json:"mounts"`
	Tmpfs      map[string]string                `json:"tmpfs"`
}

func parseTask11SyntheticStructuralInspect(
	document []byte,
) (task11SyntheticStructuralInspect, error) {
	if len(document) == 0 ||
		len(document) > int(maximumPermitProcDocumentBytes) ||
		document[len(document)-1] != '\n' ||
		bytes.Count(document, []byte{'\n'}) != 1 ||
		bytes.IndexByte(document, 0) >= 0 ||
		bytes.IndexByte(document, '\r') >= 0 {
		return task11SyntheticStructuralInspect{}, ErrFixtureStart
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var wire task11SyntheticStructuralInspectWire
	if err := decoder.Decode(&wire); err != nil {
		return task11SyntheticStructuralInspect{}, ErrFixtureStart
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF ||
		!isLowerHex(wire.ID, 64) ||
		!strings.HasPrefix(wire.Name, "/") ||
		strings.HasPrefix(wire.Name, "//") ||
		!compositionContainerNamePattern.MatchString(
			strings.TrimPrefix(wire.Name, "/"),
		) ||
		!strings.HasPrefix(wire.Image, "sha256:") ||
		!isLowerHex(strings.TrimPrefix(wire.Image, "sha256:"), 64) ||
		wire.PID < 0 ||
		uint64(wire.PID) > uint64(^uint(0)>>1) ||
		wire.Running != (wire.PID > 0) ||
		(wire.SandboxKey != "" &&
			(!validAbsolutePath(wire.SandboxKey) ||
				wire.SandboxKey == string(filepath.Separator))) ||
		!validTask11SyntheticStructuralMounts(wire.Mounts) ||
		!validTask11SyntheticStructuralTmpfs(wire.Tmpfs) {
		return task11SyntheticStructuralInspect{}, ErrFixtureStart
	}
	return task11SyntheticStructuralInspect{
		ID:         wire.ID,
		Name:       strings.TrimPrefix(wire.Name, "/"),
		ImageID:    strings.TrimPrefix(wire.Image, "sha256:"),
		Running:    wire.Running,
		PID:        int(wire.PID),
		SandboxKey: wire.SandboxKey,
		Mounts: append(
			[]task11SyntheticStructuralMount(nil),
			wire.Mounts...,
		),
		Tmpfs: cloneTask11SyntheticStringMap(wire.Tmpfs),
	}, nil
}

func validTask11SyntheticStructuralMounts(
	mounts []task11SyntheticStructuralMount,
) bool {
	seen := make(map[string]struct{}, len(mounts))
	for _, mount := range mounts {
		if mount.Type == "" ||
			!validAbsolutePath(mount.Destination) ||
			mount.Destination == string(filepath.Separator) ||
			(mount.Source != "" &&
				!validAbsolutePath(mount.Source)) ||
			(mount.Propagation != "" &&
				mount.Propagation != "rprivate") {
			return false
		}
		if _, exists := seen[mount.Destination]; exists {
			return false
		}
		seen[mount.Destination] = struct{}{}
	}
	return true
}

func validTask11SyntheticStructuralTmpfs(
	tmpfs map[string]string,
) bool {
	for path, options := range tmpfs {
		if !validAbsolutePath(path) ||
			path == string(filepath.Separator) ||
			options == "" {
			return false
		}
	}
	return true
}

func cloneTask11SyntheticStringMap(
	source map[string]string,
) map[string]string {
	if source == nil {
		return nil
	}
	cloned := make(map[string]string, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}

type task11SyntheticProcCgroupEntry struct {
	controllers []string
	path        string
}

type task11SyntheticCgroupMount struct {
	root        string
	mountPoint  string
	controllers []string
}

func task11SyntheticCgroupPaths(
	cgroupDocument []byte,
	mountInfoDocument []byte,
	version task11synthetic.CgroupVersion,
) ([]string, error) {
	entries, err := parseTask11SyntheticProcCgroup(
		cgroupDocument,
		version,
	)
	if err != nil {
		return nil, ErrFixtureStart
	}
	mounts, err := parseTask11SyntheticCgroupMounts(
		mountInfoDocument,
		version,
	)
	if err != nil {
		return nil, ErrFixtureStart
	}
	var paths []string
	switch version {
	case task11synthetic.CgroupV2:
		if len(entries) != 1 || len(mounts) != 1 {
			return nil, ErrFixtureStart
		}
		path, ok := resolveTask11SyntheticCgroupPath(
			entries[0].path,
			mounts[0],
		)
		if !ok {
			return nil, ErrFixtureStart
		}
		paths = append(paths, path)
	case task11synthetic.CgroupV1:
		for _, controller := range []string{"memory", "pids"} {
			entry, entryOK := task11SyntheticCgroupEntryFor(
				entries,
				controller,
			)
			mount, mountOK := task11SyntheticCgroupMountFor(
				mounts,
				controller,
			)
			if !entryOK || !mountOK {
				return nil, ErrFixtureStart
			}
			path, ok := resolveTask11SyntheticCgroupPath(
				entry.path,
				mount,
			)
			if !ok {
				return nil, ErrFixtureStart
			}
			paths = append(paths, path)
		}
	default:
		return nil, ErrFixtureStart
	}
	sort.Strings(paths)
	unique := paths[:0]
	for _, path := range paths {
		if len(unique) == 0 || unique[len(unique)-1] != path {
			unique = append(unique, path)
		}
	}
	if len(unique) == 0 {
		return nil, ErrFixtureStart
	}
	return append([]string(nil), unique...), nil
}

func parseTask11SyntheticProcCgroup(
	document []byte,
	version task11synthetic.CgroupVersion,
) ([]task11SyntheticProcCgroupEntry, error) {
	lines, ok := task11SyntheticCanonicalLines(document, 64)
	if !ok {
		return nil, ErrFixtureStart
	}
	entries := make([]task11SyntheticProcCgroupEntry, 0, len(lines))
	for _, line := range lines {
		parts := strings.Split(line, ":")
		if len(parts) != 3 {
			return nil, ErrFixtureStart
		}
		hierarchy, err := strconv.ParseUint(parts[0], 10, 31)
		if err != nil ||
			strconv.FormatUint(hierarchy, 10) != parts[0] ||
			!validAbsolutePath(parts[2]) ||
			parts[2] == string(filepath.Separator) {
			return nil, ErrFixtureStart
		}
		var controllers []string
		if parts[1] != "" {
			controllers = strings.Split(parts[1], ",")
			seen := make(map[string]struct{}, len(controllers))
			for _, controller := range controllers {
				if controller == "" ||
					strings.ContainsAny(controller, "/:\\\x00\r\n\t ") {
					return nil, ErrFixtureStart
				}
				if _, exists := seen[controller]; exists {
					return nil, ErrFixtureStart
				}
				seen[controller] = struct{}{}
			}
			sort.Strings(controllers)
		}
		if version == task11synthetic.CgroupV2 {
			if hierarchy != 0 || len(controllers) != 0 ||
				len(lines) != 1 {
				return nil, ErrFixtureStart
			}
		} else if version != task11synthetic.CgroupV1 ||
			hierarchy == 0 ||
			len(controllers) == 0 {
			return nil, ErrFixtureStart
		}
		entries = append(entries, task11SyntheticProcCgroupEntry{
			controllers: append([]string(nil), controllers...),
			path:        parts[2],
		})
	}
	return entries, nil
}

func parseTask11SyntheticCgroupMounts(
	document []byte,
	version task11synthetic.CgroupVersion,
) ([]task11SyntheticCgroupMount, error) {
	lines, ok := task11SyntheticCanonicalLines(document, 4096)
	if !ok {
		return nil, ErrFixtureStart
	}
	var mounts []task11SyntheticCgroupMount
	for _, line := range lines {
		fields := strings.Fields(line)
		separator := -1
		for index, field := range fields {
			if field == "-" {
				if separator >= 0 {
					return nil, ErrFixtureStart
				}
				separator = index
			}
		}
		if separator < 6 || separator+3 >= len(fields) {
			return nil, ErrFixtureStart
		}
		fsType := fields[separator+1]
		if fsType != "cgroup" && fsType != "cgroup2" {
			continue
		}
		root, rootOK := decodeTask11SyntheticMountPath(fields[3])
		mountPoint, pointOK :=
			decodeTask11SyntheticMountPath(fields[4])
		if !rootOK ||
			!pointOK ||
			!validAbsolutePath(root) ||
			!validAbsolutePath(mountPoint) {
			return nil, ErrFixtureStart
		}
		superOptions := strings.Split(fields[separator+3], ",")
		sort.Strings(superOptions)
		switch version {
		case task11synthetic.CgroupV2:
			if fsType != "cgroup2" {
				continue
			}
			mounts = append(mounts, task11SyntheticCgroupMount{
				root:       root,
				mountPoint: mountPoint,
			})
		case task11synthetic.CgroupV1:
			if fsType != "cgroup" {
				continue
			}
			var controllers []string
			for _, controller := range []string{"memory", "pids"} {
				if task11SyntheticStringPresent(
					superOptions,
					controller,
				) {
					controllers = append(controllers, controller)
				}
			}
			if len(controllers) != 0 {
				mounts = append(mounts, task11SyntheticCgroupMount{
					root:        root,
					mountPoint:  mountPoint,
					controllers: controllers,
				})
			}
		default:
			return nil, ErrFixtureStart
		}
	}
	return mounts, nil
}

func task11SyntheticCgroupEntryFor(
	entries []task11SyntheticProcCgroupEntry,
	controller string,
) (task11SyntheticProcCgroupEntry, bool) {
	var (
		found task11SyntheticProcCgroupEntry
		count int
	)
	for _, entry := range entries {
		if task11SyntheticStringPresent(
			entry.controllers,
			controller,
		) {
			found = entry
			count++
		}
	}
	return found, count == 1
}

func task11SyntheticCgroupMountFor(
	mounts []task11SyntheticCgroupMount,
	controller string,
) (task11SyntheticCgroupMount, bool) {
	var (
		found task11SyntheticCgroupMount
		count int
	)
	for _, mount := range mounts {
		if task11SyntheticStringPresent(
			mount.controllers,
			controller,
		) {
			found = mount
			count++
		}
	}
	return found, count == 1
}

func resolveTask11SyntheticCgroupPath(
	cgroupPath string,
	mount task11SyntheticCgroupMount,
) (string, bool) {
	if !validAbsolutePath(cgroupPath) ||
		cgroupPath == string(filepath.Separator) ||
		!validAbsolutePath(mount.root) ||
		!validAbsolutePath(mount.mountPoint) {
		return "", false
	}
	relative, err := filepath.Rel(mount.root, cgroupPath)
	if err != nil ||
		relative == "." ||
		relative == ".." ||
		strings.HasPrefix(
			relative,
			".."+string(filepath.Separator),
		) ||
		filepath.IsAbs(relative) {
		return "", false
	}
	resolved := filepath.Join(mount.mountPoint, relative)
	return resolved, validAbsolutePath(resolved) &&
		resolved != mount.mountPoint
}

func decodeTask11SyntheticMountPath(value string) (string, bool) {
	if value == "" {
		return "", false
	}
	var decoded strings.Builder
	for index := 0; index < len(value); {
		if value[index] != '\\' {
			decoded.WriteByte(value[index])
			index++
			continue
		}
		if index+4 > len(value) {
			return "", false
		}
		var replacement byte
		switch value[index : index+4] {
		case `\040`:
			replacement = ' '
		case `\011`:
			replacement = '\t'
		case `\012`:
			replacement = '\n'
		case `\134`:
			replacement = '\\'
		default:
			return "", false
		}
		decoded.WriteByte(replacement)
		index += 4
	}
	result := decoded.String()
	return result, !strings.ContainsAny(result, "\x00\r\n\t")
}

func parseTask11SyntheticCgroupMembers(
	document []byte,
	maximum uint64,
) ([]int, error) {
	if maximum == 0 || maximum > uint64(^uint(0)>>1) {
		return nil, ErrFixtureStart
	}
	lines, ok := task11SyntheticCanonicalLines(document, int(maximum))
	if !ok {
		return nil, ErrFixtureStart
	}
	members := make([]int, 0, len(lines))
	var previous uint64
	for index, line := range lines {
		value, err := strconv.ParseUint(line, 10, 31)
		if err != nil ||
			value == 0 ||
			strconv.FormatUint(value, 10) != line ||
			(index > 0 && value <= previous) {
			return nil, ErrFixtureStart
		}
		members = append(members, int(value))
		previous = value
	}
	return members, nil
}

func task11SyntheticCanonicalLines(
	document []byte,
	maximumLines int,
) ([]string, bool) {
	if len(document) == 0 ||
		len(document) > int(maximumPermitProcDocumentBytes) ||
		document[len(document)-1] != '\n' ||
		bytes.IndexByte(document, 0) >= 0 ||
		bytes.IndexByte(document, '\r') >= 0 ||
		maximumLines <= 0 {
		return nil, false
	}
	lines := strings.Split(string(document[:len(document)-1]), "\n")
	if len(lines) == 0 || len(lines) > maximumLines {
		return nil, false
	}
	for _, line := range lines {
		if line == "" {
			return nil, false
		}
	}
	return lines, true
}

func task11SyntheticStringPresent(
	values []string,
	target string,
) bool {
	index := sort.SearchStrings(values, target)
	return index < len(values) && values[index] == target
}
