//go:build integration && linux

package testenv

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
	"github.com/sumitake/portable-ghar/internal/task11synthetic"
	"golang.org/x/sys/unix"
)

const (
	task11SyntheticStructuralInspectFormat = `{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"running":{{json .State.Running}},"pid":{{json .State.Pid}},"sandbox_key":{{json .NetworkSettings.SandboxKey}},"mounts":{{json .Mounts}},"tmpfs":{{json .HostConfig.Tmpfs}}}`
	task11SyntheticRelaySocketName         = "https.sock"
	task11SyntheticAuthoritySocketName     = "dial-authority.sock"
)

type task11SyntheticAuthorityAbsenceProver interface {
	ProveIntegrationAuthorityAbsent(
		context.Context,
		networkjail.CapacitySlotID,
		networkjail.JobGeneration,
		string,
	) error
}

type linuxTask11SyntheticPathIdentity struct {
	Path   string `json:"path"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Mode   uint32 `json:"mode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
}

type linuxTask11SyntheticProcessIdentity struct {
	PID        int                                `json:"pid"`
	StartTime  uint64                             `json:"start_time"`
	Namespaces []linuxTask11SyntheticPathIdentity `json:"namespaces"`
	FDs        []linuxTask11SyntheticPathIdentity `json:"fds"`
}

type linuxTask11SyntheticStructuralCapture struct {
	BindingDigest string                                `json:"binding_digest"`
	Containers    []task11SyntheticStructuralInspect    `json:"containers"`
	Cgroups       []linuxTask11SyntheticPathIdentity    `json:"cgroups"`
	Processes     []linuxTask11SyntheticProcessIdentity `json:"processes"`
	Sandboxes     []linuxTask11SyntheticPathIdentity    `json:"sandboxes"`
	RootEntries   []linuxTask11SyntheticPathIdentity    `json:"root_entries"`
	Sockets       []linuxTask11SyntheticPathIdentity    `json:"sockets"`
}

type linuxTask11SyntheticCleanupProbe struct {
	dockerPath string
	command    hostruntime.CommandRunner
	recovery   hostruntime.ManagedRecovery
	root       *linuxTask11SyntheticCycleRoot
	authority  task11SyntheticAuthorityAbsenceProver
	procRoot   string
	mountInfo  string

	mu      sync.Mutex
	armed   bool
	proved  bool
	capture linuxTask11SyntheticStructuralCapture
	seal    task11SyntheticCleanupCapture
}

func newLinuxTask11SyntheticCleanupProbe(
	dockerPath string,
	command hostruntime.CommandRunner,
	recovery hostruntime.ManagedRecovery,
	root *linuxTask11SyntheticCycleRoot,
	authority task11SyntheticAuthorityAbsenceProver,
) (*linuxTask11SyntheticCleanupProbe, error) {
	if !validAbsolutePath(dockerPath) ||
		command == nil ||
		recovery == nil ||
		root == nil ||
		authority == nil {
		return nil, ErrFixtureStart
	}
	return &linuxTask11SyntheticCleanupProbe{
		dockerPath: dockerPath,
		command:    command,
		recovery:   recovery,
		root:       root,
		authority:  authority,
		procRoot:   "/proc",
		mountInfo:  "/proc/self/mountinfo",
	}, nil
}

func (p *linuxTask11SyntheticCleanupProbe) ArmStructural(
	ctx context.Context,
	binding task11SyntheticCleanupObserverBinding,
	snapshot hostruntime.ManagedSnapshot,
) (task11SyntheticCleanupCapture, error) {
	if p == nil || ctx == nil || ctx.Err() != nil {
		return task11SyntheticCleanupCapture{}, ErrFixtureStart
	}
	p.mu.Lock()
	if p.armed || p.proved {
		p.mu.Unlock()
		return task11SyntheticCleanupCapture{}, ErrFixtureStart
	}
	p.armed = true
	p.mu.Unlock()

	capture, err := p.captureStructural(ctx, binding, snapshot)
	if err != nil {
		return task11SyntheticCleanupCapture{}, ErrFixtureStart
	}
	digest, err := recordingCanonicalDigest(
		"portable-ghar.task11.synthetic-structural-capture.v1\x00",
		capture,
	)
	raw, decodeErr := hex.DecodeString(digest)
	if err != nil ||
		decodeErr != nil ||
		len(raw) != sha256.Size {
		return task11SyntheticCleanupCapture{}, ErrFixtureStart
	}
	var sealBytes [sha256.Size]byte
	copy(sealBytes[:], raw)
	seal, err := newTask11SyntheticCleanupCapture(
		binding,
		sealBytes,
	)
	if err != nil {
		return task11SyntheticCleanupCapture{}, ErrFixtureStart
	}
	p.mu.Lock()
	p.capture = capture
	p.seal = seal
	p.mu.Unlock()
	return seal, nil
}

func (p *linuxTask11SyntheticCleanupProbe) Prove(
	ctx context.Context,
	binding task11SyntheticCleanupObserverBinding,
	capture task11SyntheticCleanupCapture,
	outcome task11SyntheticCleanupOutcomeSeal,
) (task11synthetic.CleanupObservation, error) {
	if p == nil || ctx == nil || ctx.Err() != nil {
		return task11synthetic.CleanupObservation{}, ErrFixtureCleanup
	}
	p.mu.Lock()
	if !p.armed ||
		p.proved ||
		capture != p.seal ||
		outcome.bindingDigest != capture.bindingDigest ||
		outcome.structuralSeal != capture.seal ||
		!isLowerHex(outcome.digest, 64) {
		p.proved = true
		p.mu.Unlock()
		return task11synthetic.CleanupObservation{}, ErrFixtureCleanup
	}
	p.proved = true
	structural := p.capture
	p.mu.Unlock()

	if err := p.proveStructuralAbsence(
		ctx,
		binding,
		structural,
	); err != nil {
		if errors.Is(err, ErrFixtureUnexpectedObject) {
			return task11synthetic.CleanupObservation{},
				ErrFixtureUnexpectedObject
		}
		return task11synthetic.CleanupObservation{}, ErrFixtureCleanup
	}
	return task11synthetic.CleanupObservation{
		SchemaVersion:           task11synthetic.SchemaVersion,
		ProtocolID:              task11synthetic.ProtocolID,
		CycleRunDigest:          binding.Cycle.RunDigest,
		CleanupDigest:           binding.Cycle.CleanupDigest,
		CgroupVersion:           binding.CgroupVersion,
		ContainersAbsent:        true,
		CgroupsAbsent:           true,
		TmpfsAbsent:             true,
		WorkAbsent:              true,
		WorkUpdateAbsent:        true,
		ProcessesAbsent:         true,
		NamespacesAbsent:        true,
		SocketsAbsent:           true,
		AuthoritiesAbsent:       true,
		TemporaryFilesAbsent:    true,
		HostBackedWorkAbsent:    true,
		UnexpectedObjectsAbsent: true,
		PayloadVersionCount:     binding.PayloadVersionCount,
		AssertionCount:          13,
	}, nil
}

func (p *linuxTask11SyntheticCleanupProbe) captureStructural(
	ctx context.Context,
	binding task11SyntheticCleanupObserverBinding,
	snapshot hostruntime.ManagedSnapshot,
) (linuxTask11SyntheticStructuralCapture, error) {
	if !task11SyntheticCleanupObserverBindingValid(binding) ||
		snapshot.Observation() != binding.Expected ||
		snapshot.Identities() != (hostruntime.RecoveredIdentities{
			AdapterID: binding.Recovery.ExpectedAdapterID,
			BrokerID:  binding.Recovery.ExpectedBrokerID,
			RunnerID:  binding.Recovery.ExpectedRunnerID,
		}) {
		return linuxTask11SyntheticStructuralCapture{}, ErrFixtureStart
	}
	bindingDigest, err :=
		task11SyntheticCleanupObserverBindingDigest(binding)
	if err != nil {
		return linuxTask11SyntheticStructuralCapture{}, ErrFixtureStart
	}
	capture := linuxTask11SyntheticStructuralCapture{
		BindingDigest: bindingDigest,
	}
	components := []struct {
		present bool
		running bool
		id      string
		name    string
		kind    string
	}{
		{
			binding.Expected.AdapterPresent,
			binding.Expected.AdapterRunning,
			binding.Recovery.ExpectedAdapterID,
			binding.Recovery.AdapterName,
			"adapter",
		},
		{
			binding.Expected.BrokerPresent,
			binding.Expected.BrokerRunning,
			binding.Recovery.ExpectedBrokerID,
			binding.Recovery.BrokerName,
			"broker",
		},
		{
			binding.Expected.RunnerPresent,
			binding.Expected.RunnerRunning,
			binding.Recovery.ExpectedRunnerID,
			binding.Recovery.RunnerName,
			"runner",
		},
	}
	var runner task11SyntheticStructuralInspect
	for _, component := range components {
		if !component.present {
			continue
		}
		inspect, err := p.inspectContainer(ctx, component.id)
		if err != nil ||
			inspect.ID != component.id ||
			inspect.Name != component.name ||
			inspect.Running != component.running ||
			!task11SyntheticComponentLayoutMatches(
				component.kind,
				inspect,
				binding,
			) {
			return linuxTask11SyntheticStructuralCapture{},
				ErrFixtureStart
		}
		if component.kind == "runner" {
			if !inspect.Running || inspect.PID <= 0 {
				return linuxTask11SyntheticStructuralCapture{},
					ErrFixtureStart
			}
			runner = inspect
		}
		capture.Containers = append(capture.Containers, inspect)
		if inspect.SandboxKey != "" {
			identity, err := task11SyntheticPathIdentity(
				inspect.SandboxKey,
				true,
			)
			if err != nil {
				return linuxTask11SyntheticStructuralCapture{},
					ErrFixtureStart
			}
			capture.Sandboxes = append(
				capture.Sandboxes,
				identity,
			)
		}
	}
	var unique bool
	capture.Sandboxes, unique = uniqueTask11SyntheticPathIdentities(
		capture.Sandboxes,
	)
	if !unique {
		return linuxTask11SyntheticStructuralCapture{},
			ErrFixtureStart
	}
	if binding.Expected.RunnerPresent {
		cgroups, processes, err := p.captureRunnerCgroup(
			ctx,
			runner.PID,
			binding,
		)
		if err != nil {
			return linuxTask11SyntheticStructuralCapture{},
				ErrFixtureStart
		}
		capture.Cgroups = cgroups
		capture.Processes = processes
	}
	rootEntries, sockets, err := p.captureCyclePaths(binding)
	if err != nil {
		return linuxTask11SyntheticStructuralCapture{},
			ErrFixtureStart
	}
	capture.RootEntries = rootEntries
	capture.Sockets = sockets
	if err := p.revalidateStructuralCapture(
		ctx,
		capture,
	); err != nil {
		return linuxTask11SyntheticStructuralCapture{},
			ErrFixtureStart
	}
	return capture, nil
}

func (p *linuxTask11SyntheticCleanupProbe) inspectContainer(
	ctx context.Context,
	id string,
) (task11SyntheticStructuralInspect, error) {
	if ctx == nil || ctx.Err() != nil || !isLowerHex(id, 64) {
		return task11SyntheticStructuralInspect{}, ErrFixtureStart
	}
	result, err := p.command.Run(
		ctx,
		[]string{
			p.dockerPath,
			"container",
			"inspect",
			"--format",
			task11SyntheticStructuralInspectFormat,
			id,
		},
		nil,
		nil,
	)
	if err != nil ||
		result.ExitCode != 0 ||
		result.Signaled ||
		result.StdoutTruncated ||
		result.StderrTruncated ||
		len(result.Stderr) != 0 {
		return task11SyntheticStructuralInspect{}, ErrFixtureStart
	}
	return parseTask11SyntheticStructuralInspect(result.Stdout)
}

func (p *linuxTask11SyntheticCleanupProbe) revalidateStructuralCapture(
	ctx context.Context,
	capture linuxTask11SyntheticStructuralCapture,
) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrFixtureStart
	}
	for _, expected := range capture.Containers {
		current, err := p.inspectContainer(ctx, expected.ID)
		if err != nil {
			return ErrFixtureStart
		}
		expectedDigest, expectedErr := recordingCanonicalDigest(
			"portable-ghar.task11.synthetic-container-capture.v1\x00",
			expected,
		)
		currentDigest, currentErr := recordingCanonicalDigest(
			"portable-ghar.task11.synthetic-container-capture.v1\x00",
			current,
		)
		if expectedErr != nil ||
			currentErr != nil ||
			expectedDigest != currentDigest {
			return ErrFixtureStart
		}
	}
	for _, collection := range []struct {
		values []linuxTask11SyntheticPathIdentity
		follow bool
	}{
		{capture.Cgroups, false},
		{capture.Sandboxes, true},
		{capture.RootEntries, false},
		{capture.Sockets, false},
	} {
		for _, expected := range collection.values {
			current, err := task11SyntheticPathIdentity(
				expected.Path,
				collection.follow,
			)
			if err != nil || current != expected {
				return ErrFixtureStart
			}
		}
	}
	return nil
}

func task11SyntheticComponentLayoutMatches(
	kind string,
	inspect task11SyntheticStructuralInspect,
	binding task11SyntheticCleanupObserverBinding,
) bool {
	switch kind {
	case "adapter":
		return len(inspect.Mounts) == 1 &&
			task11SyntheticMountMatches(
				inspect.Mounts[0],
				binding.Recovery.RelayParent,
				"/run/portable-ghar/broker",
				false,
			) &&
			len(inspect.Tmpfs) == 0
	case "broker":
		if len(inspect.Mounts) != 2 || len(inspect.Tmpfs) != 0 {
			return false
		}
		mounts := append(
			[]task11SyntheticStructuralMount(nil),
			inspect.Mounts...,
		)
		sort.Slice(mounts, func(i, j int) bool {
			return mounts[i].Destination <
				mounts[j].Destination
		})
		return task11SyntheticMountMatches(
			mounts[0],
			binding.Recovery.AuthorityParent,
			"/run/portable-ghar/authority",
			false,
		) &&
			task11SyntheticMountMatches(
				mounts[1],
				binding.Recovery.RelayParent,
				"/run/portable-ghar/relay",
				true,
			)
	case "runner":
		return len(inspect.Mounts) == 0 &&
			len(inspect.Tmpfs) == 2 &&
			inspect.Tmpfs["/runner"] != "" &&
			inspect.Tmpfs["/tmp"] != ""
	default:
		return false
	}
}

func task11SyntheticMountMatches(
	mount task11SyntheticStructuralMount,
	source string,
	destination string,
	readWrite bool,
) bool {
	return mount.Type == "bind" &&
		mount.Name == "" &&
		mount.Source == source &&
		mount.Destination == destination &&
		mount.Driver == "" &&
		mount.Mode == "" &&
		mount.RW == readWrite &&
		(mount.Propagation == "" ||
			mount.Propagation == "rprivate")
}

func (p *linuxTask11SyntheticCleanupProbe) captureRunnerCgroup(
	ctx context.Context,
	runnerPID int,
	binding task11SyntheticCleanupObserverBinding,
) (
	[]linuxTask11SyntheticPathIdentity,
	[]linuxTask11SyntheticProcessIdentity,
	error,
) {
	if ctx == nil || ctx.Err() != nil || runnerPID <= 0 {
		return nil, nil, ErrFixtureStart
	}
	cgroupDocument, err := readTask11SyntheticBoundedFile(
		filepath.Join(
			p.procRoot,
			strconv.Itoa(runnerPID),
			"cgroup",
		),
	)
	if err != nil {
		return nil, nil, ErrFixtureStart
	}
	mountInfoDocument, err := readTask11SyntheticBoundedFile(
		p.mountInfo,
	)
	if err != nil {
		return nil, nil, ErrFixtureStart
	}
	paths, err := task11SyntheticCgroupPaths(
		cgroupDocument,
		mountInfoDocument,
		binding.CgroupVersion,
	)
	if err != nil {
		return nil, nil, ErrFixtureStart
	}
	cgroups := make(
		[]linuxTask11SyntheticPathIdentity,
		0,
		len(paths),
	)
	members := make(map[int]struct{})
	for _, path := range paths {
		identity, err := task11SyntheticPathIdentity(path, false)
		if err != nil || identity.Mode&unix.S_IFMT != unix.S_IFDIR {
			return nil, nil, ErrFixtureStart
		}
		cgroups = append(cgroups, identity)
		document, err := readTask11SyntheticBoundedFile(
			filepath.Join(path, "cgroup.procs"),
		)
		if err != nil {
			return nil, nil, ErrFixtureStart
		}
		current, err := parseTask11SyntheticCgroupMembers(
			document,
			binding.MaximumProcesses,
		)
		if err != nil {
			return nil, nil, ErrFixtureStart
		}
		for _, pid := range current {
			members[pid] = struct{}{}
		}
	}
	if _, ok := members[runnerPID]; !ok ||
		uint64(len(members)) > binding.MaximumProcesses {
		return nil, nil, ErrFixtureStart
	}
	pids := make([]int, 0, len(members))
	for pid := range members {
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	processes := make(
		[]linuxTask11SyntheticProcessIdentity,
		0,
		len(pids),
	)
	for _, pid := range pids {
		process, err := p.captureProcess(pid, binding)
		if err != nil {
			return nil, nil, ErrFixtureStart
		}
		processes = append(processes, process)
	}
	return cgroups, processes, nil
}

func (p *linuxTask11SyntheticCleanupProbe) captureProcess(
	pid int,
	binding task11SyntheticCleanupObserverBinding,
) (linuxTask11SyntheticProcessIdentity, error) {
	first, err := p.processStartTime(pid)
	if err != nil {
		return linuxTask11SyntheticProcessIdentity{},
			ErrFixtureStart
	}
	namespaces, err := p.captureProcessNamespaces(pid)
	if err != nil {
		return linuxTask11SyntheticProcessIdentity{},
			ErrFixtureStart
	}
	fds, err := p.captureProcessFDs(
		pid,
		binding.MaximumFileDescriptors,
	)
	if err != nil {
		return linuxTask11SyntheticProcessIdentity{},
			ErrFixtureStart
	}
	second, err := p.processStartTime(pid)
	if err != nil || second != first {
		return linuxTask11SyntheticProcessIdentity{},
			ErrFixtureStart
	}
	return linuxTask11SyntheticProcessIdentity{
		PID:        pid,
		StartTime:  first,
		Namespaces: namespaces,
		FDs:        fds,
	}, nil
}

func (p *linuxTask11SyntheticCleanupProbe) processStartTime(
	pid int,
) (uint64, error) {
	if pid <= 0 {
		return 0, ErrFixtureStart
	}
	document, err := readTask11SyntheticBoundedFile(
		filepath.Join(
			p.procRoot,
			strconv.Itoa(pid),
			"stat",
		),
	)
	if err != nil {
		return 0, ErrFixtureStart
	}
	return parsePermitProcStatStartTime(document)
}

func (p *linuxTask11SyntheticCleanupProbe) captureProcessNamespaces(
	pid int,
) ([]linuxTask11SyntheticPathIdentity, error) {
	directory := filepath.Join(
		p.procRoot,
		strconv.Itoa(pid),
		"ns",
	)
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) == 0 || len(entries) > 10 {
		return nil, ErrFixtureStart
	}
	allowed := map[string]bool{
		"cgroup":            false,
		"ipc":               false,
		"mnt":               false,
		"net":               false,
		"pid":               false,
		"pid_for_children":  false,
		"time":              false,
		"time_for_children": false,
		"user":              false,
		"uts":               false,
	}
	required := map[string]struct{}{
		"cgroup": {},
		"ipc":    {},
		"mnt":    {},
		"net":    {},
		"pid":    {},
		"user":   {},
		"uts":    {},
	}
	identities := make(
		[]linuxTask11SyntheticPathIdentity,
		0,
		len(entries),
	)
	for _, entry := range entries {
		if _, ok := allowed[entry.Name()]; !ok ||
			allowed[entry.Name()] {
			return nil, ErrFixtureStart
		}
		allowed[entry.Name()] = true
		identity, err := task11SyntheticPathIdentity(
			filepath.Join(directory, entry.Name()),
			true,
		)
		if err != nil || identity.Inode == 0 {
			return nil, ErrFixtureStart
		}
		identities = append(identities, identity)
	}
	for name := range required {
		if !allowed[name] {
			return nil, ErrFixtureStart
		}
	}
	return identities, nil
}

func (p *linuxTask11SyntheticCleanupProbe) captureProcessFDs(
	pid int,
	maximum uint64,
) ([]linuxTask11SyntheticPathIdentity, error) {
	if maximum == 0 || maximum > uint64(^uint(0)>>1) {
		return nil, ErrFixtureStart
	}
	directory := filepath.Join(
		p.procRoot,
		strconv.Itoa(pid),
		"fd",
	)
	entries, err := os.ReadDir(directory)
	if err != nil ||
		len(entries) == 0 ||
		uint64(len(entries)) > maximum {
		return nil, ErrFixtureStart
	}
	identities := make(
		[]linuxTask11SyntheticPathIdentity,
		0,
		len(entries),
	)
	seen := make(map[uint64]struct{}, len(entries))
	for _, entry := range entries {
		value, err := strconv.ParseUint(entry.Name(), 10, 31)
		if err != nil ||
			value >= maximum ||
			strconv.FormatUint(value, 10) != entry.Name() {
			return nil, ErrFixtureStart
		}
		if _, exists := seen[value]; exists {
			return nil, ErrFixtureStart
		}
		seen[value] = struct{}{}
		identity, err := task11SyntheticPathIdentity(
			filepath.Join(directory, entry.Name()),
			true,
		)
		if err != nil || identity.Inode == 0 {
			return nil, ErrFixtureStart
		}
		identities = append(identities, identity)
	}
	sort.Slice(identities, func(i, j int) bool {
		return identities[i].Path < identities[j].Path
	})
	return identities, nil
}

func (p *linuxTask11SyntheticCleanupProbe) captureCyclePaths(
	binding task11SyntheticCleanupObserverBinding,
) (
	[]linuxTask11SyntheticPathIdentity,
	[]linuxTask11SyntheticPathIdentity,
	error,
) {
	names, err := p.root.snapshotEntries()
	if err != nil {
		return nil, nil, ErrFixtureStart
	}
	sort.Strings(names)
	expected := []string{"authority", "relay"}
	if strings.Join(names, "\x00") !=
		strings.Join(expected, "\x00") {
		return nil, nil, ErrFixtureStart
	}
	entries := make(
		[]linuxTask11SyntheticPathIdentity,
		0,
		len(names),
	)
	for _, name := range names {
		path := filepath.Join(binding.Cycle.Root, name)
		identity, err := task11SyntheticPathIdentity(
			path,
			false,
		)
		if err != nil || identity.Mode&unix.S_IFMT != unix.S_IFDIR {
			return nil, nil, ErrFixtureStart
		}
		directoryEntries, err := os.ReadDir(path)
		if err != nil {
			return nil, nil, ErrFixtureStart
		}
		expectedEntry := ""
		switch name {
		case "authority":
			if binding.AuthorityExpected {
				expectedEntry = task11SyntheticAuthoritySocketName
			}
		case "relay":
			if binding.RelaySocketExpected {
				expectedEntry = task11SyntheticRelaySocketName
			}
		default:
			return nil, nil, ErrFixtureStart
		}
		if (expectedEntry == "" && len(directoryEntries) != 0) ||
			(expectedEntry != "" &&
				(len(directoryEntries) != 1 ||
					directoryEntries[0].Name() != expectedEntry)) {
			return nil, nil, ErrFixtureStart
		}
		entries = append(entries, identity)
	}
	var sockets []linuxTask11SyntheticPathIdentity
	socketExpectations := []struct {
		expected bool
		path     string
	}{
		{
			binding.AuthorityExpected,
			filepath.Join(
				binding.Recovery.AuthorityParent,
				task11SyntheticAuthoritySocketName,
			),
		},
		{
			binding.RelaySocketExpected,
			filepath.Join(
				binding.Recovery.RelayParent,
				task11SyntheticRelaySocketName,
			),
		},
	}
	for _, expectation := range socketExpectations {
		identity, err := task11SyntheticPathIdentity(
			expectation.path,
			false,
		)
		if expectation.expected {
			if err != nil ||
				identity.Mode&unix.S_IFMT != unix.S_IFSOCK {
				return nil, nil, ErrFixtureStart
			}
			sockets = append(sockets, identity)
			continue
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, nil, ErrFixtureStart
		}
	}
	return entries, sockets, nil
}

func (p *linuxTask11SyntheticCleanupProbe) proveStructuralAbsence(
	ctx context.Context,
	binding task11SyntheticCleanupObserverBinding,
	capture linuxTask11SyntheticStructuralCapture,
) error {
	if ctx == nil ||
		ctx.Err() != nil ||
		capture.BindingDigest == "" ||
		capture.BindingDigest !=
			mustTask11SyntheticBindingDigestForProbe(binding) ||
		binding.PayloadVersionCount != 1 {
		return ErrFixtureCleanup
	}
	snapshot, err := p.recovery.InspectManaged(
		ctx,
		binding.Recovery,
	)
	if err != nil ||
		snapshot.Observation() != (hostruntime.ManagedObservation{}) ||
		snapshot.Identities() != (hostruntime.RecoveredIdentities{}) {
		return ErrFixtureCleanup
	}
	for _, container := range capture.Containers {
		if err := p.proveContainerAbsent(ctx, container.ID); err != nil {
			return ErrFixtureCleanup
		}
	}
	for _, cgroup := range capture.Cgroups {
		if err := task11SyntheticPathAbsent(cgroup.Path); err != nil {
			return ErrFixtureCleanup
		}
	}
	for _, process := range capture.Processes {
		current, err := p.processStartTime(process.PID)
		if err == nil && current == process.StartTime {
			return ErrFixtureCleanup
		}
		if err != nil && !task11SyntheticProcPathAbsent(
			p.procRoot,
			process.PID,
		) {
			return ErrFixtureCleanup
		}
	}
	for _, path := range append(
		append(
			[]linuxTask11SyntheticPathIdentity(nil),
			capture.Sandboxes...,
		),
		append(capture.Sockets, capture.RootEntries...)...,
	) {
		if err := task11SyntheticPathAbsent(path.Path); err != nil {
			return ErrFixtureCleanup
		}
	}
	if err := p.authority.ProveIntegrationAuthorityAbsent(
		ctx,
		networkjail.CapacitySlotID(binding.CapacitySlotID),
		networkjail.JobGeneration(binding.JobGeneration),
		binding.Recovery.AuthorityParent,
	); err != nil {
		return ErrFixtureCleanup
	}
	names, err := p.root.snapshotEntries()
	if err != nil {
		return ErrFixtureCleanup
	}
	if len(names) != 0 {
		return ErrFixtureUnexpectedObject
	}
	if err := p.root.removeEmpty(); err != nil {
		return err
	}
	if err := task11SyntheticPathAbsent(
		binding.Cycle.Root,
	); err != nil {
		return ErrFixtureCleanup
	}
	return nil
}

func (p *linuxTask11SyntheticCleanupProbe) proveContainerAbsent(
	ctx context.Context,
	id string,
) error {
	result, err := p.command.Run(
		ctx,
		[]string{
			p.dockerPath,
			"container",
			"inspect",
			"--format",
			"{{json .Id}}",
			id,
		},
		nil,
		nil,
	)
	if err != nil ||
		result.ExitCode == 0 ||
		result.Signaled ||
		result.StdoutTruncated ||
		result.StderrTruncated ||
		len(result.Stdout) != 0 ||
		!task11SyntheticContainerNotFound(result.Stderr, id) {
		return ErrFixtureCleanup
	}
	return nil
}

func task11SyntheticContainerNotFound(
	stderr []byte,
	id string,
) bool {
	if !isLowerHex(id, 64) {
		return false
	}
	for _, prefix := range []string{
		"Error: No such container: ",
		"Error: No such object: ",
		"Error response from daemon: No such container: ",
	} {
		if bytes.Equal(
			stderr,
			[]byte(prefix+id+"\n"),
		) {
			return true
		}
	}
	return false
}

func task11SyntheticPathIdentity(
	path string,
	follow bool,
) (linuxTask11SyntheticPathIdentity, error) {
	if !validAbsolutePath(path) {
		return linuxTask11SyntheticPathIdentity{},
			ErrFixtureStart
	}
	var (
		stat unix.Stat_t
		err  error
	)
	if follow {
		err = unix.Stat(path, &stat)
	} else {
		err = unix.Lstat(path, &stat)
	}
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return linuxTask11SyntheticPathIdentity{}, os.ErrNotExist
		}
		return linuxTask11SyntheticPathIdentity{}, ErrFixtureStart
	}
	if !follow && stat.Mode&unix.S_IFMT == unix.S_IFLNK {
		return linuxTask11SyntheticPathIdentity{},
			ErrFixtureStart
	}
	return linuxTask11SyntheticPathIdentity{
		Path:   path,
		Device: uint64(stat.Dev),
		Inode:  stat.Ino,
		Mode:   stat.Mode,
		UID:    stat.Uid,
		GID:    stat.Gid,
	}, nil
}

func uniqueTask11SyntheticPathIdentities(
	values []linuxTask11SyntheticPathIdentity,
) ([]linuxTask11SyntheticPathIdentity, bool) {
	sort.Slice(values, func(i, j int) bool {
		return values[i].Path < values[j].Path
	})
	result := values[:0]
	for _, value := range values {
		if len(result) != 0 &&
			result[len(result)-1].Path == value.Path {
			if result[len(result)-1] != value {
				return nil, false
			}
			continue
		}
		result = append(result, value)
	}
	return append(
		[]linuxTask11SyntheticPathIdentity(nil),
		result...,
	), true
}

func readTask11SyntheticBoundedFile(path string) ([]byte, error) {
	if !validAbsolutePath(path) {
		return nil, ErrFixtureStart
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrFixtureStart
	}
	defer file.Close()
	document, err := io.ReadAll(
		io.LimitReader(file, maximumPermitProcDocumentBytes+1),
	)
	if err != nil ||
		len(document) == 0 ||
		len(document) > int(maximumPermitProcDocumentBytes) {
		return nil, ErrFixtureStart
	}
	return document, nil
}

func task11SyntheticPathAbsent(path string) error {
	if !validAbsolutePath(path) {
		return ErrFixtureCleanup
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return ErrFixtureCleanup
	}
	return ErrFixtureCleanup
}

func task11SyntheticProcPathAbsent(
	procRoot string,
	pid int,
) bool {
	if !validAbsolutePath(procRoot) || pid <= 0 {
		return false
	}
	_, err := os.Lstat(filepath.Join(procRoot, strconv.Itoa(pid)))
	return errors.Is(err, os.ErrNotExist)
}

func mustTask11SyntheticBindingDigestForProbe(
	binding task11SyntheticCleanupObserverBinding,
) string {
	digest, err := task11SyntheticCleanupObserverBindingDigest(binding)
	if err != nil {
		return ""
	}
	return digest
}

var _ task11SyntheticCleanupProbe = (*linuxTask11SyntheticCleanupProbe)(nil)
