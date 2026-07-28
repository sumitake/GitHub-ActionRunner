package hostruntime

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	managedKindAdapter  = "network-adapter"
	managedKindBroker   = "network-broker"
	managedKindRunner   = "runner"
	managedKindHelper   = "network-policy-helper"
	managedKindVerifier = "network-verifier"
)

var verifierRecoveryNamePattern = regexp.MustCompile(
	`^pghar-verifier-[0-9a-f]{32}-(?:empty|probe|identity)$`,
)

// RecoverySpec is the complete immutable identity required to inspect and
// reclaim one slot after process-local operational handles were lost.
type RecoverySpec struct {
	SlotIdentity      string
	BuildID           string
	FleetGeneration   uint64
	AdapterName       string
	BrokerName        string
	RunnerName        string
	ExpectedAdapterID string
	ExpectedBrokerID  string
	ExpectedRunnerID  string
	RelayParent       string
	AuthorityParent   string
}

// RecoveredIdentities exposes only opaque container IDs recovered from exact
// immutable labels. It never confers operational or listener-release authority.
type RecoveredIdentities struct {
	AdapterID string
	BrokerID  string
	RunnerID  string
}

// ManagedObservation is the closed runtime-presence projection used by
// reconciliation after InspectManaged has validated every immutable identity.
type ManagedObservation struct {
	AdapterPresent bool
	AdapterRunning bool
	BrokerPresent  bool
	BrokerRunning  bool
	RunnerPresent  bool
	RunnerRunning  bool
}

// ManagedSnapshot is an engine-issued cleanup capability. Its records and
// issuer are deliberately inaccessible outside this package.
type ManagedSnapshot struct {
	issuer  [32]byte
	nonce   [32]byte
	spec    RecoverySpec
	records []managedRecoveryRecord
}

type managedRecoveryRecord struct {
	id      string
	name    string
	kind    string
	running bool
}

func (snapshot ManagedSnapshot) validFor(issuer [32]byte) bool {
	return nonzero32(snapshot.nonce) &&
		subtle.ConstantTimeCompare(snapshot.issuer[:], issuer[:]) == 1
}

func (snapshot ManagedSnapshot) Identities() RecoveredIdentities {
	var identities RecoveredIdentities
	for _, record := range snapshot.records {
		switch record.kind {
		case managedKindAdapter:
			identities.AdapterID = record.id
		case managedKindBroker:
			identities.BrokerID = record.id
		case managedKindRunner:
			identities.RunnerID = record.id
		}
	}
	return identities
}

func (snapshot ManagedSnapshot) Observation() ManagedObservation {
	var observation ManagedObservation
	for _, record := range snapshot.records {
		switch record.kind {
		case managedKindAdapter:
			observation.AdapterPresent = true
			observation.AdapterRunning = record.running
		case managedKindBroker:
			observation.BrokerPresent = true
			observation.BrokerRunning = record.running
		case managedKindRunner:
			observation.RunnerPresent = true
			observation.RunnerRunning = record.running
		}
	}
	return observation
}

// ManagedRecovery is the cleanup-only restart surface. It is intentionally
// separate from Engine so ordinary operational handles remain process-local.
type ManagedRecovery interface {
	InspectManaged(context.Context, RecoverySpec) (ManagedSnapshot, error)
	RemoveManaged(context.Context, ManagedSnapshot) error
}

var _ ManagedRecovery = (*DockerCLI)(nil)

// InspectManaged lists only one exact slot label and rejects any unknown,
// duplicate, drifted, truncated, or indirectly mounted object before issuing a
// cleanup capability.
func (c *DockerCLI) InspectManaged(
	ctx context.Context,
	spec RecoverySpec,
) (ManagedSnapshot, error) {
	if c == nil {
		return ManagedSnapshot{}, errors.New("hostruntime: docker cli required")
	}
	if err := c.validateRecoverySpec(spec); err != nil {
		return ManagedSnapshot{}, err
	}
	ids, err := c.listManagedIDs(ctx, spec.SlotIdentity)
	if err != nil {
		return ManagedSnapshot{}, err
	}
	records := make([]managedRecoveryRecord, 0, len(ids))
	seenKinds := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		record, err := c.inspectManagedID(ctx, id, spec)
		if err != nil {
			return ManagedSnapshot{}, err
		}
		if _, exists := seenKinds[record.kind]; exists {
			return ManagedSnapshot{}, errors.New("hostruntime: duplicate managed component kind")
		}
		seenKinds[record.kind] = struct{}{}
		records = append(records, record)
	}
	var nonce [32]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return ManagedSnapshot{}, errors.New("hostruntime: recovery nonce generation failed")
	}
	return ManagedSnapshot{
		issuer:  c.issuer,
		nonce:   nonce,
		spec:    spec,
		records: records,
	}, nil
}

func (c *DockerCLI) validateRecoverySpec(spec RecoverySpec) error {
	for label, value := range map[string]string{
		"slot identity": spec.SlotIdentity,
		"adapter name":  spec.AdapterName,
		"broker name":   spec.BrokerName,
		"runner name":   spec.RunnerName,
	} {
		if err := validateContainerName(value); err != nil {
			return fmt.Errorf("hostruntime: recovery %s invalid", label)
		}
	}
	if !isLowerHex64(spec.BuildID) || spec.FleetGeneration == 0 {
		return errors.New("hostruntime: recovery build identity invalid")
	}
	for _, id := range []string{
		spec.ExpectedAdapterID,
		spec.ExpectedBrokerID,
		spec.ExpectedRunnerID,
	} {
		if id != "" && !isLowerHex64(id) {
			return errors.New("hostruntime: recovery expected container identity invalid")
		}
	}
	if spec.RelayParent == spec.AuthorityParent ||
		filepath.Dir(spec.RelayParent) != filepath.Dir(spec.AuthorityParent) ||
		filepath.Base(filepath.Dir(spec.RelayParent)) != spec.SlotIdentity {
		return errors.New("hostruntime: recovery directory identity invalid")
	}
	for _, item := range []struct {
		path  string
		label string
	}{
		{spec.RelayParent, "relay parent"},
		{spec.AuthorityParent, "authority parent"},
	} {
		if err := validateDescendant(c.cfg.BrokerRoot, item.path, item.label); err != nil {
			return err
		}
		if _, err := os.Lstat(item.path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return errors.New("hostruntime: recovery directory unavailable")
		}
		if err := validateDirectPrivateDirectory(c.cfg.BrokerRoot, item.path); err != nil {
			return err
		}
	}
	return nil
}

func (c *DockerCLI) listManagedIDs(
	ctx context.Context,
	slotIdentity string,
) ([]string, error) {
	result, err := c.runner.Run(
		ctx,
		[]string{
			c.cfg.DockerPath,
			"ps",
			"-a",
			"--no-trunc",
			"--filter",
			"label=io.portable-ghar.managed=true",
			"--filter",
			"label=io.portable-ghar.slot=" + slotIdentity,
			"--format",
			"{{.ID}}",
		},
		nil,
		nil,
	)
	if err != nil || result.ExitCode != 0 || result.Signaled ||
		result.StdoutTruncated || result.StderrTruncated ||
		len(result.Stderr) != 0 {
		return nil, errors.New("hostruntime: managed slot listing failed")
	}
	if len(result.Stdout) == 0 {
		return nil, nil
	}
	if result.Stdout[len(result.Stdout)-1] != '\n' {
		return nil, errors.New("hostruntime: managed slot listing malformed")
	}
	lines := strings.Split(string(result.Stdout[:len(result.Stdout)-1]), "\n")
	if len(lines) > 5 {
		return nil, errors.New("hostruntime: managed slot inventory exceeds closed bound")
	}
	seen := make(map[string]struct{}, len(lines))
	for _, id := range lines {
		if !isLowerHex64(id) {
			return nil, errors.New("hostruntime: managed slot identity malformed")
		}
		if _, exists := seen[id]; exists {
			return nil, errors.New("hostruntime: managed slot identity duplicated")
		}
		seen[id] = struct{}{}
	}
	return lines, nil
}

type managedRecoveryInspect struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	State struct {
		Running bool `json:"Running"`
	} `json:"State"`
	Mounts []struct {
		Type        string `json:"Type"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
}

func (c *DockerCLI) inspectManagedID(
	ctx context.Context,
	id string,
	spec RecoverySpec,
) (managedRecoveryRecord, error) {
	result, err := c.runner.Run(
		ctx,
		[]string{c.cfg.DockerPath, "inspect", "--type", "container", id},
		nil,
		nil,
	)
	if err != nil || result.ExitCode != 0 || result.Signaled ||
		result.StdoutTruncated || result.StderrTruncated ||
		len(result.Stderr) != 0 {
		return managedRecoveryRecord{}, errors.New("hostruntime: managed component inspection failed")
	}
	var documents []managedRecoveryInspect
	if err := json.Unmarshal(result.Stdout, &documents); err != nil || len(documents) != 1 {
		return managedRecoveryRecord{}, errors.New("hostruntime: managed component inspection document invalid")
	}
	document := documents[0]
	if document.ID != id ||
		!strings.HasPrefix(document.Name, "/") ||
		strings.HasPrefix(document.Name, "//") {
		return managedRecoveryRecord{}, errors.New("hostruntime: managed component identity invalid")
	}
	name := strings.TrimPrefix(document.Name, "/")
	if err := validateContainerName(name); err != nil {
		return managedRecoveryRecord{}, errors.New("hostruntime: managed component name invalid")
	}
	labels := document.Config.Labels
	if len(labels) != 5 ||
		labels["io.portable-ghar.managed"] != "true" ||
		labels["io.portable-ghar.build-id"] != spec.BuildID ||
		labels["io.portable-ghar.fleet-generation"] != strconv.FormatUint(spec.FleetGeneration, 10) ||
		labels["io.portable-ghar.slot"] != spec.SlotIdentity {
		return managedRecoveryRecord{}, errors.New("hostruntime: managed component labels drifted")
	}
	kind := labels["io.portable-ghar.kind"]
	if !validRecoveredName(kind, name, spec) {
		return managedRecoveryRecord{}, errors.New("hostruntime: managed component kind or name invalid")
	}
	if !validRecoveredExpectedID(kind, id, spec) {
		return managedRecoveryRecord{}, errors.New("hostruntime: managed component persisted identity conflict")
	}
	if !validRecoveredMounts(kind, document.Mounts, spec) {
		return managedRecoveryRecord{}, errors.New("hostruntime: managed component mount identity invalid")
	}
	return managedRecoveryRecord{
		id:      id,
		name:    name,
		kind:    kind,
		running: document.State.Running,
	}, nil
}

func validRecoveredName(kind, name string, spec RecoverySpec) bool {
	switch kind {
	case managedKindAdapter:
		return name == spec.AdapterName
	case managedKindBroker:
		return name == spec.BrokerName
	case managedKindRunner:
		return name == spec.RunnerName
	case managedKindHelper:
		return name == spec.BrokerName+"-policy"
	case managedKindVerifier:
		return verifierRecoveryNamePattern.MatchString(name)
	default:
		return false
	}
}

func validRecoveredExpectedID(kind, id string, spec RecoverySpec) bool {
	var expected string
	switch kind {
	case managedKindAdapter:
		expected = spec.ExpectedAdapterID
	case managedKindBroker:
		expected = spec.ExpectedBrokerID
	case managedKindRunner:
		expected = spec.ExpectedRunnerID
	}
	return expected == "" || expected == id
}

func validRecoveredMounts(
	kind string,
	mounts []struct {
		Type        string `json:"Type"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	},
	spec RecoverySpec,
) bool {
	switch kind {
	case managedKindAdapter:
		return len(mounts) == 1 &&
			mounts[0].Type == "bind" &&
			mounts[0].Source == spec.RelayParent &&
			mounts[0].Destination == adapterMountDst &&
			!mounts[0].RW
	case managedKindBroker:
		if len(mounts) != 2 {
			return false
		}
		var relay, authority bool
		for _, mount := range mounts {
			if mount.Type != "bind" {
				return false
			}
			switch mount.Destination {
			case brokerRelayMountDst:
				if relay || mount.Source != spec.RelayParent || !mount.RW {
					return false
				}
				relay = true
			case brokerAuthorityMountDst:
				if authority || mount.Source != spec.AuthorityParent || mount.RW {
					return false
				}
				authority = true
			default:
				return false
			}
		}
		return relay && authority
	default:
		return len(mounts) == 0
	}
}

// RemoveManaged consumes only an engine-issued snapshot and removes primary
// and one-shot components in dependency order, then the two per-job socket
// directories. The separately retained SQLite network ledger is out of scope.
func (c *DockerCLI) RemoveManaged(
	ctx context.Context,
	snapshot ManagedSnapshot,
) error {
	if c == nil || !snapshot.validFor(c.issuer) {
		return errors.New("hostruntime: managed snapshot invalid")
	}
	records := append([]managedRecoveryRecord(nil), snapshot.records...)
	sort.SliceStable(records, func(i, j int) bool {
		return managedRemovalRank(records[i].kind) < managedRemovalRank(records[j].kind)
	})
	for _, record := range records {
		if err := c.removeRecoveredID(ctx, record.id); err != nil {
			return err
		}
	}
	if err := c.removeBrokerDirectory(snapshot.spec.AuthorityParent); err != nil {
		return err
	}
	if err := c.removeBrokerDirectory(snapshot.spec.RelayParent); err != nil {
		return err
	}
	remaining, err := c.listManagedIDs(ctx, snapshot.spec.SlotIdentity)
	if err != nil {
		return err
	}
	if len(remaining) != 0 {
		return errors.New("hostruntime: managed slot cleanup not confirmed")
	}
	return nil
}

func managedRemovalRank(kind string) int {
	switch kind {
	case managedKindRunner:
		return 1
	case managedKindVerifier:
		return 2
	case managedKindHelper:
		return 3
	case managedKindBroker:
		return 4
	case managedKindAdapter:
		return 5
	default:
		return 6
	}
}

func (c *DockerCLI) removeRecoveredID(
	ctx context.Context,
	id string,
) error {
	result, err := c.runner.Run(
		ctx,
		[]string{c.cfg.DockerPath, "rm", "-f", id},
		nil,
		nil,
	)
	if err != nil || result.ExitCode != 0 || result.Signaled ||
		result.StdoutTruncated || result.StderrTruncated ||
		len(result.Stderr) != 0 {
		return errors.New("hostruntime: recovered component removal failed")
	}
	absence, err := c.runner.Run(
		ctx,
		[]string{
			c.cfg.DockerPath,
			"ps",
			"-a",
			"--no-trunc",
			"--filter",
			"id=" + id,
			"--format",
			"{{.ID}}",
		},
		nil,
		nil,
	)
	if err != nil || absence.ExitCode != 0 || absence.Signaled ||
		absence.StdoutTruncated || absence.StderrTruncated ||
		len(absence.Stdout) != 0 || len(absence.Stderr) != 0 {
		return errors.New("hostruntime: recovered component absence unproven")
	}
	return nil
}
