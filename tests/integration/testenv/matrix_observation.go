package testenv

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/sumitake/portable-ghar/internal/conformance"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

const typedMatrixObservationDomain = "portable-ghar.task11.typed-observation.v1\x00"

type typedMatrixObservationWire struct {
	SchemaVersion uint32          `json:"schema_version"`
	ID            ObservationID   `json:"id"`
	Operation     string          `json:"operation"`
	Parser        string          `json:"parser"`
	Payload       json.RawMessage `json:"payload"`
}

func sealTypedMatrixObservation(
	requirement ObservationRequirement,
	assertionCount uint64,
	measurements []conformance.MeasurementInput,
	payload any,
) (matrixObservation, error) {
	if !isExactObservationRequirement(requirement) ||
		assertionCount == 0 ||
		payload == nil {
		return matrixObservation{}, conformance.ErrObservation
	}
	payloadDocument, err := json.Marshal(payload)
	if err != nil ||
		len(payloadDocument) == 0 ||
		uint64(len(payloadDocument)) > requirement.MaxBytes {
		return matrixObservation{}, conformance.ErrObservation
	}
	wire := typedMatrixObservationWire{
		SchemaVersion: 1,
		ID:            requirement.ID,
		Operation:     requirement.Operation,
		Parser:        requirement.Parser,
		Payload:       payloadDocument,
	}
	document, err := json.Marshal(wire)
	if err != nil {
		return matrixObservation{}, conformance.ErrObservation
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(typedMatrixObservationDomain))
	_, _ = digest.Write(document)
	return matrixObservation{
		Requirement:    requirement,
		AssertionCount: assertionCount,
		Measurements: append(
			[]conformance.MeasurementInput(nil),
			measurements...,
		),
		Digest: hex.EncodeToString(digest.Sum(nil)),
	}, nil
}

func isExactObservationRequirement(
	requirement ObservationRequirement,
) bool {
	for _, expected := range RequiredObservationMatrix() {
		if requirement == expected {
			return true
		}
	}
	return false
}

type hostProfileMatrixSource struct {
	target      TargetBinding
	runtimeID   hostruntime.HostProfile
	static      staticPreflightResult
	memory      hostruntime.SizingResult
	conntrack   hostruntime.ConntrackResult
	storage     hostruntime.StorageResult
	logBounds   hostruntime.LogBoundsOverlay
	maxCapacity uint64
}

func newHostProfileMatrixSource(
	input ConformanceInput,
	overlay hostruntime.PrivateOverlay,
	static staticPreflightResult,
) (*hostProfileMatrixSource, error) {
	runtimeID, profileOK := runtimeProfileFromTarget(
		input.Target.ProfileID,
	)
	memory, memoryErr := runnerSizingFromTargetOverlay(
		overlay.Resources.RunnerSizing,
	)
	conntrack, conntrackErr := conntrackFromTargetOverlay(
		overlay.Resources.Conntrack,
	)
	storage, storageErr := storageFromTargetOverlay(
		overlay.Resources.Storage,
	)
	if !profileOK ||
		memoryErr != nil ||
		conntrackErr != nil ||
		storageErr != nil ||
		input.Target.OperatingSystem != "linux" ||
		input.Target.OperatingSystem != overlay.Target.OS ||
		input.Target.OperatingSystem != static.HostFacts.OperatingSystem ||
		input.Target.Architecture != overlay.Target.Architecture ||
		input.Target.Architecture != static.HostFacts.Architecture ||
		uint64(input.Target.ExpectedEUID) != overlay.Target.ExpectedEUID ||
		input.Target.ExpectedEUID != static.HostFacts.EUID ||
		string(runtimeID) != overlay.Target.ProfileID ||
		!validObservedHostCapabilities(
			input.Target,
			true,
			static.HostCapabilities,
		) ||
		!validStaticDockerInfo(static.DockerInfo) ||
		overlay.Resources.MaxCapacity == 0 {
		return nil, ErrFixtureStart
	}
	memoryResult, err := hostruntime.ValidateRunnerSizing(memory)
	if err != nil {
		return nil, ErrFixtureStart
	}
	conntrackResult, err := hostruntime.ValidateConntrackSizing(conntrack)
	if err != nil {
		return nil, ErrFixtureStart
	}
	storageResult, err := hostruntime.ValidateStorageSizing(storage)
	if err != nil {
		return nil, ErrFixtureStart
	}
	effective := uint64(memoryResult.EffectiveCapacity)
	if value := uint64(conntrackResult.EffectiveCapacity); value < effective {
		effective = value
	}
	if value := uint64(storageResult.EffectiveCapacity); value < effective {
		effective = value
	}
	if effective == 0 || effective > overlay.Resources.MaxCapacity {
		return nil, ErrFixtureStart
	}
	return &hostProfileMatrixSource{
		target:      input.Target,
		runtimeID:   runtimeID,
		static:      static,
		memory:      memoryResult,
		conntrack:   conntrackResult,
		storage:     storageResult,
		logBounds:   overlay.Resources.Storage.LogBounds,
		maxCapacity: effective,
	}, nil
}

func (s *hostProfileMatrixSource) Observe(
	ctx context.Context,
	requirement ObservationRequirement,
) (matrixObservation, error) {
	if s == nil || ctx == nil || ctx.Err() != nil ||
		!isExactObservationRequirement(requirement) ||
		requirement.Case != conformance.CaseHostProfile ||
		requirement.Source != SourceHostProfile {
		return matrixObservation{}, conformance.ErrObservation
	}
	var (
		assertions   uint64
		measurements []conformance.MeasurementInput
		payload      any
	)
	switch requirement.Operation {
	case "profile-platform":
		assertions = 2
		payload = struct {
			OperatingSystem string `json:"operating_system"`
			Architecture    string `json:"architecture"`
		}{
			OperatingSystem: s.static.HostFacts.OperatingSystem,
			Architecture:    s.static.HostFacts.Architecture,
		}
	case "profile-runtime":
		assertions = 3
		payload = struct {
			KernelVersion string `json:"kernel_version"`
			ServerVersion string `json:"server_version"`
			CgroupVersion string `json:"cgroup_version"`
		}{
			KernelVersion: s.static.DockerInfo.KernelVersion,
			ServerVersion: s.static.DockerInfo.ServerVersion,
			CgroupVersion: s.static.DockerInfo.CgroupVersion,
		}
	case "profile-identity":
		assertions = 4
		payload = struct {
			EUID             uint32 `json:"euid"`
			TargetProfileID  string `json:"target_profile_id"`
			RuntimeProfileID string `json:"runtime_profile_id"`
			Degraded         bool   `json:"degraded"`
		}{
			EUID:             s.static.HostFacts.EUID,
			TargetProfileID:  s.target.ProfileID,
			RuntimeProfileID: string(s.runtimeID),
			Degraded: s.runtimeID ==
				hostruntime.HostProfileQTSCaplessRoot,
		}
	case "profile-capabilities":
		assertions = 5
		payload = s.static.HostCapabilities
	case "profile-cgroups":
		assertions = 3
		payload = struct {
			Memory bool `json:"memory"`
			CPU    bool `json:"cpu"`
			PIDs   bool `json:"pids"`
		}{
			Memory: s.static.DockerInfo.MemoryLimit,
			CPU:    s.static.DockerInfo.CPUCFS,
			PIDs:   s.static.DockerInfo.PIDsLimit,
		}
	case "profile-envelopes":
		assertions = 5
		payload = struct {
			MemoryDigest    string `json:"memory_digest"`
			ConntrackDigest string `json:"conntrack_digest"`
			StorageDigest   string `json:"storage_digest"`
			LogMaximumBytes uint64 `json:"log_maximum_bytes"`
			LogMaximumFiles uint64 `json:"log_maximum_files"`
		}{
			MemoryDigest:    s.memory.Digest,
			ConntrackDigest: s.conntrack.Digest,
			StorageDigest:   s.storage.Digest,
			LogMaximumBytes: s.logBounds.MaxBytes,
			LogMaximumFiles: s.logBounds.MaxFiles,
		}
	case "profile-capacity":
		assertions = 1
		measurements = []conformance.MeasurementInput{
			{
				Name:  "effective_capacity",
				Value: s.maxCapacity,
				Unit:  "count",
			},
		}
		payload = struct {
			EffectiveCapacity uint64 `json:"effective_capacity"`
		}{EffectiveCapacity: s.maxCapacity}
	default:
		return matrixObservation{}, conformance.ErrObservation
	}
	return sealTypedMatrixObservation(
		requirement,
		assertions,
		measurements,
		payload,
	)
}
