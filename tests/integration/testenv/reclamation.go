package testenv

import (
	"errors"
	"math"
	"math/big"

	"github.com/sumitake/portable-ghar/internal/conformance"
)

var (
	ErrReclamationSeries = errors.New(
		"testenv: reclamation series invalid",
	)
	ErrCleanupProof = errors.New(
		"testenv: cleanup proof incomplete",
	)
	ErrWorkflowTool = errors.New(
		"testenv: workflow tool compatibility failed",
	)
	ErrSeedIsolation = errors.New(
		"testenv: seed isolation failed",
	)
)

// ReclamationSample is a bounded, nonnegative post-cleanup observation.
type ReclamationSample struct {
	Index uint64
	Value uint64
}

type CompleteCleanupProof struct {
	ContainersAbsent        bool
	CgroupsAbsent           bool
	TmpfsAbsent             bool
	WorkAbsent              bool
	WorkUpdateAbsent        bool
	ProcessesAbsent         bool
	NamespacesAbsent        bool
	SocketsAbsent           bool
	AuthoritiesAbsent       bool
	TemporaryFilesAbsent    bool
	HostBackedWorkAbsent    bool
	UnexpectedObjectsAbsent bool
	PayloadVersionCount     uint64
	AssertionCount          uint64
	ObservationDigest       string
}

type WorkflowToolStatus string

const (
	WorkflowToolSupported   WorkflowToolStatus = "supported-through-broker"
	WorkflowToolUnsupported WorkflowToolStatus = "unsupported-proxy-path"
	WorkflowToolFailed      WorkflowToolStatus = "failed"
)

type WorkflowToolResult struct {
	ProbeID string
	Status  WorkflowToolStatus
}

type SeedIsolationProof struct {
	SourceDigest             string
	FirstCopyDigest          string
	CurrentMutationDigest    string
	SecondCopyDigest         string
	SourcePostDigest         string
	MutationAbsent           bool
	SourceImmutable          bool
	HostBackedWorkAbsent     bool
	SharedSeedPathAbsent     bool
	FirstWorkspaceReclaimed  bool
	SecondWorkspaceReclaimed bool
	WorkspacesReclaimed      bool
}

// ValidateReclamationSeries uses exact integer least-squares arithmetic.
// Every sample must already be post-cleanup and within the approved bound.
func ValidateReclamationSeries(
	samples []ReclamationSample,
	baseline ReclamationBaseline,
) error {
	if len(samples) < 3 ||
		baseline.Resource == "" ||
		baseline.Margin == 0 ||
		baseline.Baseline > math.MaxUint64-baseline.Margin ||
		baseline.MaximumSlopeNumerator < 0 ||
		baseline.MaximumSlopeDenominator <= 0 {
		return ErrReclamationSeries
	}
	bound := baseline.Baseline + baseline.Margin
	strictlyIncreasing := true
	for index, sample := range samples {
		if sample.Index != uint64(index) || sample.Value > bound {
			return ErrReclamationSeries
		}
		if index != 0 && sample.Value <= samples[index-1].Value {
			strictlyIncreasing = false
		}
	}
	if strictlyIncreasing {
		return ErrReclamationSeries
	}

	n := new(big.Int).SetUint64(uint64(len(samples)))
	sumX := new(big.Int)
	sumY := new(big.Int)
	sumXY := new(big.Int)
	sumXX := new(big.Int)
	for _, sample := range samples {
		x := new(big.Int).SetUint64(sample.Index)
		y := new(big.Int).SetUint64(sample.Value)
		sumX.Add(sumX, x)
		sumY.Add(sumY, y)
		sumXY.Add(sumXY, new(big.Int).Mul(x, y))
		sumXX.Add(sumXX, new(big.Int).Mul(x, x))
	}
	numerator := new(big.Int).Sub(
		new(big.Int).Mul(n, sumXY),
		new(big.Int).Mul(sumX, sumY),
	)
	denominator := new(big.Int).Sub(
		new(big.Int).Mul(n, sumXX),
		new(big.Int).Mul(sumX, sumX),
	)
	if denominator.Sign() <= 0 {
		return ErrReclamationSeries
	}
	if numerator.Sign() <= 0 {
		return nil
	}
	left := new(big.Int).Mul(
		numerator,
		big.NewInt(baseline.MaximumSlopeDenominator),
	)
	right := new(big.Int).Mul(
		big.NewInt(baseline.MaximumSlopeNumerator),
		denominator,
	)
	if left.Cmp(right) > 0 {
		return ErrReclamationSeries
	}
	return nil
}

func SealCompleteCleanup(
	proof CompleteCleanupProof,
) (conformance.CleanupObservation, error) {
	if !proof.ContainersAbsent ||
		!proof.CgroupsAbsent ||
		!proof.TmpfsAbsent ||
		!proof.WorkAbsent ||
		!proof.WorkUpdateAbsent ||
		!proof.ProcessesAbsent ||
		!proof.NamespacesAbsent ||
		!proof.SocketsAbsent ||
		!proof.AuthoritiesAbsent ||
		!proof.TemporaryFilesAbsent ||
		!proof.HostBackedWorkAbsent ||
		!proof.UnexpectedObjectsAbsent ||
		proof.PayloadVersionCount != 1 ||
		proof.AssertionCount == 0 ||
		!isLowerHex(proof.ObservationDigest, 64) {
		return conformance.CleanupObservation{}, ErrCleanupProof
	}
	return conformance.CleanupObservation{
		AssertionCount:    proof.AssertionCount,
		ObservationDigest: proof.ObservationDigest,
	}, nil
}

func ValidateWorkflowToolResults(results []WorkflowToolResult) error {
	if len(results) != len(requiredWorkflowToolProbeIDs) {
		return ErrWorkflowTool
	}
	for index, expected := range requiredWorkflowToolProbeIDs {
		if results[index].ProbeID != expected ||
			results[index].Status != WorkflowToolSupported {
			return ErrWorkflowTool
		}
	}
	return nil
}

func ValidateSeedIsolation(proof SeedIsolationProof) error {
	if !isLowerHex(proof.SourceDigest, 64) ||
		proof.FirstCopyDigest != proof.SourceDigest ||
		!isLowerHex(proof.CurrentMutationDigest, 64) ||
		proof.CurrentMutationDigest == proof.SourceDigest ||
		proof.SecondCopyDigest != proof.SourceDigest ||
		proof.SourcePostDigest != proof.SourceDigest ||
		!proof.MutationAbsent ||
		!proof.SourceImmutable ||
		!proof.HostBackedWorkAbsent ||
		!proof.SharedSeedPathAbsent ||
		!proof.FirstWorkspaceReclaimed ||
		!proof.SecondWorkspaceReclaimed ||
		!proof.WorkspacesReclaimed {
		return ErrSeedIsolation
	}
	return nil
}
