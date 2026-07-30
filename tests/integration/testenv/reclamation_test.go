package testenv

import (
	"math"
	"testing"
)

func TestValidateReclamationSeriesRejectsLeakShapes(t *testing.T) {
	t.Parallel()

	baseline := ReclamationBaseline{
		Resource:                ResourceMemoryBytes,
		Baseline:                10,
		Margin:                  10,
		MaximumSlopeNumerator:   1,
		MaximumSlopeDenominator: 4,
	}
	tests := map[string][]ReclamationSample{
		"too few": {
			{Index: 0, Value: 10},
			{Index: 1, Value: 10},
		},
		"missing index": {
			{Index: 0, Value: 10},
			{Index: 2, Value: 10},
			{Index: 3, Value: 10},
		},
		"above bound": {
			{Index: 0, Value: 10},
			{Index: 1, Value: 21},
			{Index: 2, Value: 10},
		},
		"strictly increasing under bound": {
			{Index: 0, Value: 10},
			{Index: 1, Value: 11},
			{Index: 2, Value: 12},
		},
		"slope above maximum": {
			{Index: 0, Value: 10},
			{Index: 1, Value: 12},
			{Index: 2, Value: 11},
			{Index: 3, Value: 14},
		},
		"arithmetic edge": {
			{Index: 0, Value: math.MaxUint64},
			{Index: 1, Value: math.MaxUint64},
			{Index: 2, Value: math.MaxUint64},
		},
	}
	for name, samples := range tests {
		t.Run(name, func(t *testing.T) {
			if err := ValidateReclamationSeries(samples, baseline); err == nil {
				t.Fatalf("accepted %s", name)
			}
		})
	}
	if err := ValidateReclamationSeries([]ReclamationSample{
		{Index: 0, Value: 10},
		{Index: 1, Value: 11},
		{Index: 2, Value: 10},
		{Index: 3, Value: 10},
	}, baseline); err != nil {
		t.Fatalf("stable reclamation rejected: %v", err)
	}
}

func TestCleanupProofCannotPassWithResidueOrUnknownObject(t *testing.T) {
	t.Parallel()

	valid := completeCleanupProof()
	if _, err := SealCompleteCleanup(valid); err != nil {
		t.Fatalf("SealCompleteCleanup: %v", err)
	}
	tests := map[string]func(*CompleteCleanupProof){
		"container": func(proof *CompleteCleanupProof) {
			proof.ContainersAbsent = false
		},
		"cgroup": func(proof *CompleteCleanupProof) {
			proof.CgroupsAbsent = false
		},
		"work update": func(proof *CompleteCleanupProof) {
			proof.WorkUpdateAbsent = false
		},
		"version pair": func(proof *CompleteCleanupProof) {
			proof.PayloadVersionCount = 2
		},
		"shared work": func(proof *CompleteCleanupProof) {
			proof.HostBackedWorkAbsent = false
		},
		"unexpected": func(proof *CompleteCleanupProof) {
			proof.UnexpectedObjectsAbsent = false
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			proof := valid
			mutate(&proof)
			if _, err := SealCompleteCleanup(proof); err == nil {
				t.Fatalf("accepted cleanup proof with %s residue", name)
			}
		})
	}
}

func TestWorkflowToolResultsRequireEveryCurrentProbeSupported(t *testing.T) {
	t.Parallel()

	results := make([]WorkflowToolResult, 0, len(requiredWorkflowToolProbeIDs))
	for _, id := range requiredWorkflowToolProbeIDs {
		results = append(results, WorkflowToolResult{
			ProbeID: id,
			Status:  WorkflowToolSupported,
		})
	}
	if err := ValidateWorkflowToolResults(results); err != nil {
		t.Fatalf("ValidateWorkflowToolResults: %v", err)
	}
	for name, mutate := range map[string]func([]WorkflowToolResult) []WorkflowToolResult{
		"missing": func(values []WorkflowToolResult) []WorkflowToolResult {
			return values[:len(values)-1]
		},
		"unsupported": func(values []WorkflowToolResult) []WorkflowToolResult {
			values[0].Status = WorkflowToolUnsupported
			return values
		},
		"failed": func(values []WorkflowToolResult) []WorkflowToolResult {
			values[0].Status = WorkflowToolFailed
			return values
		},
		"reordered": func(values []WorkflowToolResult) []WorkflowToolResult {
			values[0], values[1] = values[1], values[0]
			return values
		},
	} {
		t.Run(name, func(t *testing.T) {
			values := append([]WorkflowToolResult(nil), results...)
			if err := ValidateWorkflowToolResults(mutate(values)); err == nil {
				t.Fatalf("accepted %s workflow result", name)
			}
		})
	}
}

func TestSeedIsolationRequiresFreshImmutableNonHostBackedCopy(t *testing.T) {
	t.Parallel()

	valid := SeedIsolationProof{
		SourceDigest:             inputDigestA,
		FirstCopyDigest:          inputDigestA,
		CurrentMutationDigest:    inputDigestB,
		SecondCopyDigest:         inputDigestA,
		SourcePostDigest:         inputDigestA,
		MutationAbsent:           true,
		SourceImmutable:          true,
		HostBackedWorkAbsent:     true,
		SharedSeedPathAbsent:     true,
		FirstWorkspaceReclaimed:  true,
		SecondWorkspaceReclaimed: true,
		WorkspacesReclaimed:      true,
	}
	if err := ValidateSeedIsolation(valid); err != nil {
		t.Fatalf("ValidateSeedIsolation: %v", err)
	}
	valid.SecondCopyDigest = inputDigestB
	if err := ValidateSeedIsolation(valid); err == nil {
		t.Fatal("accepted mutated seed in next job")
	}
}

func completeCleanupProof() CompleteCleanupProof {
	return CompleteCleanupProof{
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
		PayloadVersionCount:     1,
		AssertionCount:          12,
		ObservationDigest:       inputDigestA,
	}
}
