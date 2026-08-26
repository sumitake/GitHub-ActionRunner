package controller

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

type canonicalTransitionerStub struct{}

func (canonicalTransitionerStub) Snapshot(context.Context) (AcquisitionPolicy, error) {
	return AcquisitionPolicy{}, nil
}

func (canonicalTransitionerStub) Transition(
	context.Context,
	uint64,
	AcquisitionPolicy,
) (AcquisitionPolicy, error) {
	return AcquisitionPolicy{}, nil
}

type canonicalGuardStub struct{}

func (canonicalGuardStub) Close() error { return nil }

type countingGuardStub struct {
	closeCalls int
}

func (guard *countingGuardStub) Close() error {
	guard.closeCalls++
	return nil
}

type countingPermitGuardStub struct {
	countingGuardStub
}

func (*countingPermitGuardStub) Context() context.Context { return context.Background() }
func (*countingPermitGuardStub) Binding() AcquisitionPermitBinding {
	return AcquisitionPermitBinding{}
}
func (*countingPermitGuardStub) ValidateBinding(context.Context, AcquisitionPermitBinding) error {
	return nil
}
func (*countingPermitGuardStub) Revalidate() error { return nil }
func (*countingPermitGuardStub) Admit() error      { return nil }

type canonicalPermitGuardStub struct {
	canonicalGuardStub
	ctx context.Context
}

func (guard canonicalPermitGuardStub) Context() context.Context {
	if guard.ctx != nil {
		return guard.ctx
	}
	return context.Background()
}
func (canonicalPermitGuardStub) Binding() AcquisitionPermitBinding {
	return AcquisitionPermitBinding{}
}
func (canonicalPermitGuardStub) ValidateBinding(context.Context, AcquisitionPermitBinding) error {
	return nil
}
func (canonicalPermitGuardStub) Revalidate() error { return nil }
func (canonicalPermitGuardStub) Admit() error      { return nil }

type canonicalFleetGuardProviderStub struct{}

func (canonicalFleetGuardProviderStub) AcquirePortable(context.Context) (AcquisitionGuard, error) {
	return canonicalGuardStub{}, nil
}

type canonicalPermitProviderStub struct{}

func (canonicalPermitProviderStub) Acquire(
	ctx context.Context,
	_ AcquisitionPermitRequest,
) (AcquisitionPermitGuard, error) {
	return canonicalPermitGuardStub{ctx: ctx}, nil
}

func (canonicalPermitProviderStub) Invalidate(context.Context) error { return nil }

var (
	_ AcquisitionTransitioner   = canonicalTransitionerStub{}
	_ AcquisitionGuard          = canonicalGuardStub{}
	_ AcquisitionPermitGuard    = canonicalPermitGuardStub{}
	_ FleetGuardProvider        = canonicalFleetGuardProviderStub{}
	_ AcquisitionPermitProvider = canonicalPermitProviderStub{}
)

func TestGuardedAcquisitionOperationCloseIsIdempotent(t *testing.T) {
	barrier, err := newAcquisitionBarrier(testDesiredPolicy(), true)
	if err != nil {
		t.Fatalf("newAcquisitionBarrier: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	operation, err := barrier.beginOperation(ctx, "poll", "repo-a", "portable-ghar")
	if err != nil {
		t.Fatalf("beginOperation: %v", err)
	}
	permit := &countingPermitGuardStub{}
	host := &countingGuardStub{}
	cancelCalls := 0
	guarded := &guardedAcquisitionOperation{
		operation:       operation,
		operationCancel: func() { cancelCalls++ },
		permit:          permit,
		host:            host,
	}

	if err := guarded.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := guarded.Close(); err != nil {
		t.Fatalf("Close second: %v", err)
	}
	if permit.closeCalls != 1 || host.closeCalls != 1 || cancelCalls != 1 {
		t.Fatalf(
			"close counts = permit:%d host:%d cancel:%d, want one each",
			permit.closeCalls,
			host.closeCalls,
			cancelCalls,
		)
	}
}

func TestAcquisitionPermitBindingDigestIsClosedAndDeterministic(t *testing.T) {
	binding := AcquisitionPermitBinding{
		AuthorityRevision:        11,
		AuthorityKey:             "{\"fleetId\":\"example-fleet\",\"mode\":\"enabled\"}",
		FenceGeneration:          12,
		ServerEpoch:              13,
		SessionID:                strings.Repeat("a", 64),
		LeaseGeneration:          14,
		OperationID:              "operation-15",
		RepositoryAlias:          "repo-a",
		ScaleSetName:             "portable-ghar",
		OperationKind:            "jit",
		PolicyDigest:             strings.Repeat("b", 64),
		PolicyEpoch:              16,
		PolicyMode:               AcquisitionEnabled,
		MaxCapacity:              17,
		RepositoryPolicyRevision: 18,
		OriginalLocalDeadline:    time.Date(1970, 1, 1, 0, 2, 3, 456, time.FixedZone("CLOCK_BOOTTIME", 0)),
	}
	digest, err := AcquisitionPermitBindingDigest(binding)
	if err != nil {
		t.Fatalf("AcquisitionPermitBindingDigest: %v", err)
	}
	if digest == ([32]byte{}) {
		t.Fatal("binding digest is zero")
	}
	second, err := AcquisitionPermitBindingDigest(binding)
	if err != nil || second != digest {
		t.Fatalf("binding digest replay = (%x, %v), want %x", second, err, digest)
	}

	mutations := []func(*AcquisitionPermitBinding){
		func(value *AcquisitionPermitBinding) { value.AuthorityRevision++ },
		func(value *AcquisitionPermitBinding) { value.AuthorityKey += " " },
		func(value *AcquisitionPermitBinding) { value.FenceGeneration++ },
		func(value *AcquisitionPermitBinding) { value.ServerEpoch++ },
		func(value *AcquisitionPermitBinding) { value.SessionID = strings.Repeat("c", 64) },
		func(value *AcquisitionPermitBinding) { value.LeaseGeneration++ },
		func(value *AcquisitionPermitBinding) { value.OperationID += "-changed" },
		func(value *AcquisitionPermitBinding) { value.RepositoryAlias = "repo-b" },
		func(value *AcquisitionPermitBinding) { value.ScaleSetName = "other-set" },
		func(value *AcquisitionPermitBinding) { value.OperationKind = "poll" },
		func(value *AcquisitionPermitBinding) { value.PolicyDigest = strings.Repeat("d", 64) },
		func(value *AcquisitionPermitBinding) { value.PolicyEpoch++ },
		func(value *AcquisitionPermitBinding) {
			value.PolicyMode = AcquisitionCanaryOnly
			value.MaxCapacity = 1
		},
		func(value *AcquisitionPermitBinding) { value.MaxCapacity++ },
		func(value *AcquisitionPermitBinding) { value.RepositoryPolicyRevision++ },
		func(value *AcquisitionPermitBinding) {
			value.OriginalLocalDeadline = value.OriginalLocalDeadline.Add(time.Nanosecond)
		},
		func(value *AcquisitionPermitBinding) {
			value.OriginalLocalDeadline = value.OriginalLocalDeadline.In(time.FixedZone("OTHER_CLOCK", 0))
		},
	}
	for index, mutate := range mutations {
		changed := binding
		mutate(&changed)
		changedDigest, err := AcquisitionPermitBindingDigest(changed)
		if err != nil {
			t.Fatalf("mutation %d digest: %v", index, err)
		}
		if changedDigest == digest {
			t.Fatalf("mutation %d did not change digest", index)
		}
	}
	if _, err := AcquisitionPermitBindingDigest(AcquisitionPermitBinding{}); err == nil {
		t.Fatal("zero binding was digestible")
	}
}

func TestAcquisitionPolicyCanonicalBytesAndDigest(t *testing.T) {
	t.Parallel()

	policy := AcquisitionPolicy{
		Mode:                     AcquisitionEnabled,
		EligibleScaleSets:        []string{"set-z", "set-a"},
		MaxCapacity:              12,
		RepositoryPolicyRevision: 7,
		RepositoryPolicies: []RepositoryPolicySummary{
			{Alias: "repo-z", MaxConcurrency: 2, Eligibility: "active"},
			{Alias: "repo-a", MaxConcurrency: 5, Eligibility: "pending-reactivation"},
		},
		Epoch: 99,
	}
	wantBytes := []byte(
		"portable-ghar-acquisition-policy-v1\n" +
			"enabled\n" +
			"12\n" +
			"7\n" +
			"set-a\n" +
			"set-z\n" +
			"--\n" +
			"repo-a\t5\tpending-reactivation\n" +
			"repo-z\t2\tactive\n",
	)

	gotPolicy, err := CanonicalizeAcquisitionPolicy(policy)
	if err != nil {
		t.Fatalf("CanonicalizeAcquisitionPolicy: %v", err)
	}
	gotBytes, err := canonicalAcquisitionPolicyBytes(gotPolicy)
	if err != nil {
		t.Fatalf("canonicalAcquisitionPolicyBytes: %v", err)
	}
	if !bytes.Equal(gotBytes, wantBytes) {
		t.Fatalf("canonical bytes = %q, want %q", gotBytes, wantBytes)
	}
	gotDigest, err := AcquisitionPolicyDigest(gotPolicy)
	if err != nil {
		t.Fatalf("AcquisitionPolicyDigest: %v", err)
	}
	const wantDigest = "c2a2d3987e1146c7c2ca3b229767ab376753f56a58bcb4f4e33941d561f01fc6"
	if got := hex.EncodeToString(gotDigest[:]); got != wantDigest {
		t.Fatalf("digest = %s, want %s", got, wantDigest)
	}

	withoutEpoch := gotPolicy
	withoutEpoch.Epoch = 100
	otherDigest, err := AcquisitionPolicyDigest(withoutEpoch)
	if err != nil {
		t.Fatalf("AcquisitionPolicyDigest(other epoch): %v", err)
	}
	if otherDigest != gotDigest {
		t.Fatalf("digest changed with epoch: %x != %x", otherDigest, gotDigest)
	}
}

func TestCanonicalizeAcquisitionPolicyDeepCopiesAndNormalizesEmptySlices(t *testing.T) {
	t.Parallel()

	policy := validAcquisitionPolicyFixture()
	canonical, err := CanonicalizeAcquisitionPolicy(policy)
	if err != nil {
		t.Fatalf("CanonicalizeAcquisitionPolicy: %v", err)
	}
	policy.EligibleScaleSets[0] = "mutated"
	policy.RepositoryPolicies[0].Alias = "mutated"
	if canonical.EligibleScaleSets[0] != "set-a" ||
		canonical.RepositoryPolicies[0].Alias != "repo-a" {
		t.Fatalf("canonical policy aliases caller memory: %+v", canonical)
	}

	nilPolicy := AcquisitionPolicy{
		Mode:                     AcquisitionDisabled,
		RepositoryPolicyRevision: 1,
	}
	emptyPolicy := nilPolicy
	emptyPolicy.EligibleScaleSets = []string{}
	emptyPolicy.RepositoryPolicies = []RepositoryPolicySummary{}
	nilCanonical, err := CanonicalizeAcquisitionPolicy(nilPolicy)
	if err != nil {
		t.Fatalf("canonical nil policy: %v", err)
	}
	emptyCanonical, err := CanonicalizeAcquisitionPolicy(emptyPolicy)
	if err != nil {
		t.Fatalf("canonical empty policy: %v", err)
	}
	if nilCanonical.EligibleScaleSets != nil ||
		nilCanonical.RepositoryPolicies != nil ||
		emptyCanonical.EligibleScaleSets != nil ||
		emptyCanonical.RepositoryPolicies != nil {
		t.Fatalf("empty sets were not normalized: nil=%+v empty=%+v", nilCanonical, emptyCanonical)
	}
}

func TestCanonicalizeAcquisitionPolicyRejectsInvalidShapes(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*AcquisitionPolicy){
		"unknown mode": func(policy *AcquisitionPolicy) {
			policy.Mode = AcquisitionMode("other")
		},
		"disabled nonzero": func(policy *AcquisitionPolicy) {
			policy.Mode = AcquisitionDisabled
			policy.MaxCapacity = 1
			policy.EligibleScaleSets = nil
		},
		"disabled eligible": func(policy *AcquisitionPolicy) {
			policy.Mode = AcquisitionDisabled
			policy.MaxCapacity = 0
		},
		"fatal nonzero": func(policy *AcquisitionPolicy) {
			policy.Mode = AcquisitionFatal
			policy.MaxCapacity = 1
			policy.EligibleScaleSets = nil
		},
		"canary wrong capacity": func(policy *AcquisitionPolicy) {
			policy.Mode = AcquisitionCanaryOnly
			policy.MaxCapacity = 2
		},
		"canary wrong eligible count": func(policy *AcquisitionPolicy) {
			policy.Mode = AcquisitionCanaryOnly
			policy.MaxCapacity = 1
			policy.EligibleScaleSets = append(policy.EligibleScaleSets, "set-b")
		},
		"enabled zero": func(policy *AcquisitionPolicy) {
			policy.MaxCapacity = 0
		},
		"duplicate eligible": func(policy *AcquisitionPolicy) {
			policy.EligibleScaleSets = []string{"set-a", "set-a"}
		},
		"duplicate repository": func(policy *AcquisitionPolicy) {
			policy.RepositoryPolicies = append(
				policy.RepositoryPolicies,
				policy.RepositoryPolicies[0],
			)
		},
		"invalid eligibility": func(policy *AcquisitionPolicy) {
			policy.RepositoryPolicies[0].Eligibility = "unknown"
		},
		"empty eligible name": func(policy *AcquisitionPolicy) {
			policy.EligibleScaleSets[0] = ""
		},
		"eligible tab": func(policy *AcquisitionPolicy) {
			policy.EligibleScaleSets[0] = "set\ta"
		},
		"eligible newline": func(policy *AcquisitionPolicy) {
			policy.EligibleScaleSets[0] = "set\na"
		},
		"eligible carriage return": func(policy *AcquisitionPolicy) {
			policy.EligibleScaleSets[0] = "set\ra"
		},
		"eligible NUL": func(policy *AcquisitionPolicy) {
			policy.EligibleScaleSets[0] = "set\x00a"
		},
		"eligible invalid UTF-8": func(policy *AcquisitionPolicy) {
			policy.EligibleScaleSets[0] = string([]byte{0xff})
		},
		"eligible too long": func(policy *AcquisitionPolicy) {
			policy.EligibleScaleSets[0] = strings.Repeat("x", 129)
		},
		"empty repository alias": func(policy *AcquisitionPolicy) {
			policy.RepositoryPolicies[0].Alias = ""
		},
		"repository separator": func(policy *AcquisitionPolicy) {
			policy.RepositoryPolicies[0].Alias = "repo\ta"
		},
		"repository too long": func(policy *AcquisitionPolicy) {
			policy.RepositoryPolicies[0].Alias = strings.Repeat("r", 65)
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			policy := validAcquisitionPolicyFixture()
			mutate(&policy)
			if _, err := CanonicalizeAcquisitionPolicy(policy); !errors.Is(
				err,
				ErrInvalidAcquisitionPolicy,
			) {
				t.Fatalf("error = %v, want ErrInvalidAcquisitionPolicy", err)
			}
		})
	}
}

func TestAcquisitionPolicyUnsignedUTF8OrderingAndCaseSensitivity(t *testing.T) {
	t.Parallel()

	policy := AcquisitionPolicy{
		Mode:                     AcquisitionEnabled,
		EligibleScaleSets:        []string{"é", "Z", "a"},
		MaxCapacity:              3,
		RepositoryPolicyRevision: 1,
		RepositoryPolicies: []RepositoryPolicySummary{
			{Alias: "é", MaxConcurrency: 0, Eligibility: "archived-disabled"},
			{Alias: "Z", MaxConcurrency: 1, Eligibility: "active"},
			{Alias: "a", MaxConcurrency: 1, Eligibility: "active"},
		},
	}
	canonical, err := CanonicalizeAcquisitionPolicy(policy)
	if err != nil {
		t.Fatalf("CanonicalizeAcquisitionPolicy: %v", err)
	}
	if got, want := canonical.EligibleScaleSets, []string{"Z", "a", "é"}; !equalStrings(got, want) {
		t.Fatalf("eligible = %q, want %q", got, want)
	}
	gotAliases := make([]string, len(canonical.RepositoryPolicies))
	for i := range canonical.RepositoryPolicies {
		gotAliases[i] = canonical.RepositoryPolicies[i].Alias
	}
	if want := []string{"Z", "a", "é"}; !equalStrings(gotAliases, want) {
		t.Fatalf("aliases = %q, want %q", gotAliases, want)
	}
}

func validAcquisitionPolicyFixture() AcquisitionPolicy {
	return AcquisitionPolicy{
		Mode:                     AcquisitionEnabled,
		EligibleScaleSets:        []string{"set-a"},
		MaxCapacity:              4,
		RepositoryPolicyRevision: 3,
		RepositoryPolicies: []RepositoryPolicySummary{
			{Alias: "repo-a", MaxConcurrency: 2, Eligibility: "active"},
		},
		Epoch: 8,
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
