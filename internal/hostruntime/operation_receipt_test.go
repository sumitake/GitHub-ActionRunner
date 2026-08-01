package hostruntime

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/fleetfence"
)

const (
	goldenEffectKey           = "c4a3a650de849448de44d3612f5ad219ff504ee97e9aae869d18fae29d637d0e"
	goldenPostconditionDigest = "7e7dec46d2a2d338fde78f06d6d9ac8165cc544fed1f3f1443589905af48dde6"
	goldenApplyingDigest      = "8b7d200901733b5bb7c67de2303dcafb66a507f7499978a802348eb75dc251fd"
	goldenAppliedDigest       = "e77131a4324230ef234c1ec53b54c1179fc0b4799c53d58036a27f21ede8ffc4"
)

func TestOperationEffectAndReceiptGolden(t *testing.T) {
	t.Parallel()

	binding := goldenUpgradeBinding(t)
	effectKey, err := DeriveOperationEffectKey(binding, OperationPhasePrepared)
	if err != nil {
		t.Fatalf("DeriveOperationEffectKey() error = %v", err)
	}
	if effectKey != goldenEffectKey {
		t.Fatalf("DeriveOperationEffectKey() = %q, want %q", effectKey, goldenEffectKey)
	}

	postcondition := goldenPostcondition(t, binding, effectKey)
	encodedPostcondition, postconditionDigest, err := MarshalTargetPostcondition(postcondition)
	if err != nil {
		t.Fatalf("MarshalTargetPostcondition() error = %v", err)
	}
	if postconditionDigest != goldenPostconditionDigest {
		t.Fatalf(
			"MarshalTargetPostcondition() digest = %q, want %q; json=%s",
			postconditionDigest,
			goldenPostconditionDigest,
			encodedPostcondition,
		)
	}
	decodedPostcondition, decodedPostconditionDigest, err := ParseTargetPostcondition(
		encodedPostcondition,
		len(encodedPostcondition),
	)
	if err != nil {
		t.Fatalf("ParseTargetPostcondition() error = %v", err)
	}
	if decodedPostcondition.EffectKey != effectKey ||
		decodedPostconditionDigest != postconditionDigest {
		t.Fatalf("ParseTargetPostcondition() = %#v, digest=%q", decodedPostcondition, decodedPostconditionDigest)
	}

	created := time.Date(2026, 7, 29, 7, 0, 0, 0, time.UTC)
	applying := OperationReceipt{
		SchemaVersion:             1,
		OperationID:               binding.OperationID,
		BindingDigest:             goldenBindingDigestFor(t, binding),
		EffectKey:                 effectKey,
		Phase:                     OperationPhasePrepared,
		State:                     ReceiptStateApplying,
		PriorReceiptDigest:        strings.Repeat("0", 64),
		TargetPostconditionDigest: nil,
		CreatedAt:                 created,
		UpdatedAt:                 created,
	}
	encodedApplying, applyingDigest, err := MarshalOperationReceipt(applying)
	if err != nil {
		t.Fatalf("MarshalOperationReceipt(applying) error = %v", err)
	}
	if applyingDigest != goldenApplyingDigest {
		t.Fatalf(
			"MarshalOperationReceipt(applying) digest = %q, want %q; json=%s",
			applyingDigest,
			goldenApplyingDigest,
			encodedApplying,
		)
	}

	applied := applying
	applied.State = ReceiptStateApplied
	applied.TargetPostconditionDigest = &postconditionDigest
	applied.UpdatedAt = created.Add(time.Second)
	encodedApplied, appliedDigest, err := MarshalOperationReceipt(applied)
	if err != nil {
		t.Fatalf("MarshalOperationReceipt(applied) error = %v", err)
	}
	if appliedDigest != goldenAppliedDigest {
		t.Fatalf(
			"MarshalOperationReceipt(applied) digest = %q, want %q; json=%s",
			appliedDigest,
			goldenAppliedDigest,
			encodedApplied,
		)
	}
	if err := ValidateAppliedReceipt(applying, applied, postcondition, binding); err != nil {
		t.Fatalf("ValidateAppliedReceipt() error = %v", err)
	}
	if _, _, err := ParseOperationReceipt(encodedApplied, len(encodedApplied)); err != nil {
		t.Fatalf("ParseOperationReceipt(applied) error = %v", err)
	}
}

func TestOperationReceiptRejectsInvalidStateShape(t *testing.T) {
	t.Parallel()

	binding := goldenUpgradeBinding(t)
	effectKey, err := DeriveOperationEffectKey(binding, OperationPhasePrepared)
	if err != nil {
		t.Fatalf("DeriveOperationEffectKey() error = %v", err)
	}
	now := time.Date(2026, 7, 29, 7, 0, 0, 0, time.UTC)
	digest := strings.Repeat("d", 64)
	valid := OperationReceipt{
		SchemaVersion:             1,
		OperationID:               binding.OperationID,
		BindingDigest:             goldenBindingDigestFor(t, binding),
		EffectKey:                 effectKey,
		Phase:                     OperationPhasePrepared,
		State:                     ReceiptStateApplying,
		PriorReceiptDigest:        strings.Repeat("0", 64),
		TargetPostconditionDigest: nil,
		CreatedAt:                 now,
		UpdatedAt:                 now,
	}
	tests := map[string]func(*OperationReceipt){
		"applying with proof": func(receipt *OperationReceipt) {
			receipt.TargetPostconditionDigest = &digest
		},
		"applied without proof": func(receipt *OperationReceipt) {
			receipt.State = ReceiptStateApplied
		},
		"unknown state": func(receipt *OperationReceipt) {
			receipt.State = ReceiptState("unknown")
		},
		"bad chain": func(receipt *OperationReceipt) {
			receipt.PriorReceiptDigest = strings.Repeat("Z", 64)
		},
		"updated before created": func(receipt *OperationReceipt) {
			receipt.UpdatedAt = receipt.CreatedAt.Add(-time.Nanosecond)
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			receipt := valid
			mutate(&receipt)
			if _, _, err := MarshalOperationReceipt(receipt); !errors.Is(err, ErrInvalidOperationReceipt) {
				t.Fatalf("MarshalOperationReceipt() error = %v", err)
			}
		})
	}
}

func TestTargetPostconditionRejectsFilesystemOrderAndIdentityDrift(t *testing.T) {
	t.Parallel()

	binding := goldenUpgradeBinding(t)
	effectKey, err := DeriveOperationEffectKey(binding, OperationPhasePrepared)
	if err != nil {
		t.Fatalf("DeriveOperationEffectKey() error = %v", err)
	}
	valid := goldenPostcondition(t, binding, effectKey)

	wrongOrder := valid
	wrongOrder.Filesystems = append([]LifecycleFilesystemIdentity(nil), valid.Filesystems...)
	wrongOrder.Filesystems[0], wrongOrder.Filesystems[1] =
		wrongOrder.Filesystems[1], wrongOrder.Filesystems[0]
	if _, _, err := MarshalTargetPostcondition(wrongOrder); !errors.Is(err, ErrInvalidTargetPostcondition) {
		t.Fatalf("MarshalTargetPostcondition(wrong order) error = %v", err)
	}

	changedEffect := valid
	changedEffect.EffectKey = strings.Repeat("e", 64)
	if err := ValidateTargetPostconditionAgainstBinding(
		changedEffect,
		binding,
		OperationPhasePrepared,
	); !errors.Is(err, ErrInvalidTargetPostcondition) {
		t.Fatalf("ValidateTargetPostconditionAgainstBinding(changed effect) error = %v", err)
	}
}

func goldenPostcondition(
	t *testing.T,
	binding OperationBinding,
	effectKey string,
) TargetPostcondition {
	t.Helper()
	bindingDigest := goldenBindingDigestFor(t, binding)
	manifestDigest := *binding.TargetManifestDigest
	return TargetPostcondition{
		SchemaVersion:          1,
		OperationID:            binding.OperationID,
		BindingDigest:          bindingDigest,
		EffectKey:              effectKey,
		Phase:                  OperationPhasePrepared,
		ManifestDigest:         &manifestDigest,
		PrivateOverlayRevision: binding.PrivateOverlayRevision,
		FenceGeneration:        binding.ExpectedGeneration,
		ActiveFleet:            fleetfence.FleetPortable,
		Filesystems: []LifecycleFilesystemIdentity{
			{Role: "docker-root", MountID: 1, DeviceMajor: 8, DeviceMinor: 1, RootInode: 11, FSType: "ext4"},
			{Role: "state", MountID: 2, DeviceMajor: 8, DeviceMinor: 2, RootInode: 12, FSType: "ext4"},
			{Role: "staging", MountID: 3, DeviceMajor: 8, DeviceMinor: 3, RootInode: 13, FSType: "ext4"},
			{Role: "rollback", MountID: 4, DeviceMajor: 8, DeviceMinor: 4, RootInode: 14, FSType: "ext4"},
			{Role: "scratch", MountID: 5, DeviceMajor: 8, DeviceMinor: 5, RootInode: 15, FSType: "tmpfs"},
			{Role: "logs", MountID: 6, DeviceMajor: 8, DeviceMinor: 6, RootInode: 16, FSType: "ext4"},
		},
		Artifacts: []ArtifactProjection{},
		Processes: []ProcessProjection{},
		Policy: PolicyProjection{
			PolicyManifestDigest: strings.Repeat("4", 64),
			TransitionEpoch:      9,
			AcquisitionEnabled:   false,
			PendingAcquisitions:  0,
			ActiveListeners:      0,
		},
		Quiescence:          QuiescenceProjection{},
		CurrentSelection:    nil,
		LegacyNormalization: nil,
		ObservedAt:          time.Date(2026, 7, 29, 7, 0, 0, 0, time.UTC),
	}
}

func goldenBindingDigestFor(t *testing.T, binding OperationBinding) string {
	t.Helper()
	_, digest, err := MarshalOperationBinding(binding)
	if err != nil {
		t.Fatalf("MarshalOperationBinding() error = %v", err)
	}
	return digest
}
