package productionruntime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/cli"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

func TestSystemHostedHoldAuthorityValidatesExactCanonicalEvidence(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	path, evidence := writeHostedHoldEvidenceFixture(t, now)
	authority, err := NewSystemHostedHoldAuthority(func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewSystemHostedHoldAuthority() error = %v", err)
	}
	expectation := HostedHoldExpectation{
		Path:              path,
		RepositoryAliases: append([]string(nil), evidence.Repositories...),
		FenceGeneration:   evidence.FenceGeneration,
	}

	validation := authority.Validate(context.Background(), expectation)
	if validation.Validity != AuthorityValid ||
		!lowerHexDigest(validation.EvidenceDigest) ||
		validation.ProofDigest != evidence.ProofDigest ||
		validation.TransitionEpoch != evidence.TransitionEpoch {
		t.Fatalf("Validate() = %#v", validation)
	}
	expectation.EvidenceDigest = validation.EvidenceDigest
	if repeated := authority.Validate(
		context.Background(),
		expectation,
	); repeated != validation {
		t.Fatalf("revalidated evidence = %#v, want %#v", repeated, validation)
	}
}

func TestSystemHostedHoldAuthorityRejectsDriftAndExpiredEvidence(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	path, evidence := writeHostedHoldEvidenceFixture(t, now)
	authority, err := NewSystemHostedHoldAuthority(func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewSystemHostedHoldAuthority() error = %v", err)
	}
	expectation := HostedHoldExpectation{
		Path:              path,
		RepositoryAliases: append([]string(nil), evidence.Repositories...),
		FenceGeneration:   evidence.FenceGeneration,
	}
	first := authority.Validate(context.Background(), expectation)
	if first.Validity != AuthorityValid {
		t.Fatalf("initial Validate() = %#v", first)
	}

	evidence.TransitionEpoch++
	writeCanonicalHostedHoldEvidence(t, path, evidence)
	expectation.EvidenceDigest = first.EvidenceDigest
	if drifted := authority.Validate(
		context.Background(),
		expectation,
	); drifted.Validity != AuthorityInvalid {
		t.Fatalf("drifted Validate() = %#v", drifted)
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove(evidence) error = %v", err)
	}
	if missing := authority.Validate(
		context.Background(),
		expectation,
	); missing.Validity != AuthorityUnavailable {
		t.Fatalf("missing Validate() = %#v", missing)
	}
}

func TestSystemHostedHoldAuthorityRejectsWrongTupleAndNoncanonicalBytes(
	t *testing.T,
) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	path, evidence := writeHostedHoldEvidenceFixture(t, now)
	authority, err := NewSystemHostedHoldAuthority(func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewSystemHostedHoldAuthority() error = %v", err)
	}

	wrongRepository := HostedHoldExpectation{
		Path:              path,
		RepositoryAliases: []string{"foreign"},
		FenceGeneration:   evidence.FenceGeneration,
	}
	if got := authority.Validate(
		context.Background(),
		wrongRepository,
	); got.Validity != AuthorityInvalid {
		t.Fatalf("wrong repository Validate() = %#v", got)
	}

	evidence.NotAfter = now
	writeCanonicalHostedHoldEvidence(t, path, evidence)
	if got := authority.Validate(context.Background(), HostedHoldExpectation{
		Path:              path,
		RepositoryAliases: append([]string(nil), evidence.Repositories...),
		FenceGeneration:   evidence.FenceGeneration,
	}); got.Validity != AuthorityInvalid {
		t.Fatalf("expired Validate() = %#v", got)
	}

	document, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if err := os.WriteFile(path, append(document, '\n'), 0o600); err != nil {
		t.Fatalf("WriteFile(noncanonical) error = %v", err)
	}
	if got := authority.Validate(context.Background(), HostedHoldExpectation{
		Path:              path,
		RepositoryAliases: append([]string(nil), evidence.Repositories...),
		FenceGeneration:   evidence.FenceGeneration,
	}); got.Validity != AuthorityInvalid {
		t.Fatalf("noncanonical Validate() = %#v", got)
	}
}

func TestUnavailableLegacyCommandAuthorityIsClosedAndNeverValid(t *testing.T) {
	t.Parallel()

	authority, err := NewUnavailableLegacyCommandAuthority()
	if err != nil || authority == nil {
		t.Fatalf("NewUnavailableLegacyCommandAuthority() = %#v, %v", authority, err)
	}
	expectation := LegacyCommandExpectation{
		Path:                "/opt/portable/legacy/command.json",
		CommandDigest:       strings.Repeat("a", 64),
		ConfigurationDigest: strings.Repeat("b", 64),
		ImageDigests: []string{
			"registry.example/legacy@sha256:" + strings.Repeat("c", 64),
		},
		WatchdogDigest: strings.Repeat("d", 64),
	}
	if got := authority.Validate(
		context.Background(),
		expectation,
	); got.Validity != AuthorityUnavailable {
		t.Fatalf("Validate(valid tuple) = %#v", got)
	}
	expectation.CommandDigest = "invalid"
	if got := authority.Validate(
		context.Background(),
		expectation,
	); got.Validity != AuthorityInvalid {
		t.Fatalf("Validate(invalid tuple) = %#v", got)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if got := authority.Validate(
		cancelled,
		LegacyCommandExpectation{
			Path:                "/opt/portable/legacy/command.json",
			CommandDigest:       strings.Repeat("a", 64),
			ConfigurationDigest: strings.Repeat("b", 64),
			ImageDigests: []string{
				"registry.example/legacy@sha256:" + strings.Repeat("c", 64),
			},
			WatchdogDigest: strings.Repeat("d", 64),
		},
	); got.Validity != AuthorityUnavailable {
		t.Fatalf("Validate(cancelled) = %#v", got)
	}
}

func TestValidateTransitionAuthoritiesRejectsUnavailableLegacyBeforeWrite(
	t *testing.T,
) {
	t.Parallel()

	overlay, _ := protocolTestOverlay(t)
	overlay.Legacy = &hostruntime.LegacyOverlay{
		CommandFilePath:     "/opt/portable/legacy/command.json",
		CommandDigest:       strings.Repeat("a", 64),
		ConfigurationDigest: strings.Repeat("b", 64),
		ImageDigests: []string{
			"registry.example/legacy@sha256:" + strings.Repeat("c", 64),
		},
		WatchdogDigest: strings.Repeat("d", 64),
	}
	binding := hostruntime.OperationBinding{ExpectedGeneration: 9}
	arguments := InvokeArguments{
		HostedConfirmation: filepath.Join(
			overlay.Paths.StateRoot,
			"hosted-evidence",
			"hold.json",
		),
		LegacyCommandFile: overlay.Legacy.CommandFilePath,
	}
	hosted := fixedHostedHoldAuthority{
		validation: HostedHoldValidation{
			Validity:       AuthorityValid,
			EvidenceDigest: strings.Repeat("e", 64),
		},
	}
	unavailable, err := NewUnavailableLegacyCommandAuthority()
	if err != nil {
		t.Fatalf("NewUnavailableLegacyCommandAuthority() error = %v", err)
	}
	if _, err := validateTransitionAuthorities(
		context.Background(),
		cli.ActionRollback,
		overlay,
		arguments,
		binding,
		hosted,
		unavailable,
	); !errors.Is(err, ErrLifecycleAuthority) {
		t.Fatalf("unavailable legacy error = %v", err)
	}
	valid := fixedLegacyCommandAuthority{
		validation: LegacyCommandValidation{Validity: AuthorityValid},
	}
	expectation, err := validateTransitionAuthorities(
		context.Background(),
		cli.ActionRollback,
		overlay,
		arguments,
		binding,
		hosted,
		valid,
	)
	if err != nil || expectation.EvidenceDigest != strings.Repeat("e", 64) {
		t.Fatalf("valid authorities = %#v, %v", expectation, err)
	}
}

type fixedHostedHoldAuthority struct {
	validation HostedHoldValidation
}

func (authority fixedHostedHoldAuthority) Validate(
	context.Context,
	HostedHoldExpectation,
) HostedHoldValidation {
	return authority.validation
}

type fixedLegacyCommandAuthority struct {
	validation LegacyCommandValidation
}

func (authority fixedLegacyCommandAuthority) Validate(
	context.Context,
	LegacyCommandExpectation,
) LegacyCommandValidation {
	return authority.validation
}

func writeHostedHoldEvidenceFixture(
	t *testing.T,
	now time.Time,
) (string, HostedHoldEvidence) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "hosted-evidence")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("Mkdir(hosted-evidence) error = %v", err)
	}
	path := filepath.Join(root, "hold.json")
	evidence := HostedHoldEvidence{
		SchemaVersion:   1,
		HoldID:          "maintenance-20260801",
		TransitionEpoch: 17,
		FenceGeneration: 9,
		Route:           "hosted",
		HoldActive:      true,
		Repositories:    []string{"keicrew", "workspace"},
		NotBefore:       now.Add(-time.Minute),
		NotAfter:        now.Add(time.Minute),
		ProofDigest:     strings.Repeat("a", 64),
	}
	writeCanonicalHostedHoldEvidence(t, path, evidence)
	return path, evidence
}

func writeCanonicalHostedHoldEvidence(
	t *testing.T,
	path string,
	evidence HostedHoldEvidence,
) {
	t.Helper()
	document, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("json.Marshal(evidence) error = %v", err)
	}
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatalf("WriteFile(evidence) error = %v", err)
	}
}
