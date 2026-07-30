package upgrade

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"
)

const (
	runnerMaintenanceStatusProtocol    = "portable-ghar.runner-maintenance.status.v1"
	runnerMaintenanceDirectiveProtocol = "portable-ghar.runner-maintenance.directive.v1"
	runnerMaintenanceResponsePrefix    = "portable-ghar-response-v1\n"
	maintenanceBindingDomain           = "portable-ghar-runner-maintenance-binding-v1"
)

var (
	ErrInvalidMaintenanceRequest = errors.New(
		"upgrade: invalid maintenance request",
	)
	ErrInvalidMaintenanceDirective = errors.New(
		"upgrade: invalid maintenance directive",
	)
	ErrMaintenanceDirectiveUnauthorized = errors.New(
		"upgrade: maintenance directive unauthorized",
	)
	ErrMaintenanceUnavailable = errors.New(
		"upgrade: maintenance directive unavailable",
	)
)

// RunnerMaintenanceStatusRequest is byte-compatible with the Phase 3 status
// request.
type RunnerMaintenanceStatusRequest struct {
	Protocol                string  `json:"protocol"`
	FleetID                 string  `json:"fleetId"`
	Epoch                   uint64  `json:"epoch"`
	SessionID               string  `json:"sessionId"`
	ControlSequence         uint64  `json:"controlSequence"`
	SelectedManifestDigest  string  `json:"selectedManifestDigest"`
	CandidateManifestDigest *string `json:"candidateManifestDigest"`
}

// RunnerMaintenancePhase is the closed Worker-authorized local phase.
type RunnerMaintenancePhase string

const (
	MaintenanceWaitHosted       RunnerMaintenancePhase = "wait-hosted"
	MaintenanceStagePermitted   RunnerMaintenancePhase = "stage-permitted"
	MaintenanceReplacePermitted RunnerMaintenancePhase = "replace-permitted"
	MaintenanceCanaryPermitted  RunnerMaintenancePhase = "canary-permitted"
	MaintenanceEnablePermitted  RunnerMaintenancePhase = "enable-permitted"
	MaintenanceComplete         RunnerMaintenancePhase = "complete"
)

// MaintenanceDirectiveProvider is read-only. It exposes no route or local
// mutation method.
type MaintenanceDirectiveProvider interface {
	Current(
		context.Context,
		RunnerMaintenanceStatusRequest,
	) (RunnerMaintenanceDirective, error)
}

// MaintenanceResponseVerifier verifies the exact response frame and MAC.
type MaintenanceResponseVerifier interface {
	VerifyRunnerMaintenanceResponse(
		context.Context,
		[]byte,
		string,
	) error
}

type runnerMaintenanceDirectiveWire struct {
	Protocol                         string                 `json:"protocol"`
	Epoch                            uint64                 `json:"epoch"`
	SessionID                        string                 `json:"sessionId"`
	RequestControlSequence           uint64                 `json:"requestControlSequence"`
	RequestedSelectedManifestDigest  string                 `json:"requestedSelectedManifestDigest"`
	RequestedCandidateManifestDigest *string                `json:"requestedCandidateManifestDigest"`
	TransitionEpoch                  uint64                 `json:"transitionEpoch"`
	PermitGeneration                 uint64                 `json:"permitGeneration"`
	Phase                            RunnerMaintenancePhase `json:"phase"`
	QualifiedVersion                 *string                `json:"qualifiedVersion"`
	QualifiedManifestDigest          *string                `json:"qualifiedManifestDigest"`
	QualifiedImageDigest             *string                `json:"qualifiedImageDigest"`
	ConfigRevision                   uint64                 `json:"configRevision"`
	CanaryPolicyDigest               string                 `json:"canaryPolicyDigest"`
	EnabledPolicyDigest              string                 `json:"enabledPolicyDigest"`
	ExpiresAtServerMS                int64                  `json:"expiresAtServerMs"`
	ResponseMAC                      string                 `json:"responseMac"`
}

type runnerMaintenanceDirectiveSignedWire struct {
	Protocol                         string                 `json:"protocol"`
	Epoch                            uint64                 `json:"epoch"`
	SessionID                        string                 `json:"sessionId"`
	RequestControlSequence           uint64                 `json:"requestControlSequence"`
	RequestedSelectedManifestDigest  string                 `json:"requestedSelectedManifestDigest"`
	RequestedCandidateManifestDigest *string                `json:"requestedCandidateManifestDigest"`
	TransitionEpoch                  uint64                 `json:"transitionEpoch"`
	PermitGeneration                 uint64                 `json:"permitGeneration"`
	Phase                            RunnerMaintenancePhase `json:"phase"`
	QualifiedVersion                 *string                `json:"qualifiedVersion"`
	QualifiedManifestDigest          *string                `json:"qualifiedManifestDigest"`
	QualifiedImageDigest             *string                `json:"qualifiedImageDigest"`
	ConfigRevision                   uint64                 `json:"configRevision"`
	CanaryPolicyDigest               string                 `json:"canaryPolicyDigest"`
	EnabledPolicyDigest              string                 `json:"enabledPolicyDigest"`
	ExpiresAtServerMS                int64                  `json:"expiresAtServerMs"`
}

// RunnerMaintenanceDirective carries private verified authority. Its zero
// value and direct literals cannot authorize a phase.
type RunnerMaintenanceDirective struct {
	wire           runnerMaintenanceDirectiveWire
	signedDocument []byte
	verified       bool
}

type directiveAuthorization struct {
	phase                   RunnerMaintenancePhase
	bindingDigest           string
	enrollmentBindingDigest string
	enrollmentEpoch         uint64
	controlSequence         uint64
}

// UnavailableMaintenanceDirectiveProvider is the Phase 2 production default.
// It performs no I/O and never returns authority.
type UnavailableMaintenanceDirectiveProvider struct{}

func (UnavailableMaintenanceDirectiveProvider) Current(
	context.Context,
	RunnerMaintenanceStatusRequest,
) (RunnerMaintenanceDirective, error) {
	return RunnerMaintenanceDirective{}, ErrMaintenanceUnavailable
}

// MarshalRunnerMaintenanceStatusRequest emits the only canonical V1 request
// form.
func MarshalRunnerMaintenanceStatusRequest(
	request RunnerMaintenanceStatusRequest,
) ([]byte, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}
	document, err := json.Marshal(request)
	if err != nil {
		return nil, ErrInvalidMaintenanceRequest
	}
	return document, nil
}

// Validate rejects open, stale, or malformed request identities.
func (request RunnerMaintenanceStatusRequest) Validate() error {
	if request.Protocol != runnerMaintenanceStatusProtocol ||
		!validBoundedID(request.FleetID, 64) ||
		!validBoundedSessionID(request.SessionID, 128) ||
		request.Epoch == 0 ||
		request.ControlSequence == 0 ||
		!validRawDigest(request.SelectedManifestDigest) ||
		(request.CandidateManifestDigest != nil &&
			!validRawDigest(*request.CandidateManifestDigest)) {
		return ErrInvalidMaintenanceRequest
	}
	return nil
}

// ParseVerifiedRunnerMaintenanceDirective strictly canonicalizes, validates,
// and authenticates a bounded response before constructing authority.
func ParseVerifiedRunnerMaintenanceDirective(
	ctx context.Context,
	document []byte,
	maxBytes int,
	verifier MaintenanceResponseVerifier,
) (RunnerMaintenanceDirective, error) {
	if ctx == nil ||
		verifier == nil ||
		maxBytes <= 0 ||
		len(document) == 0 ||
		len(document) > maxBytes {
		return RunnerMaintenanceDirective{}, ErrInvalidMaintenanceDirective
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var wire runnerMaintenanceDirectiveWire
	if err := decoder.Decode(&wire); err != nil {
		return RunnerMaintenanceDirective{}, ErrInvalidMaintenanceDirective
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return RunnerMaintenanceDirective{}, ErrInvalidMaintenanceDirective
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, document) {
		return RunnerMaintenanceDirective{}, ErrInvalidMaintenanceDirective
	}
	if err := validateMaintenanceWire(wire); err != nil {
		return RunnerMaintenanceDirective{}, err
	}
	var signed runnerMaintenanceDirectiveSignedWire
	copyMaintenanceSignedWire(&signed, wire)
	signedDocument, err := json.Marshal(signed)
	if err != nil {
		return RunnerMaintenanceDirective{}, ErrInvalidMaintenanceDirective
	}
	var frame []byte
	frame = append(frame, runnerMaintenanceResponsePrefix...)
	frame = append(frame, wire.Protocol...)
	frame = append(frame, '\n')
	frame = append(frame, signedDocument...)
	if err := verifier.VerifyRunnerMaintenanceResponse(
		ctx,
		frame,
		wire.ResponseMAC,
	); err != nil {
		return RunnerMaintenanceDirective{}, ErrInvalidMaintenanceDirective
	}
	return RunnerMaintenanceDirective{
		wire:           cloneMaintenanceWire(wire),
		signedDocument: append([]byte(nil), signedDocument...),
		verified:       true,
	}, nil
}

func (directive RunnerMaintenanceDirective) authorize(
	request RunnerMaintenanceStatusRequest,
	now time.Time,
	maxFuture time.Duration,
	expectedPhase RunnerMaintenancePhase,
	candidate *Candidate,
	configRevision uint64,
	canaryPolicyDigest string,
	enabledPolicyDigest string,
) (directiveAuthorization, error) {
	if !directive.verified ||
		request.Validate() != nil ||
		!validUTCTime(now) ||
		maxFuture <= 0 ||
		configRevision == 0 ||
		!validRawDigest(canaryPolicyDigest) ||
		!validRawDigest(enabledPolicyDigest) {
		return directiveAuthorization{}, ErrMaintenanceDirectiveUnauthorized
	}
	wire := directive.wire
	if wire.Phase != expectedPhase ||
		wire.Epoch != request.Epoch ||
		wire.SessionID != request.SessionID ||
		wire.RequestControlSequence != request.ControlSequence ||
		wire.RequestedSelectedManifestDigest !=
			request.SelectedManifestDigest ||
		!optionalStringEqual(
			wire.RequestedCandidateManifestDigest,
			request.CandidateManifestDigest,
		) ||
		wire.ConfigRevision != configRevision ||
		wire.CanaryPolicyDigest != canaryPolicyDigest ||
		wire.EnabledPolicyDigest != enabledPolicyDigest ||
		wire.ExpiresAtServerMS <= now.UnixMilli() ||
		wire.ExpiresAtServerMS > now.Add(maxFuture).UnixMilli() {
		return directiveAuthorization{}, ErrMaintenanceDirectiveUnauthorized
	}
	if expectedPhase != MaintenanceWaitHosted {
		if candidate == nil ||
			candidate.Validate() != nil ||
			request.CandidateManifestDigest == nil ||
			*request.CandidateManifestDigest != candidate.ManifestDigest {
			return directiveAuthorization{}, ErrMaintenanceDirectiveUnauthorized
		}
	}
	switch expectedPhase {
	case MaintenanceStagePermitted:
		if !qualifiedTupleNil(wire) {
			return directiveAuthorization{}, ErrMaintenanceDirectiveUnauthorized
		}
	case MaintenanceReplacePermitted,
		MaintenanceCanaryPermitted,
		MaintenanceEnablePermitted,
		MaintenanceComplete:
		if candidate == nil ||
			!wireMatchesCandidate(wire, *candidate) {
			return directiveAuthorization{}, ErrMaintenanceDirectiveUnauthorized
		}
	case MaintenanceWaitHosted:
	default:
		return directiveAuthorization{}, ErrMaintenanceDirectiveUnauthorized
	}
	requestDocument, err := MarshalRunnerMaintenanceStatusRequest(request)
	if err != nil {
		return directiveAuthorization{}, ErrMaintenanceDirectiveUnauthorized
	}
	hash := sha256.New()
	for _, field := range [][]byte{
		[]byte(maintenanceBindingDomain),
		requestDocument,
		directive.signedDocument,
		[]byte(expectedPhase),
	} {
		writeEvidenceField(hash, field)
	}
	bindingDigest := hex.EncodeToString(hash.Sum(nil))
	enrollmentHash := sha256.New()
	for _, field := range [][]byte{
		[]byte(maintenanceBindingDomain + "-enrollment"),
		[]byte(request.FleetID),
		[]byte(stringInteger(request.Epoch)),
		[]byte(request.SessionID),
	} {
		writeEvidenceField(enrollmentHash, field)
	}
	return directiveAuthorization{
		phase:                   expectedPhase,
		bindingDigest:           bindingDigest,
		enrollmentBindingDigest: hex.EncodeToString(enrollmentHash.Sum(nil)),
		enrollmentEpoch:         request.Epoch,
		controlSequence:         request.ControlSequence,
	}, nil
}

func validateMaintenanceWire(
	wire runnerMaintenanceDirectiveWire,
) error {
	if wire.Protocol != runnerMaintenanceDirectiveProtocol ||
		wire.Epoch == 0 ||
		!validBoundedSessionID(wire.SessionID, 128) ||
		wire.RequestControlSequence == 0 ||
		!validRawDigest(wire.RequestedSelectedManifestDigest) ||
		(wire.RequestedCandidateManifestDigest != nil &&
			!validRawDigest(*wire.RequestedCandidateManifestDigest)) ||
		wire.TransitionEpoch == 0 ||
		wire.PermitGeneration == 0 ||
		wire.ConfigRevision == 0 ||
		!validRawDigest(wire.CanaryPolicyDigest) ||
		!validRawDigest(wire.EnabledPolicyDigest) ||
		wire.ExpiresAtServerMS <= 0 ||
		!validOpaqueMAC(wire.ResponseMAC) ||
		!validMaintenancePhaseShape(wire) {
		return ErrInvalidMaintenanceDirective
	}
	return nil
}

func validMaintenancePhaseShape(
	wire runnerMaintenanceDirectiveWire,
) bool {
	anyQualified := wire.QualifiedVersion != nil ||
		wire.QualifiedManifestDigest != nil ||
		wire.QualifiedImageDigest != nil
	hasQualified := wire.QualifiedVersion != nil &&
		wire.QualifiedManifestDigest != nil &&
		wire.QualifiedImageDigest != nil
	if anyQualified && !hasQualified {
		return false
	}
	if hasQualified {
		if _, err := parseRunnerVersion(*wire.QualifiedVersion); err != nil ||
			!validRawDigest(*wire.QualifiedManifestDigest) ||
			!validImageDigest(*wire.QualifiedImageDigest) {
			return false
		}
	}
	switch wire.Phase {
	case MaintenanceWaitHosted:
		if hasQualified {
			return wire.RequestedCandidateManifestDigest != nil &&
				*wire.RequestedCandidateManifestDigest ==
					*wire.QualifiedManifestDigest
		}
		return true
	case MaintenanceStagePermitted:
		return wire.RequestedCandidateManifestDigest != nil &&
			!anyQualified
	case MaintenanceReplacePermitted,
		MaintenanceCanaryPermitted,
		MaintenanceEnablePermitted,
		MaintenanceComplete:
		return wire.RequestedCandidateManifestDigest != nil &&
			hasQualified &&
			*wire.RequestedCandidateManifestDigest ==
				*wire.QualifiedManifestDigest
	default:
		return false
	}
}

func qualifiedTupleNil(wire runnerMaintenanceDirectiveWire) bool {
	return wire.QualifiedVersion == nil &&
		wire.QualifiedManifestDigest == nil &&
		wire.QualifiedImageDigest == nil
}

func wireMatchesCandidate(
	wire runnerMaintenanceDirectiveWire,
	candidate Candidate,
) bool {
	return wire.QualifiedVersion != nil &&
		wire.QualifiedManifestDigest != nil &&
		wire.QualifiedImageDigest != nil &&
		*wire.QualifiedVersion == candidate.Version &&
		*wire.QualifiedManifestDigest == candidate.ManifestDigest &&
		*wire.QualifiedImageDigest == candidate.ImageDigest
}

func copyMaintenanceSignedWire(
	target *runnerMaintenanceDirectiveSignedWire,
	source runnerMaintenanceDirectiveWire,
) {
	*target = runnerMaintenanceDirectiveSignedWire{
		Protocol:                         source.Protocol,
		Epoch:                            source.Epoch,
		SessionID:                        source.SessionID,
		RequestControlSequence:           source.RequestControlSequence,
		RequestedSelectedManifestDigest:  source.RequestedSelectedManifestDigest,
		RequestedCandidateManifestDigest: cloneOptionalString(source.RequestedCandidateManifestDigest),
		TransitionEpoch:                  source.TransitionEpoch,
		PermitGeneration:                 source.PermitGeneration,
		Phase:                            source.Phase,
		QualifiedVersion:                 cloneOptionalString(source.QualifiedVersion),
		QualifiedManifestDigest:          cloneOptionalString(source.QualifiedManifestDigest),
		QualifiedImageDigest:             cloneOptionalString(source.QualifiedImageDigest),
		ConfigRevision:                   source.ConfigRevision,
		CanaryPolicyDigest:               source.CanaryPolicyDigest,
		EnabledPolicyDigest:              source.EnabledPolicyDigest,
		ExpiresAtServerMS:                source.ExpiresAtServerMS,
	}
}

func cloneMaintenanceWire(
	source runnerMaintenanceDirectiveWire,
) runnerMaintenanceDirectiveWire {
	source.RequestedCandidateManifestDigest = cloneOptionalString(
		source.RequestedCandidateManifestDigest,
	)
	source.QualifiedVersion = cloneOptionalString(source.QualifiedVersion)
	source.QualifiedManifestDigest = cloneOptionalString(
		source.QualifiedManifestDigest,
	)
	source.QualifiedImageDigest = cloneOptionalString(
		source.QualifiedImageDigest,
	)
	return source
}

func cloneOptionalString(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func optionalStringEqual(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func validBoundedID(value string, maxBytes int) bool {
	if len(value) == 0 || len(value) > maxBytes ||
		!isLowerAlphaNumeric(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !isLowerAlphaNumeric(character) &&
			character != '.' &&
			character != '_' &&
			character != '-' {
			return false
		}
	}
	return true
}

func validBoundedSessionID(value string, maxBytes int) bool {
	if len(value) == 0 || len(value) > maxBytes {
		return false
	}
	for index := range value {
		character := value[index]
		if !isASCIIAlphaNumeric(character) &&
			character != '.' &&
			character != '_' &&
			character != '-' &&
			character != ':' {
			return false
		}
	}
	return true
}

func validOpaqueMAC(value string) bool {
	if len(value) < 16 || len(value) > 512 {
		return false
	}
	for index := range value {
		character := value[index]
		if !isASCIIAlphaNumeric(character) &&
			character != '-' &&
			character != '_' {
			return false
		}
	}
	return true
}

func isLowerAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' ||
		value >= '0' && value <= '9'
}

func isASCIIAlphaNumeric(value byte) bool {
	return isLowerAlphaNumeric(value) ||
		value >= 'A' && value <= 'Z'
}

var _ MaintenanceDirectiveProvider = UnavailableMaintenanceDirectiveProvider{}
