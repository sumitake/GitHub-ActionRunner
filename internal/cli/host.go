// Package cli owns the exact public Portable-GHAR command grammar and the
// closed host-transport boundary. It contains no generic command, shell,
// destination, environment, or stdin surface.
package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sumitake/portable-ghar/internal/fleetfence"
	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

const (
	targetProofSchemaVersion = uint32(1)
	stageProofSchemaVersion  = uint32(1)
	targetProofDomain        = "portable-ghar-cli-target-proof-v1"
	stageProofDomain         = "portable-ghar-cli-stage-proof-v1"
	verifyOperationDomain    = "portable-ghar-verify-operation-v1"
	maxPrivateOverlayBytes   = 2 << 20
	maxRuntimeManifestBytes  = 1 << 16
)

var (
	ErrHostUsage         = errors.New("cli: invalid host command")
	ErrHostCommandFailed = errors.New("cli: host command failed")
)

type HostAction uint8

const (
	ActionInstall HostAction = iota + 1
	ActionVerify
	ActionSuspend
	ActionResume
	// ActionRollback and ActionUninstall are target-local lifecycle actions.
	// ParseHostCommand and the SSH protocol intentionally never expose them.
	ActionRollback
	ActionUninstall
)

type HostRequest struct {
	Action             HostAction
	PrivatePath        string
	DrainPolicy        string
	HostedConfirmation string
}

type TargetProof struct {
	SchemaVersion          uint32                          `json:"schema_version"`
	PrivateOverlayRevision string                          `json:"private_overlay_revision"`
	HostIdentityDigest     string                          `json:"host_identity_digest"`
	ControlIdentityDigest  string                          `json:"control_identity_digest"`
	OS                     string                          `json:"os"`
	Architecture           string                          `json:"architecture"`
	ExpectedEUID           uint64                          `json:"expected_euid"`
	FenceGeneration        uint64                          `json:"fence_generation"`
	ActiveFleet            fleetfence.Fleet                `json:"active_fleet"`
	CurrentManifestDigest  *string                         `json:"current_manifest_digest"`
	InstallDisposition     *hostruntime.InstallDisposition `json:"install_disposition"`
	ProofDigest            string                          `json:"proof_digest"`
}

type targetProofPreimage struct {
	SchemaVersion          uint32                          `json:"schema_version"`
	PrivateOverlayRevision string                          `json:"private_overlay_revision"`
	HostIdentityDigest     string                          `json:"host_identity_digest"`
	ControlIdentityDigest  string                          `json:"control_identity_digest"`
	OS                     string                          `json:"os"`
	Architecture           string                          `json:"architecture"`
	ExpectedEUID           uint64                          `json:"expected_euid"`
	FenceGeneration        uint64                          `json:"fence_generation"`
	ActiveFleet            fleetfence.Fleet                `json:"active_fleet"`
	CurrentManifestDigest  *string                         `json:"current_manifest_digest"`
	InstallDisposition     *hostruntime.InstallDisposition `json:"install_disposition"`
}

type StageProof struct {
	SchemaVersion          uint32 `json:"schema_version"`
	TargetProofDigest      string `json:"target_proof_digest"`
	PrivateOverlayRevision string `json:"private_overlay_revision"`
	ManifestDigest         string `json:"manifest_digest"`
	ProofDigest            string `json:"proof_digest"`
}

type stageProofPreimage struct {
	SchemaVersion          uint32 `json:"schema_version"`
	TargetProofDigest      string `json:"target_proof_digest"`
	PrivateOverlayRevision string `json:"private_overlay_revision"`
	ManifestDigest         string `json:"manifest_digest"`
}

type StagedRelease struct {
	manifest               hostruntime.RuntimeManifest
	manifestDocument       []byte
	manifestDigest         string
	privateOverlayRevision string
}

func (release StagedRelease) Manifest() hostruntime.RuntimeManifest {
	return release.manifest
}

func (release StagedRelease) ManifestDocument() []byte {
	return append([]byte(nil), release.manifestDocument...)
}

func (release StagedRelease) ManifestDigest() string {
	return release.manifestDigest
}

func (release StagedRelease) PrivateOverlayRevision() string {
	return release.privateOverlayRevision
}

type FixedArguments struct {
	privatePath             string
	acquisition             string
	drainPolicy             string
	hostedConfirmation      string
	requireZeroListeners    bool
	manifestDigest          string
	privateOverlayRevision  string
	targetProofDigest       string
	stageProofDigest        string
	expectedOperationID     string
	expectedFenceGeneration uint64
	expectedFleet           fleetfence.Fleet
}

func (arguments FixedArguments) PrivatePath() string {
	return arguments.privatePath
}

func (arguments FixedArguments) Acquisition() string {
	return arguments.acquisition
}

func (arguments FixedArguments) DrainPolicy() string {
	return arguments.drainPolicy
}

func (arguments FixedArguments) HostedConfirmation() string {
	return arguments.hostedConfirmation
}

func (arguments FixedArguments) RequireZeroListeners() bool {
	return arguments.requireZeroListeners
}

func (arguments FixedArguments) ManifestDigest() string {
	return arguments.manifestDigest
}

func (arguments FixedArguments) PrivateOverlayRevision() string {
	return arguments.privateOverlayRevision
}

func (arguments FixedArguments) TargetProofDigest() string {
	return arguments.targetProofDigest
}

func (arguments FixedArguments) StageProofDigest() string {
	return arguments.stageProofDigest
}

func (arguments FixedArguments) ExpectedOperationID() string {
	return arguments.expectedOperationID
}

func (arguments FixedArguments) ExpectedFenceGeneration() uint64 {
	return arguments.expectedFenceGeneration
}

func (arguments FixedArguments) ExpectedFleet() fleetfence.Fleet {
	return arguments.expectedFleet
}

type ActionResult struct {
	Result hostruntime.HostActionResult
}

type HostTransport interface {
	ProveTarget(
		context.Context,
		hostruntime.PrivateOverlay,
	) (TargetProof, error)
	Stage(
		context.Context,
		TargetProof,
		StagedRelease,
	) (StageProof, error)
	Invoke(
		context.Context,
		TargetProof,
		HostAction,
		FixedArguments,
	) (ActionResult, error)
}

type HostCommandDependencies struct {
	LoadPrivateOverlay func(string) (
		hostruntime.PrivateOverlay,
		string,
		error,
	)
	LoadRuntimeManifest func(string) (
		hostruntime.RuntimeManifest,
		[]byte,
		string,
		error,
	)
	TransportForOverlay func(
		hostruntime.PrivateOverlay,
	) (HostTransport, error)
}

type PublicHostResult struct {
	Status            hostruntime.HostActionStatus `json:"status"`
	Action            string                       `json:"action"`
	OperationID       string                       `json:"operation_id"`
	JournalDigest     string                       `json:"journal_digest"`
	TargetProofDigest string                       `json:"target_proof_digest"`
	FenceGeneration   uint64                       `json:"fence_generation"`
	ActiveFleet       fleetfence.Fleet             `json:"active_fleet"`
}

func ParseHostCommand(args []string) (HostRequest, error) {
	var request HostRequest
	switch {
	case len(args) == 6 &&
		args[0] == "deploy" &&
		args[1] == "host" &&
		args[2] == "--private" &&
		args[4] == "--acquisition" &&
		args[5] == "disabled":
		request = HostRequest{
			Action:      ActionInstall,
			PrivatePath: args[3],
		}
	case len(args) == 5 &&
		args[0] == "verify" &&
		args[1] == "host" &&
		args[2] == "--private" &&
		args[4] == "--require-zero-listeners":
		request = HostRequest{
			Action:      ActionVerify,
			PrivatePath: args[3],
		}
	case len(args) == 7 &&
		args[0] == "suspend" &&
		args[1] == "host" &&
		args[2] == "--private" &&
		(args[4] == "--drain-policy=wait" ||
			args[4] == "--drain-policy=cancel") &&
		args[5] == "--hosted-confirmation":
		request = HostRequest{
			Action:             ActionSuspend,
			PrivatePath:        args[3],
			DrainPolicy:        strings.TrimPrefix(args[4], "--drain-policy="),
			HostedConfirmation: args[6],
		}
	case len(args) == 6 &&
		args[0] == "resume" &&
		args[1] == "host" &&
		args[2] == "--private" &&
		args[4] == "--acquisition" &&
		args[5] == "disabled":
		request = HostRequest{
			Action:      ActionResume,
			PrivatePath: args[3],
		}
	default:
		return HostRequest{}, ErrHostUsage
	}
	if !canonicalHostPath(request.PrivatePath) ||
		request.HostedConfirmation != "" &&
			(!canonicalHostPath(request.HostedConfirmation) ||
				request.HostedConfirmation == request.PrivatePath) {
		return HostRequest{}, ErrHostUsage
	}
	return request, nil
}

func RunHostCommand(
	ctx context.Context,
	args []string,
	dependencies HostCommandDependencies,
) (PublicHostResult, error) {
	if ctx == nil ||
		dependencies.LoadPrivateOverlay == nil ||
		dependencies.LoadRuntimeManifest == nil ||
		dependencies.TransportForOverlay == nil {
		return PublicHostResult{}, ErrHostCommandFailed
	}
	request, err := ParseHostCommand(args)
	if err != nil {
		return PublicHostResult{}, err
	}
	overlay, revision, err := dependencies.LoadPrivateOverlay(
		request.PrivatePath,
	)
	if err != nil ||
		!validLowerDigest(revision) ||
		!validLoadedOverlayIdentity(overlay) {
		return PublicHostResult{}, ErrHostCommandFailed
	}
	transport, err := dependencies.TransportForOverlay(overlay)
	if err != nil || transport == nil {
		return PublicHostResult{}, ErrHostCommandFailed
	}
	target, err := transport.ProveTarget(ctx, overlay)
	if err != nil ||
		validateTargetProof(target) != nil ||
		!targetMatchesOverlay(target, overlay, revision) {
		return PublicHostResult{}, ErrHostCommandFailed
	}
	operationID, terminalGeneration, terminalFleet, err := expectedOperation(
		request.Action,
		target,
		overlay.Manifest.Digest,
		revision,
	)
	if err != nil {
		return PublicHostResult{}, ErrHostCommandFailed
	}
	arguments := FixedArguments{
		privatePath:             request.PrivatePath,
		drainPolicy:             request.DrainPolicy,
		hostedConfirmation:      request.HostedConfirmation,
		requireZeroListeners:    request.Action == ActionVerify,
		manifestDigest:          overlay.Manifest.Digest,
		privateOverlayRevision:  revision,
		targetProofDigest:       target.ProofDigest,
		expectedOperationID:     operationID,
		expectedFenceGeneration: terminalGeneration,
		expectedFleet:           terminalFleet,
	}
	if request.Action == ActionInstall || request.Action == ActionResume {
		arguments.acquisition = "disabled"
	}
	if request.Action == ActionInstall {
		manifest, document, manifestDigest, loadErr :=
			dependencies.LoadRuntimeManifest(overlay.Manifest.Path)
		if loadErr != nil ||
			manifestDigest != overlay.Manifest.Digest ||
			len(document) == 0 {
			return PublicHostResult{}, ErrHostCommandFailed
		}
		canonical, canonicalDigest, marshalErr :=
			hostruntime.MarshalRuntimeManifest(manifest)
		if marshalErr != nil ||
			canonicalDigest != manifestDigest ||
			!bytes.Equal(canonical, document) {
			return PublicHostResult{}, ErrHostCommandFailed
		}
		release := StagedRelease{
			manifest:               manifest,
			manifestDocument:       append([]byte(nil), document...),
			manifestDigest:         manifestDigest,
			privateOverlayRevision: revision,
		}
		stage, stageErr := transport.Stage(
			ctx,
			target,
			release,
		)
		if stageErr != nil ||
			validateStageProof(stage) != nil ||
			stage.TargetProofDigest != target.ProofDigest ||
			stage.PrivateOverlayRevision != revision ||
			stage.ManifestDigest != manifestDigest {
			return PublicHostResult{}, ErrHostCommandFailed
		}
		arguments.stageProofDigest = stage.ProofDigest
	}
	actionResult, err := transport.Invoke(
		ctx,
		target,
		request.Action,
		arguments,
	)
	if err != nil ||
		validateActionResult(actionResult.Result) != nil ||
		actionResult.Result.Status != hostruntime.HostActionComplete ||
		actionResult.Result.OperationID != operationID ||
		actionResult.Result.FenceGeneration != terminalGeneration ||
		actionResult.Result.ActiveFleet != terminalFleet ||
		actionResult.Result.TargetProofDigest == nil {
		return PublicHostResult{}, ErrHostCommandFailed
	}
	return PublicHostResult{
		Status:            actionResult.Result.Status,
		Action:            request.Action.String(),
		OperationID:       actionResult.Result.OperationID,
		JournalDigest:     actionResult.Result.JournalDigest,
		TargetProofDigest: *actionResult.Result.TargetProofDigest,
		FenceGeneration:   actionResult.Result.FenceGeneration,
		ActiveFleet:       actionResult.Result.ActiveFleet,
	}, nil
}

func DefaultHostCommandDependencies(
	transportForOverlay func(
		hostruntime.PrivateOverlay,
	) (HostTransport, error),
) HostCommandDependencies {
	return HostCommandDependencies{
		LoadPrivateOverlay:  LoadPrivateOverlayFile,
		LoadRuntimeManifest: LoadRuntimeManifestFile,
		TransportForOverlay: transportForOverlay,
	}
}

func LoadPrivateOverlayFile(
	path string,
) (hostruntime.PrivateOverlay, string, error) {
	document, err := readBoundedFile(path, maxPrivateOverlayBytes)
	if err != nil {
		return hostruntime.PrivateOverlay{}, "", ErrHostCommandFailed
	}
	return hostruntime.ParsePrivateOverlay(document, maxPrivateOverlayBytes)
}

func LoadRuntimeManifestFile(
	path string,
) (hostruntime.RuntimeManifest, []byte, string, error) {
	document, err := readBoundedFile(path, maxRuntimeManifestBytes)
	if err != nil {
		return hostruntime.RuntimeManifest{}, nil, "", ErrHostCommandFailed
	}
	manifest, digest, err := hostruntime.ParseRuntimeManifest(
		document,
		maxRuntimeManifestBytes,
	)
	if err != nil {
		return hostruntime.RuntimeManifest{}, nil, "", ErrHostCommandFailed
	}
	return manifest, document, digest, nil
}

func SealTargetProof(proof TargetProof) (TargetProof, error) {
	proof.ProofDigest = ""
	if err := validateTargetProofShape(proof); err != nil {
		return TargetProof{}, err
	}
	document, err := json.Marshal(targetProofPreimageOf(proof))
	if err != nil {
		return TargetProof{}, ErrHostCommandFailed
	}
	proof.ProofDigest = artifactDigest(targetProofDomain, document)
	return proof, nil
}

func SealStageProof(proof StageProof) (StageProof, error) {
	proof.ProofDigest = ""
	if proof.SchemaVersion != stageProofSchemaVersion ||
		!validLowerDigest(proof.TargetProofDigest) ||
		!validLowerDigest(proof.PrivateOverlayRevision) ||
		!validLowerDigest(proof.ManifestDigest) {
		return StageProof{}, ErrHostCommandFailed
	}
	document, err := json.Marshal(stageProofPreimage{
		SchemaVersion:          proof.SchemaVersion,
		TargetProofDigest:      proof.TargetProofDigest,
		PrivateOverlayRevision: proof.PrivateOverlayRevision,
		ManifestDigest:         proof.ManifestDigest,
	})
	if err != nil {
		return StageProof{}, ErrHostCommandFailed
	}
	proof.ProofDigest = artifactDigest(stageProofDomain, document)
	return proof, nil
}

func validateTargetProof(proof TargetProof) error {
	if err := validateTargetProofShape(proof); err != nil ||
		!validLowerDigest(proof.ProofDigest) {
		return ErrHostCommandFailed
	}
	sealed, err := SealTargetProof(proof)
	if err != nil || sealed.ProofDigest != proof.ProofDigest {
		return ErrHostCommandFailed
	}
	return nil
}

func validateTargetProofShape(proof TargetProof) error {
	if proof.SchemaVersion != targetProofSchemaVersion ||
		!validLowerDigest(proof.PrivateOverlayRevision) ||
		!validLowerDigest(proof.HostIdentityDigest) ||
		!validLowerDigest(proof.ControlIdentityDigest) ||
		proof.HostIdentityDigest == proof.ControlIdentityDigest ||
		proof.OS != "linux" ||
		proof.Architecture != "amd64" ||
		proof.ExpectedEUID != 0 ||
		!validFleet(proof.ActiveFleet) ||
		proof.CurrentManifestDigest != nil &&
			!validLowerDigest(*proof.CurrentManifestDigest) {
		return ErrHostCommandFailed
	}
	if proof.InstallDisposition != nil {
		switch *proof.InstallDisposition {
		case hostruntime.InstallDispositionGreenfieldPortable,
			hostruntime.InstallDispositionUpgradePortable,
			hostruntime.InstallDispositionLegacyDisabledObserver:
		default:
			return ErrHostCommandFailed
		}
	}
	return nil
}

func validateStageProof(proof StageProof) error {
	if !validLowerDigest(proof.ProofDigest) {
		return ErrHostCommandFailed
	}
	sealed, err := SealStageProof(proof)
	if err != nil || sealed.ProofDigest != proof.ProofDigest {
		return ErrHostCommandFailed
	}
	return nil
}

func validateActionResult(result hostruntime.HostActionResult) error {
	_, _, err := hostruntime.MarshalHostActionResult(result)
	return err
}

func targetMatchesOverlay(
	target TargetProof,
	overlay hostruntime.PrivateOverlay,
	revision string,
) bool {
	return target.PrivateOverlayRevision == revision &&
		target.HostIdentityDigest == overlay.Target.HostIdentityDigest &&
		target.ControlIdentityDigest ==
			overlay.Target.ControlHostIdentityDigest &&
		target.OS == overlay.Target.OS &&
		target.Architecture == overlay.Target.Architecture &&
		target.ExpectedEUID == overlay.Target.ExpectedEUID
}

func expectedOperation(
	action HostAction,
	target TargetProof,
	manifestDigest string,
	revision string,
) (string, uint64, fleetfence.Fleet, error) {
	if !validLowerDigest(manifestDigest) || !validLowerDigest(revision) {
		return "", 0, "", ErrHostCommandFailed
	}
	switch action {
	case ActionInstall:
		if target.InstallDisposition == nil {
			return "", 0, "", ErrHostCommandFailed
		}
		var targetFleet fleetfence.Fleet
		var terminalFleet fleetfence.Fleet
		var terminalGeneration uint64
		switch *target.InstallDisposition {
		case hostruntime.InstallDispositionGreenfieldPortable:
			if target.FenceGeneration != 0 ||
				target.ActiveFleet != fleetfence.FleetNone ||
				target.CurrentManifestDigest != nil {
				return "", 0, "", ErrHostCommandFailed
			}
			targetFleet = fleetfence.FleetPortable
			terminalFleet = fleetfence.FleetPortable
			terminalGeneration = 1
		case hostruntime.InstallDispositionUpgradePortable:
			if target.FenceGeneration == 0 ||
				target.ActiveFleet != fleetfence.FleetPortable ||
				target.CurrentManifestDigest == nil {
				return "", 0, "", ErrHostCommandFailed
			}
			targetFleet = fleetfence.FleetPortable
			terminalFleet = fleetfence.FleetPortable
			terminalGeneration = target.FenceGeneration
		case hostruntime.InstallDispositionLegacyDisabledObserver:
			if target.FenceGeneration == 0 ||
				target.ActiveFleet != fleetfence.FleetLegacy ||
				target.CurrentManifestDigest == nil {
				return "", 0, "", ErrHostCommandFailed
			}
			targetFleet = fleetfence.FleetLegacy
			terminalFleet = fleetfence.FleetLegacy
			terminalGeneration = target.FenceGeneration
		}
		targetManifest := manifestDigest
		operationID, err := hostruntime.DeriveOperationID(
			hostruntime.OperationKindInstall,
			target.InstallDisposition,
			target.FenceGeneration,
			target.CurrentManifestDigest,
			&targetManifest,
			targetFleet,
			revision,
		)
		return operationID, terminalGeneration, terminalFleet, err
	case ActionVerify:
		operationID := artifactDigest(
			verifyOperationDomain,
			[]byte(target.ProofDigest+manifestDigest),
		)
		return operationID, target.FenceGeneration, target.ActiveFleet, nil
	case ActionSuspend:
		if target.FenceGeneration == 0 ||
			target.ActiveFleet != fleetfence.FleetPortable ||
			target.CurrentManifestDigest == nil {
			return "", 0, "", ErrHostCommandFailed
		}
		operationID, err := hostruntime.DeriveOperationID(
			hostruntime.OperationKindSuspend,
			nil,
			target.FenceGeneration,
			target.CurrentManifestDigest,
			nil,
			fleetfence.FleetNone,
			revision,
		)
		if target.FenceGeneration == ^uint64(0) {
			return "", 0, "", ErrHostCommandFailed
		}
		return operationID, target.FenceGeneration + 1, fleetfence.FleetNone, err
	case ActionResume:
		if target.FenceGeneration == 0 ||
			target.ActiveFleet != fleetfence.FleetNone {
			return "", 0, "", ErrHostCommandFailed
		}
		targetManifest := manifestDigest
		operationID, err := hostruntime.DeriveOperationID(
			hostruntime.OperationKindResume,
			nil,
			target.FenceGeneration,
			target.CurrentManifestDigest,
			&targetManifest,
			fleetfence.FleetPortable,
			revision,
		)
		if target.FenceGeneration == ^uint64(0) {
			return "", 0, "", ErrHostCommandFailed
		}
		return operationID, target.FenceGeneration + 1, fleetfence.FleetPortable, err
	case ActionRollback:
		if target.FenceGeneration == 0 ||
			target.FenceGeneration == ^uint64(0) ||
			target.ActiveFleet != fleetfence.FleetPortable ||
			target.CurrentManifestDigest == nil {
			return "", 0, "", ErrHostCommandFailed
		}
		operationID, err := hostruntime.DeriveOperationID(
			hostruntime.OperationKindRollback,
			nil,
			target.FenceGeneration,
			target.CurrentManifestDigest,
			nil,
			fleetfence.FleetLegacy,
			revision,
		)
		return operationID, target.FenceGeneration + 1, fleetfence.FleetLegacy, err
	case ActionUninstall:
		if target.FenceGeneration == 0 ||
			target.CurrentManifestDigest == nil ||
			(target.ActiveFleet != fleetfence.FleetNone &&
				target.ActiveFleet != fleetfence.FleetLegacy) {
			return "", 0, "", ErrHostCommandFailed
		}
		operationID, err := hostruntime.DeriveOperationID(
			hostruntime.OperationKindUninstall,
			nil,
			target.FenceGeneration,
			target.CurrentManifestDigest,
			nil,
			target.ActiveFleet,
			revision,
		)
		return operationID, target.FenceGeneration, target.ActiveFleet, err
	default:
		return "", 0, "", ErrHostCommandFailed
	}
}

// ExpectedOperation derives the sole operation identity and terminal fence
// state accepted by both the control-side command and the target-side
// production handler. Callers cannot supply or override any derived field.
func ExpectedOperation(
	action HostAction,
	target TargetProof,
	manifestDigest string,
	revision string,
) (string, uint64, fleetfence.Fleet, error) {
	return expectedOperation(action, target, manifestDigest, revision)
}

func targetProofPreimageOf(proof TargetProof) targetProofPreimage {
	return targetProofPreimage{
		SchemaVersion:          proof.SchemaVersion,
		PrivateOverlayRevision: proof.PrivateOverlayRevision,
		HostIdentityDigest:     proof.HostIdentityDigest,
		ControlIdentityDigest:  proof.ControlIdentityDigest,
		OS:                     proof.OS,
		Architecture:           proof.Architecture,
		ExpectedEUID:           proof.ExpectedEUID,
		FenceGeneration:        proof.FenceGeneration,
		ActiveFleet:            proof.ActiveFleet,
		CurrentManifestDigest:  proof.CurrentManifestDigest,
		InstallDisposition:     proof.InstallDisposition,
	}
}

func (action HostAction) String() string {
	switch action {
	case ActionInstall:
		return "deploy"
	case ActionVerify:
		return "verify"
	case ActionSuspend:
		return "suspend"
	case ActionResume:
		return "resume"
	case ActionRollback:
		return "rollback"
	case ActionUninstall:
		return "uninstall"
	default:
		return ""
	}
}

func readBoundedFile(path string, maxBytes int) ([]byte, error) {
	if !canonicalHostPath(path) || maxBytes <= 0 {
		return nil, ErrHostCommandFailed
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrHostCommandFailed
	}
	defer file.Close()
	document, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)+1))
	if err != nil || len(document) == 0 || len(document) > maxBytes {
		return nil, ErrHostCommandFailed
	}
	return document, nil
}

func validLoadedOverlayIdentity(overlay hostruntime.PrivateOverlay) bool {
	return overlay.Target.OS == "linux" &&
		overlay.Target.Architecture == "amd64" &&
		overlay.Target.ExpectedEUID == 0 &&
		validLowerDigest(overlay.Target.HostIdentityDigest) &&
		validLowerDigest(overlay.Target.ControlHostIdentityDigest) &&
		overlay.Target.HostIdentityDigest !=
			overlay.Target.ControlHostIdentityDigest &&
		canonicalHostPath(overlay.Manifest.Path) &&
		validLowerDigest(overlay.Manifest.Digest)
}

func canonicalHostPath(path string) bool {
	return filepath.IsAbs(path) &&
		filepath.Clean(path) == path &&
		!strings.ContainsRune(path, 0)
}

func validFleet(fleet fleetfence.Fleet) bool {
	return fleet == fleetfence.FleetNone ||
		fleet == fleetfence.FleetPortable ||
		fleet == fleetfence.FleetLegacy
}

func validLowerDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil &&
		len(decoded) == sha256.Size &&
		value == strings.ToLower(value)
}

func artifactDigest(domain string, document []byte) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(domain))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write(document)
	return hex.EncodeToString(hasher.Sum(nil))
}
