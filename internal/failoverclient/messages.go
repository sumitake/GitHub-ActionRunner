package failoverclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

var ErrProtocolMessage = errors.New("failoverclient: protocol message")

type Holder string

const (
	HeartbeatHolderPortable Holder = "portable"
	HeartbeatHolderLegacy   Holder = "legacy"
	HolderNone              Holder = "none"
)

type SessionRequestV1 struct {
	ProtocolVersion int    `json:"protocolVersion"`
	FleetID         string `json:"fleetId"`
	Nonce           string `json:"nonce"`
	Timestamp       string `json:"timestamp"`
	BuildID         string `json:"buildId"`
}

type SessionResponseV1 struct {
	ProtocolVersion int    `json:"protocolVersion"`
	FleetID         string `json:"fleetId"`
	Nonce           string `json:"nonce"`
	Epoch           uint64 `json:"epoch"`
	SessionID       string `json:"sessionId"`
	Sequence        uint64 `json:"sequence"`
	LeaseGeneration uint64 `json:"leaseGeneration"`
	LeaseNotBefore  string `json:"leaseNotBefore"`
	ReceiptTime     string `json:"receiptTime"`
}

type AcquisitionMode string

const (
	AcquisitionModeDisabled   AcquisitionMode = "disabled"
	AcquisitionModeCanaryOnly AcquisitionMode = "canary-only"
	AcquisitionModeEnabled    AcquisitionMode = "enabled"
	AcquisitionModeFatal      AcquisitionMode = "fatal"
)

type HostProfileID string

const (
	HostProfileStrictLinuxV1  HostProfileID = "strict-linux-v1"
	HostProfileQTSCaplessRoot HostProfileID = "qts-capless-root"
)

type HeartbeatCapacityV1 struct {
	Configured uint64 `json:"configured"`
	Effective  uint64 `json:"effective"`
	Occupied   uint64 `json:"occupied"`
	Available  uint64 `json:"available"`
	Queued     uint64 `json:"queued"`
}

type HeartbeatSnapshotV1 struct {
	ObservedAt                  string              `json:"observedAt"`
	FleetAlias                  string              `json:"fleetAlias"`
	AcquisitionMode             AcquisitionMode     `json:"acquisitionMode"`
	PolicyEpoch                 uint64              `json:"policyEpoch"`
	PolicyDigest                string              `json:"policyDigest"`
	RepositoryPolicyRevision    uint64              `json:"repositoryPolicyRevision"`
	Capacity                    HeartbeatCapacityV1 `json:"capacity"`
	AssignedJobs                uint64              `json:"assignedJobs"`
	RunningJobs                 uint64              `json:"runningJobs"`
	OldestLiveAssignmentAgeMs   uint64              `json:"oldestLiveAssignmentAgeMs"`
	UnassignedReleasedListeners uint64              `json:"unassignedReleasedListeners"`
	LastTerminalAt              *string             `json:"lastTerminalAt"`
	HostProfileID               HostProfileID       `json:"hostProfileId"`
	Degraded                    bool                `json:"degraded"`
	BuildID                     string              `json:"buildId"`
}

type HeartbeatRequestV1 struct {
	ProtocolVersion int                 `json:"protocolVersion"`
	FleetID         string              `json:"fleetId"`
	Epoch           uint64              `json:"epoch"`
	SessionID       string              `json:"sessionId"`
	Sequence        uint64              `json:"sequence"`
	Holder          Holder              `json:"holder"`
	FenceGeneration uint64              `json:"fenceGeneration"`
	Snapshot        HeartbeatSnapshotV1 `json:"snapshot"`
	Timestamp       string              `json:"timestamp"`
}

type RoutingState string

const (
	RoutingHosted           RoutingState = "HOSTED"
	RoutingDrainingToHosted RoutingState = "DRAINING_TO_HOSTED"
	RoutingPortableCanary   RoutingState = "PORTABLE_CANARY"
	RoutingPortable         RoutingState = "PORTABLE"
	RoutingLegacyCanary     RoutingState = "LEGACY_CANARY"
	RoutingLegacy           RoutingState = "LEGACY"
)

type MaintenanceKind string

const (
	MaintenanceNone       MaintenanceKind = "none"
	MaintenanceHostedHold MaintenanceKind = "hosted-hold"
)

type MaintenanceDirectiveV1 struct {
	Kind            MaintenanceKind `json:"kind"`
	SessionID       string          `json:"sessionId"`
	LeaseGeneration uint64          `json:"leaseGeneration"`
}

type NoLeaseReason string

const (
	NoLeasePredecessorDraining NoLeaseReason = "predecessor-lease-draining"
	NoLeaseFleetNotInventoried NoLeaseReason = "fleet-not-inventoried"
	NoLeaseHostedHold          NoLeaseReason = "hosted-hold"
	NoLeaseStaleSelector       NoLeaseReason = "stale-selector-evidence"
	NoLeaseQueueRisk           NoLeaseReason = "queue-risk-open"
	NoLeaseInvalidRequest      NoLeaseReason = "invalid-request"
	NoLeaseClockAnomaly        NoLeaseReason = "clock-anomaly"
	NoLeasePolicyMismatch      NoLeaseReason = "policy-mismatch"
	NoLeaseCapacityZero        NoLeaseReason = "capacity-zero"
	NoLeaseRoutingHosted       NoLeaseReason = "routing-hosted"
	NoLeaseDisabled            NoLeaseReason = "lease-disabled"
)

type HeartbeatResponseV1 struct {
	ProtocolVersion int                    `json:"protocolVersion"`
	FleetID         string                 `json:"fleetId"`
	SessionID       string                 `json:"sessionId"`
	Sequence        uint64                 `json:"sequence"`
	ReceiptTime     string                 `json:"receiptTime"`
	RoutingState    RoutingState           `json:"routingState"`
	Maintenance     MaintenanceDirectiveV1 `json:"maintenance"`
	Lease           *AcquisitionLeaseV1    `json:"lease"`
	NoLeaseReason   *NoLeaseReason         `json:"noLeaseReason"`
}

var (
	sessionRequestFields = []string{
		"buildId", "fleetId", "nonce", "protocolVersion", "timestamp",
	}
	sessionResponseFields = []string{
		"epoch", "fleetId", "leaseGeneration", "leaseNotBefore", "nonce",
		"protocolVersion", "receiptTime", "sequence", "sessionId",
	}
	heartbeatRequestFields = []string{
		"epoch", "fenceGeneration", "fleetId", "holder", "protocolVersion",
		"sequence", "sessionId", "snapshot", "timestamp",
	}
	heartbeatSnapshotFields = []string{
		"acquisitionMode", "assignedJobs", "buildId", "capacity", "degraded",
		"fleetAlias", "hostProfileId", "lastTerminalAt", "observedAt",
		"oldestLiveAssignmentAgeMs", "policyDigest", "policyEpoch",
		"repositoryPolicyRevision", "runningJobs", "unassignedReleasedListeners",
	}
	heartbeatCapacityFields = []string{
		"available", "configured", "effective", "occupied", "queued",
	}
	heartbeatResponseFields = []string{
		"fleetId", "lease", "maintenance", "noLeaseReason", "protocolVersion",
		"receiptTime", "routingState", "sequence", "sessionId",
	}
	maintenanceFields = []string{"kind", "leaseGeneration", "sessionId"}
	leaseFields       = []string{
		"archivedDisabledAliases", "canaryScaleSet", "durationMs", "expiry",
		"fleetId", "holder", "leaseGeneration", "localPolicyEpoch", "maxCapacity",
		"mode", "policyDigest", "protocolVersion", "repositoryPolicyRevision",
		"serverEpoch", "sessionId",
	}
)

func ParseSessionRequestV1(raw []byte) (SessionRequestV1, error) {
	var request SessionRequestV1
	if _, err := decodeExactMessage(raw, sessionRequestFields, &request); err != nil {
		return SessionRequestV1{}, err
	}
	if request.ProtocolVersion != 1 ||
		!fleetIDPattern.MatchString(request.FleetID) ||
		!hex64Pattern.MatchString(request.Nonce) ||
		!hex64Pattern.MatchString(request.BuildID) {
		return SessionRequestV1{}, messageError("session request identity")
	}
	if _, err := parseProtocolTimestamp(request.Timestamp); err != nil {
		return SessionRequestV1{}, messageError("session request timestamp")
	}
	return request, nil
}

func ParseSessionResponseV1(raw []byte) (SessionResponseV1, error) {
	var response SessionResponseV1
	if _, err := decodeExactMessage(raw, sessionResponseFields, &response); err != nil {
		return SessionResponseV1{}, err
	}
	if response.ProtocolVersion != 1 ||
		!fleetIDPattern.MatchString(response.FleetID) ||
		!hex64Pattern.MatchString(response.Nonce) ||
		!hex64Pattern.MatchString(response.SessionID) ||
		response.SessionID == response.Nonce ||
		response.Epoch == 0 || response.Epoch > maxJavaScriptSafeInteger ||
		response.Sequence != 0 ||
		response.LeaseGeneration == 0 || response.LeaseGeneration > maxJavaScriptSafeInteger {
		return SessionResponseV1{}, messageError("session response identity")
	}
	receipt, err := parseProtocolTimestamp(response.ReceiptTime)
	if err != nil {
		return SessionResponseV1{}, messageError("session response receipt")
	}
	notBefore, err := parseProtocolTimestamp(response.LeaseNotBefore)
	if err != nil || notBefore.Before(receipt) {
		return SessionResponseV1{}, messageError("session response lease boundary")
	}
	return response, nil
}

func ParseHeartbeatRequestV1(raw []byte) (HeartbeatRequestV1, error) {
	var request HeartbeatRequestV1
	record, err := decodeExactMessage(
		raw,
		heartbeatRequestFields,
		&request,
		"snapshot.lastTerminalAt",
	)
	if err != nil {
		return HeartbeatRequestV1{}, err
	}
	snapshotRecord, err := exactNestedRecord(record, "snapshot", heartbeatSnapshotFields)
	if err != nil {
		return HeartbeatRequestV1{}, err
	}
	if _, err := exactNestedRecord(snapshotRecord, "capacity", heartbeatCapacityFields); err != nil {
		return HeartbeatRequestV1{}, err
	}
	if request.ProtocolVersion != 1 ||
		!fleetIDPattern.MatchString(request.FleetID) ||
		!hex64Pattern.MatchString(request.SessionID) ||
		request.Epoch > maxJavaScriptSafeInteger ||
		request.Sequence > maxJavaScriptSafeInteger ||
		request.FenceGeneration > maxJavaScriptSafeInteger ||
		!validHolder(request.Holder) {
		return HeartbeatRequestV1{}, messageError("heartbeat request identity")
	}
	if _, err := parseProtocolTimestamp(request.Timestamp); err != nil {
		return HeartbeatRequestV1{}, messageError("heartbeat request timestamp")
	}
	if err := validateHeartbeatSnapshot(request.FleetID, request.Snapshot); err != nil {
		return HeartbeatRequestV1{}, err
	}
	return request, nil
}

func ParseHeartbeatResponseV1(raw []byte) (HeartbeatResponseV1, error) {
	var response HeartbeatResponseV1
	record, err := decodeExactMessage(
		raw,
		heartbeatResponseFields,
		&response,
		"lease",
		"lease.canaryScaleSet",
		"noLeaseReason",
	)
	if err != nil {
		return HeartbeatResponseV1{}, err
	}
	if _, err := exactNestedRecord(record, "maintenance", maintenanceFields); err != nil {
		return HeartbeatResponseV1{}, err
	}
	if response.Lease != nil {
		if _, err := exactNestedRecord(record, "lease", leaseFields); err != nil {
			return HeartbeatResponseV1{}, err
		}
	}
	if response.ProtocolVersion != 1 ||
		!fleetIDPattern.MatchString(response.FleetID) ||
		!hex64Pattern.MatchString(response.SessionID) ||
		response.Sequence > maxJavaScriptSafeInteger ||
		!validRoutingState(response.RoutingState) ||
		!validMaintenanceKind(response.Maintenance.Kind) ||
		!hex64Pattern.MatchString(response.Maintenance.SessionID) ||
		response.Maintenance.LeaseGeneration == 0 ||
		response.Maintenance.LeaseGeneration > maxJavaScriptSafeInteger ||
		response.Maintenance.SessionID != response.SessionID {
		return HeartbeatResponseV1{}, messageError("heartbeat response identity")
	}
	if _, err := parseProtocolTimestamp(response.ReceiptTime); err != nil {
		return HeartbeatResponseV1{}, messageError("heartbeat response receipt")
	}
	if (response.Lease == nil) == (response.NoLeaseReason == nil) ||
		(response.Maintenance.Kind == MaintenanceHostedHold && response.Lease != nil) {
		return HeartbeatResponseV1{}, messageError("heartbeat response authority")
	}
	if response.NoLeaseReason != nil && !validNoLeaseReason(*response.NoLeaseReason) {
		return HeartbeatResponseV1{}, messageError("heartbeat no-lease reason")
	}
	if response.Lease != nil {
		if err := response.Lease.validate(); err != nil {
			return HeartbeatResponseV1{}, err
		}
		if response.Lease.FleetID != response.FleetID ||
			response.Lease.SessionID != response.SessionID ||
			response.Lease.LeaseGeneration != response.Maintenance.LeaseGeneration {
			return HeartbeatResponseV1{}, messageError("heartbeat lease binding")
		}
		if err := validateHeartbeatLeaseEnvelope(response); err != nil {
			return HeartbeatResponseV1{}, err
		}
	}
	return response, nil
}

func validateHeartbeatLeaseEnvelope(response HeartbeatResponseV1) error {
	lease := response.Lease
	if lease == nil {
		return nil
	}
	receipt, err := parseProtocolTimestamp(response.ReceiptTime)
	if err != nil {
		return messageError("heartbeat lease receipt")
	}
	expiry, err := parseProtocolTimestamp(lease.Expiry)
	if err != nil || !receipt.Add(time.Duration(lease.DurationMs)*time.Millisecond).Equal(expiry) {
		return messageError("heartbeat lease expiry")
	}
	switch response.RoutingState {
	case RoutingPortableCanary:
		if lease.Holder != HolderPortable || lease.Mode != LeaseCanaryOnly {
			return messageError("heartbeat lease routing")
		}
	case RoutingPortable:
		if lease.Holder != HolderPortable || lease.Mode != LeaseEnabled || lease.CanaryScaleSet != nil {
			return messageError("heartbeat lease routing")
		}
	case RoutingLegacyCanary:
		if lease.Holder != HolderLegacy || lease.Mode != LeaseCanaryOnly {
			return messageError("heartbeat lease routing")
		}
	case RoutingLegacy:
		if lease.Holder != HolderLegacy || lease.Mode != LeaseEnabled || lease.CanaryScaleSet != nil {
			return messageError("heartbeat lease routing")
		}
	case RoutingHosted, RoutingDrainingToHosted:
		return messageError("hosted routing cannot carry a lease")
	default:
		return messageError("heartbeat lease routing")
	}
	return nil
}

func validateHeartbeatSnapshot(fleetID string, snapshot HeartbeatSnapshotV1) error {
	if snapshot.FleetAlias != fleetID ||
		!fleetIDPattern.MatchString(snapshot.FleetAlias) ||
		!validAcquisitionMode(snapshot.AcquisitionMode) ||
		snapshot.PolicyEpoch == 0 || snapshot.PolicyEpoch > maxJavaScriptSafeInteger ||
		!hex64Pattern.MatchString(snapshot.PolicyDigest) ||
		snapshot.RepositoryPolicyRevision == 0 || snapshot.RepositoryPolicyRevision > maxJavaScriptSafeInteger ||
		!validHostProfileID(snapshot.HostProfileID) ||
		!hex64Pattern.MatchString(snapshot.BuildID) ||
		!heartbeatSnapshotIntegersSafe(snapshot) {
		return messageError("heartbeat snapshot identity")
	}
	observed, err := parseProtocolTimestamp(snapshot.ObservedAt)
	if err != nil {
		return messageError("heartbeat snapshot observed time")
	}
	if snapshot.LastTerminalAt != nil {
		terminal, err := parseProtocolTimestamp(*snapshot.LastTerminalAt)
		if err != nil || terminal.After(observed) {
			return messageError("heartbeat snapshot terminal time")
		}
	}
	expectedAvailable := uint64(0)
	if snapshot.Capacity.Effective > snapshot.Capacity.Occupied {
		expectedAvailable = snapshot.Capacity.Effective - snapshot.Capacity.Occupied
	}
	if snapshot.Capacity.Effective > snapshot.Capacity.Configured ||
		snapshot.Capacity.Occupied > snapshot.Capacity.Configured ||
		snapshot.Capacity.Available > snapshot.Capacity.Effective ||
		snapshot.Capacity.Available != expectedAvailable ||
		snapshot.RunningJobs > snapshot.AssignedJobs {
		return messageError("heartbeat snapshot consistency")
	}
	return nil
}

func heartbeatSnapshotIntegersSafe(snapshot HeartbeatSnapshotV1) bool {
	values := []uint64{
		snapshot.Capacity.Configured,
		snapshot.Capacity.Effective,
		snapshot.Capacity.Occupied,
		snapshot.Capacity.Available,
		snapshot.Capacity.Queued,
		snapshot.AssignedJobs,
		snapshot.RunningJobs,
		snapshot.OldestLiveAssignmentAgeMs,
		snapshot.UnassignedReleasedListeners,
	}
	for _, value := range values {
		if value > maxJavaScriptSafeInteger {
			return false
		}
	}
	return true
}

func decodeExactMessage(
	raw []byte,
	fields []string,
	target any,
	allowedNullPaths ...string,
) (map[string]any, error) {
	parsed, err := ParseCanonicalJSON(raw)
	if err != nil {
		return nil, err
	}
	record, ok := parsed.(map[string]any)
	if !ok || !hasExactFields(record, fields) {
		return nil, messageError("fields")
	}
	allowed := make(map[string]struct{}, len(allowedNullPaths))
	for _, path := range allowedNullPaths {
		allowed[path] = struct{}{}
	}
	if err := rejectUnexpectedNull(record, "", allowed); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return nil, messageError("decode")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, messageError("trailing")
	}
	return record, nil
}

func rejectUnexpectedNull(value any, path string, allowed map[string]struct{}) error {
	switch typed := value.(type) {
	case nil:
		if _, ok := allowed[path]; !ok {
			return messageError("null " + path)
		}
	case map[string]any:
		for key, item := range typed {
			next := key
			if path != "" {
				next = path + "." + key
			}
			if err := rejectUnexpectedNull(item, next, allowed); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range typed {
			if err := rejectUnexpectedNull(item, path+"[]", allowed); err != nil {
				return err
			}
		}
	}
	return nil
}

func exactNestedRecord(parent map[string]any, field string, fields []string) (map[string]any, error) {
	record, ok := parent[field].(map[string]any)
	if !ok || !hasExactFields(record, fields) {
		return nil, messageError(field + " fields")
	}
	return record, nil
}

func hasExactFields(record map[string]any, fields []string) bool {
	if len(record) != len(fields) {
		return false
	}
	for _, field := range fields {
		if _, ok := record[field]; !ok {
			return false
		}
	}
	return true
}

func validHolder(value Holder) bool {
	return value == HeartbeatHolderPortable || value == HeartbeatHolderLegacy || value == HolderNone
}

func validAcquisitionMode(value AcquisitionMode) bool {
	return value == AcquisitionModeDisabled || value == AcquisitionModeCanaryOnly ||
		value == AcquisitionModeEnabled || value == AcquisitionModeFatal
}

func validHostProfileID(value HostProfileID) bool {
	return value == HostProfileStrictLinuxV1 || value == HostProfileQTSCaplessRoot
}

func validRoutingState(value RoutingState) bool {
	return value == RoutingHosted || value == RoutingDrainingToHosted ||
		value == RoutingPortableCanary || value == RoutingPortable ||
		value == RoutingLegacyCanary || value == RoutingLegacy
}

func validMaintenanceKind(value MaintenanceKind) bool {
	return value == MaintenanceNone || value == MaintenanceHostedHold
}

func validNoLeaseReason(value NoLeaseReason) bool {
	switch value {
	case NoLeasePredecessorDraining,
		NoLeaseFleetNotInventoried,
		NoLeaseHostedHold,
		NoLeaseStaleSelector,
		NoLeaseQueueRisk,
		NoLeaseInvalidRequest,
		NoLeaseClockAnomaly,
		NoLeasePolicyMismatch,
		NoLeaseCapacityZero,
		NoLeaseRoutingHosted,
		NoLeaseDisabled:
		return true
	default:
		return false
	}
}

func messageError(detail string) error {
	return fmt.Errorf("%w: %s", ErrProtocolMessage, detail)
}
