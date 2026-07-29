// Package config loads and validates the controller runtime configuration.
//
// Scope for this package as of Task 1 is deliberately narrow: LoadRuntime
// decodes and validates the egress-backend and IP-family selection (plus
// where to read the runtime's bootstrap secret from), and ReadSecret reads
// a referenced secret source into a redaction.Secret. Probes, address
// ranges, and the full profile-aware blocked-address/policy decision graph
// are out of scope here and land in a later task.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"time"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/redaction"
	"github.com/sumitake/portable-ghar/internal/state"
)

// EgressBackend enumerates the controller's egress backends. Only
// EgressBackendRestrictedBrokerV1 is currently available;
// EgressBackendNFTablesDirectV1 is defined but rejected by LoadRuntime
// until it has exact pre-conntrack qualification (see
// internal/buildinfo.Pins for the same availability decision recorded at
// the dependency-pin level).
type EgressBackend string

const (
	EgressBackendRestrictedBrokerV1 EgressBackend = "restricted-broker-v1"
	EgressBackendNFTablesDirectV1   EgressBackend = "nftables-direct-v1"
)

// IPFamily enumerates the supported public IP address families for
// controller-managed egress.
type IPFamily string

const (
	IPFamilyPublicIPv4Only  IPFamily = "public_ipv4_only"
	IPFamilyPublicDualStack IPFamily = "public_dual_stack"
)

// SecretRef identifies where to read a piece of secret material from. It
// never carries the secret value itself -- only a source kind and a
// reference into that source (e.g. a file path). Runtime documents may
// only reference secrets this way; an inline literal in a secret's place
// is a decode error (see LoadRuntime), and an unrecognized Source is a
// validation error (see Runtime.validate) -- otherwise a literal secret
// could be smuggled through under a bogus source label.
type SecretRef struct {
	// Source names where to read the secret from. Task 1 supports "file"
	// (Ref is a filesystem path) and "env" (Ref is an environment variable
	// name). Must be one of secretSourceAllowlist.
	Source string `json:"source"`
	Ref    string `json:"ref"`
}

// ControllerRuntime is the production-only private runtime overlay. Its wire
// representation is exactly hostruntime.PrivateOverlay; the wrapper keeps the
// canonical revision alongside the decoded object without adding a second
// looser schema.
type ControllerRuntime struct {
	overlay  hostruntime.PrivateOverlay
	revision string
}

func (runtime *ControllerRuntime) UnmarshalJSON(data []byte) error {
	if runtime == nil {
		return errors.New("config: controller runtime is nil")
	}
	overlay, revision, err := hostruntime.ParsePrivateOverlay(data, len(data))
	if err != nil {
		return errors.New("config: controller runtime is invalid")
	}
	runtime.overlay = overlay
	runtime.revision = revision
	return nil
}

func (runtime ControllerRuntime) MarshalJSON() ([]byte, error) {
	document, _, err := hostruntime.MarshalPrivateOverlay(runtime.overlay)
	if err != nil || runtime.revision == "" {
		return nil, errors.New("config: controller runtime is invalid")
	}
	return document, nil
}

// HistoryRuntime is the operator-authored, no-default wire representation of
// state.HistoryLimits. Durations are explicit Go-duration strings rather than
// implicit nanosecond integers.
type HistoryRuntime struct {
	MinRetention                 time.Duration
	MaxHistoryRows               uint64
	MaxHistoryLogicalBytes       uint64
	MaxNetworkLedgerRows         uint64
	MaxNetworkLedgerLogicalBytes uint64
	InflightReserveRows          uint64
	InflightReserveLogicalBytes  uint64
	GCBatchRows                  uint64
	NetworkGCBatchRows           uint64
	VacuumBatchPages             uint64
	MaintenanceCadence           time.Duration
}

// UnmarshalJSON strictly decodes every HistoryLimits field. Unknown nested
// fields are rejected here because implementing json.Unmarshaler otherwise
// bypasses the outer decoder's DisallowUnknownFields behavior for this object.
func (h *HistoryRuntime) UnmarshalJSON(data []byte) error {
	if h == nil || bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return errors.New("config: history must be an object")
	}
	var document struct {
		MinRetention                 string `json:"min_retention"`
		MaxHistoryRows               uint64 `json:"max_history_rows"`
		MaxHistoryLogicalBytes       uint64 `json:"max_history_logical_bytes"`
		MaxNetworkLedgerRows         uint64 `json:"max_network_ledger_rows"`
		MaxNetworkLedgerLogicalBytes uint64 `json:"max_network_ledger_logical_bytes"`
		InflightReserveRows          uint64 `json:"inflight_reserve_rows"`
		InflightReserveLogicalBytes  uint64 `json:"inflight_reserve_logical_bytes"`
		GCBatchRows                  uint64 `json:"gc_batch_rows"`
		NetworkGCBatchRows           uint64 `json:"network_gc_batch_rows"`
		VacuumBatchPages             uint64 `json:"vacuum_batch_pages"`
		MaintenanceCadence           string `json:"maintenance_cadence"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&document); err != nil {
		return fmt.Errorf("config: decode history: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("config: history contains trailing data")
		}
		return fmt.Errorf("config: decode history trailing data: %w", err)
	}
	minRetention, err := time.ParseDuration(document.MinRetention)
	if err != nil {
		return errors.New("config: invalid history min_retention")
	}
	maintenanceCadence, err := time.ParseDuration(document.MaintenanceCadence)
	if err != nil {
		return errors.New("config: invalid history maintenance_cadence")
	}
	*h = HistoryRuntime{
		MinRetention:                 minRetention,
		MaxHistoryRows:               document.MaxHistoryRows,
		MaxHistoryLogicalBytes:       document.MaxHistoryLogicalBytes,
		MaxNetworkLedgerRows:         document.MaxNetworkLedgerRows,
		MaxNetworkLedgerLogicalBytes: document.MaxNetworkLedgerLogicalBytes,
		InflightReserveRows:          document.InflightReserveRows,
		InflightReserveLogicalBytes:  document.InflightReserveLogicalBytes,
		GCBatchRows:                  document.GCBatchRows,
		NetworkGCBatchRows:           document.NetworkGCBatchRows,
		VacuumBatchPages:             document.VacuumBatchPages,
		MaintenanceCadence:           maintenanceCadence,
	}
	return nil
}

func (h HistoryRuntime) limits() state.HistoryLimits {
	return state.HistoryLimits{
		MinRetention:                 h.MinRetention,
		MaxHistoryRows:               h.MaxHistoryRows,
		MaxHistoryLogicalBytes:       h.MaxHistoryLogicalBytes,
		MaxNetworkLedgerRows:         h.MaxNetworkLedgerRows,
		MaxNetworkLedgerLogicalBytes: h.MaxNetworkLedgerLogicalBytes,
		InflightReserveRows:          h.InflightReserveRows,
		InflightReserveLogicalBytes:  h.InflightReserveLogicalBytes,
		GCBatchRows:                  h.GCBatchRows,
		NetworkGCBatchRows:           h.NetworkGCBatchRows,
		VacuumBatchPages:             h.VacuumBatchPages,
		MaintenanceCadence:           h.MaintenanceCadence,
	}
}

// secretSourceAllowlist is the exact set of SecretRef.Source values Task 1
// recognizes. Runtime.validate and ReadSecret share this single set so
// they can never drift apart -- a source Runtime.validate accepts but
// ReadSecret doesn't recognize (or vice versa) would either reject valid
// configs or let an unvalidated source reach ReadSecret's default case.
var secretSourceAllowlist = map[string]bool{
	"file": true,
	"env":  true,
}

// Runtime is the controller's runtime configuration, strictly decoded and
// validated by LoadRuntime.
type Runtime struct {
	// EgressBackend selects the egress backend the controller uses.
	EgressBackend EgressBackend `json:"egress_backend"`

	// IPFamily selects which public IP address families controller-managed
	// egress may use.
	IPFamily IPFamily `json:"ip_family"`

	// Secret references where the runtime reads its bootstrap credential
	// from. It must be a SecretRef object; an inline secret literal here
	// is rejected at decode time.
	Secret SecretRef `json:"secret"`

	// The following fields are required by LoadControllerRuntime. LoadRuntime
	// remains the narrow Task-1/offline parser so older offline tooling can read
	// the transport subset without silently inventing production history
	// defaults.
	FleetConcurrency                 uint64         `json:"fleet_concurrency"`
	NetworkLedgerReserveRows         uint64         `json:"network_ledger_reserve_rows"`
	NetworkLedgerReserveLogicalBytes uint64         `json:"network_ledger_reserve_logical_bytes"`
	History                          HistoryRuntime `json:"history"`

	// Controller is absent for the narrow transport/offline document and is
	// mandatory for production startup through LoadControllerRuntime.
	Controller *ControllerRuntime `json:"controller,omitempty"`
}

// LoadRuntime decodes and validates a Runtime document from r.
//
// Decoding is strict: json.Decoder.DisallowUnknownFields rejects any
// unrecognized field, at both the top level and within the nested Secret
// object, and a document containing more than one JSON value is rejected.
// Because Secret is typed as SecretRef (an object), providing an inline
// literal (a JSON string) in its place is itself a decode error -- secret
// material can never be embedded directly in a Runtime document.
//
// After decoding, LoadRuntime validates that EgressBackend is a known,
// currently-available backend and that IPFamily is one of the two
// supported families.
func LoadRuntime(r io.Reader) (Runtime, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()

	var rt Runtime
	if err := dec.Decode(&rt); err != nil {
		return Runtime{}, fmt.Errorf("config: decode runtime: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Runtime{}, errors.New("config: runtime document contains trailing data")
		}
		return Runtime{}, fmt.Errorf("config: decode runtime trailing data: %w", err)
	}

	if err := rt.validate(); err != nil {
		return Runtime{}, err
	}
	return rt, nil
}

// LoadControllerRuntime is the production-startup loader. It requires every
// durable-history input and proves the configured concurrency fits the
// full-lifecycle row/byte reserve. NetworkLedgerReserve* is the explicit
// operator-proven aggregate needed for active concurrency plus the protected
// detached tail; no tail or size default is inferred here.
func LoadControllerRuntime(r io.Reader) (Runtime, error) {
	rt, err := LoadRuntime(r)
	if err != nil {
		return Runtime{}, err
	}
	if err := rt.validateControllerHistory(); err != nil {
		return Runtime{}, err
	}
	if err := rt.validateControllerRuntime(); err != nil {
		return Runtime{}, err
	}
	return rt, nil
}

// LoadStatusRuntime validates the durable-history envelope needed by the
// read-only status command without authorizing production startup. It does not
// require the private controller overlay and therefore cannot be used to
// construct a controller process.
func LoadStatusRuntime(r io.Reader) (Runtime, error) {
	rt, err := LoadRuntime(r)
	if err != nil {
		return Runtime{}, err
	}
	if err := rt.validateControllerHistory(); err != nil {
		return Runtime{}, err
	}
	return rt, nil
}

// HistoryLimits returns the already-decoded state envelope. Production callers
// must obtain Runtime through LoadControllerRuntime before using it.
func (rt Runtime) HistoryLimits() state.HistoryLimits {
	return rt.History.limits()
}

// ControllerPrivateOverlay returns an isolated validated copy plus its exact
// canonical revision. The false result distinguishes the offline subset from
// a production runtime.
func (rt Runtime) ControllerPrivateOverlay() (
	hostruntime.PrivateOverlay,
	string,
	bool,
) {
	if rt.Controller == nil {
		return hostruntime.PrivateOverlay{}, "", false
	}
	document, revision, err := hostruntime.MarshalPrivateOverlay(
		rt.Controller.overlay,
	)
	if err != nil || revision != rt.Controller.revision {
		return hostruntime.PrivateOverlay{}, "", false
	}
	overlay, parsedRevision, err := hostruntime.ParsePrivateOverlay(
		document,
		len(document),
	)
	if err != nil || parsedRevision != revision {
		return hostruntime.PrivateOverlay{}, "", false
	}
	return overlay, revision, true
}

func (rt Runtime) validateControllerHistory() error {
	limits := rt.HistoryLimits()
	if err := state.ValidateHistoryLimits(limits); err != nil {
		return fmt.Errorf("config: invalid history limits: %w", err)
	}
	if rt.FleetConcurrency == 0 ||
		rt.NetworkLedgerReserveRows == 0 ||
		rt.NetworkLedgerReserveLogicalBytes == 0 {
		return errors.New("config: controller history sizing is incomplete")
	}
	requiredRows, ok := checkedMultiply(rt.FleetConcurrency, limits.InflightReserveRows)
	if !ok || requiredRows > limits.MaxHistoryRows {
		return errors.New("config: fleet history row reserve exceeds cap")
	}
	requiredBytes, ok := checkedMultiply(
		rt.FleetConcurrency,
		limits.InflightReserveLogicalBytes,
	)
	if !ok || requiredBytes > limits.MaxHistoryLogicalBytes {
		return errors.New("config: fleet history byte reserve exceeds cap")
	}
	if rt.NetworkLedgerReserveRows < rt.FleetConcurrency ||
		rt.NetworkLedgerReserveRows > limits.MaxNetworkLedgerRows {
		return errors.New("config: network ledger row reserve is inconsistent")
	}
	// Every retained ledger row has at least one logical byte by schema. The
	// explicit reserve must cover at least the active fleet and remain within
	// the independently configured ledger cap.
	if rt.NetworkLedgerReserveLogicalBytes < rt.FleetConcurrency ||
		rt.NetworkLedgerReserveLogicalBytes > limits.MaxNetworkLedgerLogicalBytes {
		return errors.New("config: network ledger byte reserve is inconsistent")
	}
	return nil
}

func (rt Runtime) validateControllerRuntime() error {
	overlay, _, ok := rt.ControllerPrivateOverlay()
	if !ok ||
		string(rt.EgressBackend) != overlay.Docker.BrokerNetworkID ||
		rt.FleetConcurrency != overlay.Resources.FleetConcurrency ||
		rt.FleetConcurrency != overlay.Resources.MaxCapacity ||
		rt.NetworkLedgerReserveRows !=
			overlay.Resources.NetworkLedgerReserveRows ||
		rt.NetworkLedgerReserveLogicalBytes !=
			overlay.Resources.NetworkLedgerReserveBytes ||
		!controllerHistoryMatchesOverlay(rt.History, overlay.Resources.History) ||
		!controllerSecretMatchesOverlay(rt.Secret, overlay.Secrets) {
		return errors.New("config: controller runtime binding is inconsistent")
	}
	return nil
}

func controllerHistoryMatchesOverlay(
	history HistoryRuntime,
	overlay hostruntime.HistoryOverlay,
) bool {
	minRetention, minErr := time.ParseDuration(overlay.MinRetention)
	maintenance, maintenanceErr := time.ParseDuration(
		overlay.MaintenanceCadence,
	)
	return minErr == nil &&
		maintenanceErr == nil &&
		history.MinRetention == minRetention &&
		history.MaxHistoryRows == overlay.MaxHistoryRows &&
		history.MaxHistoryLogicalBytes == overlay.MaxHistoryLogicalBytes &&
		history.MaxNetworkLedgerRows == overlay.MaxNetworkLedgerRows &&
		history.MaxNetworkLedgerLogicalBytes ==
			overlay.MaxNetworkLedgerLogicalBytes &&
		history.InflightReserveRows == overlay.InflightReserveRows &&
		history.InflightReserveLogicalBytes ==
			overlay.InflightReserveLogicalBytes &&
		history.GCBatchRows == overlay.GCBatchRows &&
		history.NetworkGCBatchRows == overlay.NetworkGCBatchRows &&
		history.VacuumBatchPages == overlay.VacuumBatchPages &&
		history.MaintenanceCadence == maintenance
}

func controllerSecretMatchesOverlay(
	secret SecretRef,
	overlay []hostruntime.NamedSecretRef,
) bool {
	if secret.Ref == "" {
		return false
	}
	for _, candidate := range overlay {
		if candidate.Ref.Source == secret.Source &&
			candidate.Ref.Ref == secret.Ref {
			return true
		}
	}
	return false
}

func checkedMultiply(left, right uint64) (uint64, bool) {
	if left != 0 && right > math.MaxUint64/left {
		return 0, false
	}
	return left * right, true
}

func (rt Runtime) validate() error {
	switch rt.EgressBackend {
	case EgressBackendRestrictedBrokerV1:
		// available
	case EgressBackendNFTablesDirectV1:
		return fmt.Errorf("config: egress backend %q is defined but not yet available (pending exact pre-conntrack qualification)", rt.EgressBackend)
	default:
		return fmt.Errorf("config: unknown egress backend %q", rt.EgressBackend)
	}

	switch rt.IPFamily {
	case IPFamilyPublicIPv4Only, IPFamilyPublicDualStack:
		// ok
	default:
		return fmt.Errorf("config: unknown ip family %q", rt.IPFamily)
	}

	if !secretSourceAllowlist[rt.Secret.Source] {
		return fmt.Errorf("config: unsupported secret source %q", rt.Secret.Source)
	}

	return nil
}

// ReadSecret reads the secret material identified by ref and returns it as
// an owned, non-copyable redaction.Secret. Supported sources are "file"
// (Ref is a filesystem path) and "env" (Ref is an environment variable
// name); any other source is rejected (see secretSourceAllowlist, shared
// with Runtime.validate).
//
// Callers must not log a raw filesystem path even so: ReadSecret itself
// never includes ref.Ref in a returned error, but a caller that logs
// ref.Ref directly (e.g. alongside a "read secret failed" event) would
// reintroduce the same path leak this function avoids.
func ReadSecret(ref SecretRef) (*redaction.Secret, error) {
	if !secretSourceAllowlist[ref.Source] {
		return nil, fmt.Errorf("config: unsupported secret source %q", ref.Source)
	}

	switch ref.Source {
	case "file":
		b, err := os.ReadFile(ref.Ref)
		if err != nil {
			// Identify the failure by source kind and error class only --
			// os.ReadFile's error (%w or %v) embeds the raw path in its
			// string, and paths must never reach logs.
			return nil, fmt.Errorf("config: read secret from file source: %w", unwrapPathError(err))
		}
		// SecretFromBytes copies b and best-effort zeroes it in place, so
		// no further zeroing is needed here.
		return redaction.SecretFromBytes(b), nil
	case "env":
		v, ok := os.LookupEnv(ref.Ref)
		if !ok {
			return nil, fmt.Errorf("config: read secret from env: variable %q is not set", ref.Ref)
		}
		s := redaction.SecretFromBytes([]byte(v))
		return s, nil
	default:
		return nil, fmt.Errorf("config: unsupported secret source %q", ref.Source)
	}
}

// unwrapPathError reduces a filesystem error to its underlying error class
// (e.g. "no such file or directory", "permission denied"), stripping any
// *fs.PathError wrapping that would otherwise carry the raw path in its
// Error() string.
func unwrapPathError(err error) error {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err
	}
	return err
}
