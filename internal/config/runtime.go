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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/sumitake/portable-ghar/internal/redaction"
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
	if dec.More() {
		return Runtime{}, errors.New("config: runtime document contains trailing data")
	}

	if err := rt.validate(); err != nil {
		return Runtime{}, err
	}
	return rt, nil
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
