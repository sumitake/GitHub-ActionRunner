package redaction

import (
	"encoding/json"
	"fmt"
	"io"
)

// allowedLogKeys is the fixed allowlist Logger.Event accepts. It exists to
// keep operationally useful, non-sensitive fleet/acquisition/health state
// out of band from anything job-controlled or otherwise sensitive: raw
// eligible scale-set names, job names, repository coordinates, request
// bodies, JIT material, tokens, secret refs, filesystem paths, routes, and
// command output are all deliberately excluded and therefore rejected by
// Event rather than silently dropped.
var allowedLogKeys = map[string]struct{}{
	"fleet_alias":                        {},
	"acquisition_state":                  {},
	"acquisition_mode":                   {},
	"acquisition_policy_epoch":           {},
	"policy_sha256":                      {},
	"capacity_summary":                   {},
	"assigned_count":                     {},
	"assigned_age":                       {},
	"unassigned_released_listener_count": {},
	"terminal_time":                      {},
	"profile":                            {},
	"degraded":                           {},
	"build_id":                           {},
}

// Logger emits structured events restricted to an explicit key allowlist.
// The zero value is usable: with Writer nil, validated events are simply
// not written anywhere (still returning nil on success), which lets
// callers unit test the allowlist without wiring an output sink.
type Logger struct {
	// Writer, if set, receives one JSON object per successfully validated
	// Event call. If nil, valid events are accepted but not written.
	Writer io.Writer
}

// event is the on-the-wire shape written to Writer for a validated event.
type event struct {
	Name   string         `json:"name"`
	Fields map[string]any `json:"fields,omitempty"`
}

// Event validates fields against the fixed allowlist. Any key not on the
// allowlist -- including every job-controlled field explicitly named in
// the package doc -- causes Event to return an error and write nothing;
// it never silently drops the offending key and logs the rest.
func (l Logger) Event(name string, fields map[string]any) error {
	for k := range fields {
		if _, ok := allowedLogKeys[k]; !ok {
			return fmt.Errorf("redaction: log field %q is not allowlisted", k)
		}
	}

	if l.Writer == nil {
		return nil
	}

	enc := json.NewEncoder(l.Writer)
	return enc.Encode(event{Name: name, Fields: fields})
}
