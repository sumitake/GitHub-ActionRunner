package redaction

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

const wantPlaceholder = "[REDACTED]"

// TestSecretStringNeverRevealsBytes proves that String() always returns the
// fixed redacted placeholder, never the owned secret bytes.
func TestSecretStringNeverRevealsBytes(t *testing.T) {
	s := SecretFromBytes([]byte("super-secret-value"))
	defer s.Destroy()

	if got := s.String(); got != wantPlaceholder {
		t.Fatalf("String() = %q, want %q", got, wantPlaceholder)
	}

	if formatted := fmt.Sprintf("%v / %s / %+v", s, s, s); strings.Contains(formatted, "super-secret-value") {
		t.Fatalf("fmt formatting leaked secret bytes: %q", formatted)
	}
}

// TestSecretMarshalJSONNeverRevealsBytes proves that JSON encoding of a
// Secret (directly or embedded in a struct) never reveals the owned bytes.
func TestSecretMarshalJSONNeverRevealsBytes(t *testing.T) {
	s := SecretFromBytes([]byte("super-secret-value"))
	defer s.Destroy()

	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(b), "super-secret-value") {
		t.Fatalf("MarshalJSON leaked secret bytes: %s", b)
	}

	var decoded string
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal placeholder: %v", err)
	}
	if decoded != wantPlaceholder {
		t.Fatalf("marshaled placeholder = %q, want %q", decoded, wantPlaceholder)
	}
}

// TestSecretUseProvidesReaderOnlyDuringCallback proves that the reader
// handed to the Use callback works during the callback, and that retaining
// it past the callback's return yields ErrSecretScopeClosed rather than
// leaking further reads.
func TestSecretUseProvidesReaderOnlyDuringCallback(t *testing.T) {
	s := SecretFromBytes([]byte("scoped-value"))
	defer s.Destroy()

	var retained io.Reader
	err := s.Use(func(r io.Reader) error {
		got, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		if string(got) != "scoped-value" {
			t.Fatalf("Use callback read %q, want %q", got, "scoped-value")
		}
		retained = r
		return nil
	})
	if err != nil {
		t.Fatalf("Use: %v", err)
	}
	if retained == nil {
		t.Fatal("Use callback never ran")
	}

	if _, err := retained.Read(make([]byte, 1)); !errors.Is(err, ErrSecretScopeClosed) {
		t.Fatalf("read on retained reader after Use returned err=%v, want ErrSecretScopeClosed", err)
	}
}

// TestSecretUsePropagatesCallbackError proves Use surfaces the callback's
// own error rather than swallowing it.
func TestSecretUsePropagatesCallbackError(t *testing.T) {
	s := SecretFromBytes([]byte("value"))
	defer s.Destroy()

	sentinel := errors.New("boom")
	err := s.Use(func(io.Reader) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("Use error = %v, want %v", err, sentinel)
	}
}

// TestSecretDestroyIsIdempotentAndClosesScope proves that Destroy can be
// called any number of times without panicking, and that Use after Destroy
// fails closed rather than running the callback.
func TestSecretDestroyIsIdempotentAndClosesScope(t *testing.T) {
	s := SecretFromBytes([]byte("destroy-me"))

	s.Destroy()
	s.Destroy()
	s.Destroy()

	err := s.Use(func(io.Reader) error {
		t.Fatal("Use callback must not run after Destroy")
		return nil
	})
	if !errors.Is(err, ErrSecretScopeClosed) {
		t.Fatalf("Use after Destroy = %v, want ErrSecretScopeClosed", err)
	}

	if got := s.String(); got != wantPlaceholder {
		t.Fatalf("String() after Destroy = %q, want %q", got, wantPlaceholder)
	}
}

// TestSecretReadDuringCallbackAfterDestroyFromAnotherGoroutine proves that a
// reader obtained inside Use also closes if the Secret is destroyed mid
// callback (defense in depth: the scope check consults live Secret state,
// not just its own local flag).
func TestSecretUseAfterDestroyReturnsErrImmediately(t *testing.T) {
	s := SecretFromBytes([]byte("value"))
	s.Destroy()

	called := false
	err := s.Use(func(io.Reader) error {
		called = true
		return nil
	})
	if called {
		t.Fatal("Use callback ran after Destroy")
	}
	if !errors.Is(err, ErrSecretScopeClosed) {
		t.Fatalf("Use after Destroy = %v, want ErrSecretScopeClosed", err)
	}
}

// TestLoggerEventAllowlist proves that Logger.Event accepts the fixed
// allowlisted key set and rejects job-controlled or otherwise
// non-allowlisted keys with an error, never by silently dropping them.
func TestLoggerEventAllowlist(t *testing.T) {
	tests := []struct {
		name    string
		fields  map[string]any
		wantErr bool
	}{
		{
			name: "fully populated allowlisted event",
			fields: map[string]any{
				"fleet_alias":                        "example-fleet",
				"acquisition_state":                  "assigned",
				"acquisition_mode":                   "reserved",
				"acquisition_policy_epoch":           3,
				"policy_sha256":                      strings.Repeat("a", 64),
				"capacity_summary":                   "3/5",
				"assigned_count":                     3,
				"assigned_age":                       "12m",
				"unassigned_released_listener_count": 1,
				"terminal_time":                      "2026-07-15T00:00:00Z",
				"profile":                            "qts",
				"degraded":                           false,
				"build_id":                           "dev",
			},
			wantErr: false,
		},
		{
			name:    "single allowlisted key",
			fields:  map[string]any{"fleet_alias": "example-fleet"},
			wantErr: false,
		},
		{
			name:    "empty fields",
			fields:  map[string]any{},
			wantErr: false,
		},
		{
			name:    "job name is job-controlled and rejected",
			fields:  map[string]any{"job_name": "example-job"},
			wantErr: true,
		},
		{
			name:    "eligible scale set name is job-controlled and rejected",
			fields:  map[string]any{"eligible_scale_set_name": "example-scaleset"},
			wantErr: true,
		},
		{
			name:    "repository coordinate is job-controlled and rejected",
			fields:  map[string]any{"repository": "owner/repository"},
			wantErr: true,
		},
		{
			name:    "request body is job-controlled and rejected",
			fields:  map[string]any{"request_body": `{"ref":"refs/heads/main"}`},
			wantErr: true,
		},
		{
			name:    "jit material is rejected",
			fields:  map[string]any{"jit": "eyJhbGciOiJFUzI1NiJ9.EXAMPLE"},
			wantErr: true,
		},
		{
			name:    "token is rejected",
			fields:  map[string]any{"token": "EXAMPLE_TOKEN_VALUE"},
			wantErr: true,
		},
		{
			name:    "secret ref is rejected",
			fields:  map[string]any{"secret_ref": "EXAMPLE_SECRET_REFERENCE"},
			wantErr: true,
		},
		{
			name:    "filesystem path is rejected",
			fields:  map[string]any{"path": "/example/adapter.sock"},
			wantErr: true,
		},
		{
			name:    "route is rejected",
			fields:  map[string]any{"route": "/example/route"},
			wantErr: true,
		},
		{
			name:    "command output is rejected",
			fields:  map[string]any{"command_output": "example stdout"},
			wantErr: true,
		},
		{
			name:    "unknown key is rejected",
			fields:  map[string]any{"totally_unrecognized_key": "x"},
			wantErr: true,
		},
		{
			name: "one bad key among good keys still errors",
			fields: map[string]any{
				"fleet_alias": "example-fleet",
				"job_name":    "example-job",
			},
			wantErr: true,
		},
	}

	var buf bytes.Buffer
	l := Logger{Writer: &buf}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := l.Event("controller.test_event", tt.fields)
			if tt.wantErr && err == nil {
				t.Fatalf("Event(%v) = nil error, want error", tt.fields)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Event(%v) = %v, want nil error", tt.fields, err)
			}
		})
	}
}

// TestLoggerEventNeverPartiallyWritesRejectedEvent proves that a rejected
// event does not reach the sink at all (fail closed, not "log then error").
func TestLoggerEventNeverPartiallyWritesRejectedEvent(t *testing.T) {
	var buf bytes.Buffer
	l := Logger{Writer: &buf}

	if err := l.Event("controller.test_event", map[string]any{"job_name": "example-job"}); err == nil {
		t.Fatal("expected an error for a job-controlled key")
	}
	if buf.Len() != 0 {
		t.Fatalf("Writer received output for a rejected event: %q", buf.String())
	}
}
