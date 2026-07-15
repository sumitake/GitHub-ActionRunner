package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempSecretFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write temp secret file: %v", err)
	}
	return path
}

// TestLoadRuntimeAcceptsValidDocument proves LoadRuntime accepts a
// well-formed document naming the available egress backend and either
// supported IP family, with secret material referenced (not inlined).
func TestLoadRuntimeAcceptsValidDocument(t *testing.T) {
	secretPath := writeTempSecretFile(t, "ghp_EXAMPLETOKEN1234567890")

	tests := []struct {
		name     string
		ipFamily string
	}{
		{"ipv4 only", "public_ipv4_only"},
		{"dual stack", "public_dual_stack"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := fmt.Sprintf(`{
				"egress_backend": "restricted-broker-v1",
				"ip_family": %q,
				"secret": {"source": "file", "ref": %q}
			}`, tt.ipFamily, secretPath)

			rt, err := LoadRuntime(strings.NewReader(doc))
			if err != nil {
				t.Fatalf("LoadRuntime: %v", err)
			}
			if rt.EgressBackend != EgressBackendRestrictedBrokerV1 {
				t.Errorf("EgressBackend = %q, want %q", rt.EgressBackend, EgressBackendRestrictedBrokerV1)
			}
			if string(rt.IPFamily) != tt.ipFamily {
				t.Errorf("IPFamily = %q, want %q", rt.IPFamily, tt.ipFamily)
			}
			if rt.Secret.Source != "file" || rt.Secret.Ref != secretPath {
				t.Errorf("Secret = %+v, want source=file ref=%q", rt.Secret, secretPath)
			}
		})
	}
}

// TestLoadRuntimeRejectsUnknownFields proves strict decoding: an unknown
// top-level field must fail the document rather than being ignored.
func TestLoadRuntimeRejectsUnknownFields(t *testing.T) {
	doc := `{
		"egress_backend": "restricted-broker-v1",
		"ip_family": "public_ipv4_only",
		"secret": {"source": "file", "ref": "/example/secret.txt"},
		"unexpected_field": true
	}`
	if _, err := LoadRuntime(strings.NewReader(doc)); err == nil {
		t.Fatal("LoadRuntime accepted a document with an unknown top-level field")
	}
}

// TestLoadRuntimeRejectsUnknownNestedFields proves strict decoding also
// applies to the nested SecretRef object.
func TestLoadRuntimeRejectsUnknownNestedFields(t *testing.T) {
	doc := `{
		"egress_backend": "restricted-broker-v1",
		"ip_family": "public_ipv4_only",
		"secret": {"source": "file", "ref": "/example/secret.txt", "value": "ghp_EXAMPLE"}
	}`
	if _, err := LoadRuntime(strings.NewReader(doc)); err == nil {
		t.Fatal("LoadRuntime accepted a secret ref with an unknown nested field")
	}
}

// TestLoadRuntimeRejectsInlineSecretValue proves that secret material may
// only appear as a SecretRef object, never as an inline literal string in
// place of that object.
func TestLoadRuntimeRejectsInlineSecretValue(t *testing.T) {
	doc := `{
		"egress_backend": "restricted-broker-v1",
		"ip_family": "public_ipv4_only",
		"secret": "ghp_EXAMPLETOKEN1234567890"
	}`
	if _, err := LoadRuntime(strings.NewReader(doc)); err == nil {
		t.Fatal("LoadRuntime accepted an inline secret literal instead of a SecretRef object")
	}
}

// TestLoadRuntimeRejectsBogusSecretSource proves LoadRuntime validates
// SecretRef.Source against the same allowlist ReadSecret uses, so a
// literal secret smuggled behind a bogus source label (rather than a
// recognized SecretRef source) is rejected at load time instead of
// silently accepted.
func TestLoadRuntimeRejectsBogusSecretSource(t *testing.T) {
	doc := `{
		"egress_backend": "restricted-broker-v1",
		"ip_family": "public_ipv4_only",
		"secret": {"source": "literal", "ref": "ghp_EXAMPLETOKEN1234567890"}
	}`
	if _, err := LoadRuntime(strings.NewReader(doc)); err == nil {
		t.Fatal("LoadRuntime accepted a SecretRef with bogus source \"literal\"")
	}
}

// TestLoadRuntimeRejectsEmptySecretSource proves an empty Source (e.g. the
// secret field omitted entirely, leaving the zero-value SecretRef) is
// rejected rather than silently accepted.
func TestLoadRuntimeRejectsEmptySecretSource(t *testing.T) {
	doc := `{
		"egress_backend": "restricted-broker-v1",
		"ip_family": "public_ipv4_only",
		"secret": {"source": "", "ref": "ghp_EXAMPLETOKEN1234567890"}
	}`
	if _, err := LoadRuntime(strings.NewReader(doc)); err == nil {
		t.Fatal("LoadRuntime accepted a SecretRef with empty source")
	}
}

// TestLoadRuntimeAcceptsEachValidSecretSource proves LoadRuntime still
// accepts every source ReadSecret recognizes ("file" and "env"), so the
// new source validation doesn't regress the previously-accepted sources.
func TestLoadRuntimeAcceptsEachValidSecretSource(t *testing.T) {
	secretPath := writeTempSecretFile(t, "ghp_EXAMPLETOKEN1234567890")
	t.Setenv("PORTABLE_GHAR_EXAMPLE_SECRET", "ghp_EXAMPLETOKEN1234567890")

	tests := []struct {
		name   string
		source string
		ref    string
	}{
		{"file", "file", secretPath},
		{"env", "env", "PORTABLE_GHAR_EXAMPLE_SECRET"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := fmt.Sprintf(`{
				"egress_backend": "restricted-broker-v1",
				"ip_family": "public_ipv4_only",
				"secret": {"source": %q, "ref": %q}
			}`, tt.source, tt.ref)

			if _, err := LoadRuntime(strings.NewReader(doc)); err != nil {
				t.Fatalf("LoadRuntime: %v", err)
			}
		})
	}
}

// TestLoadRuntimeRejectsUnavailableEgressBackend proves nftables-direct-v1
// is defined as an enum value but rejected by validation until exact
// pre-conntrack qualification is complete.
func TestLoadRuntimeRejectsUnavailableEgressBackend(t *testing.T) {
	doc := `{
		"egress_backend": "nftables-direct-v1",
		"ip_family": "public_ipv4_only",
		"secret": {"source": "file", "ref": "/example/secret.txt"}
	}`
	if _, err := LoadRuntime(strings.NewReader(doc)); err == nil {
		t.Fatal("LoadRuntime accepted nftables-direct-v1, which is not yet available")
	}
}

// TestLoadRuntimeRejectsUnknownEnumValues is a table test over unrecognized
// egress backend and IP family values.
func TestLoadRuntimeRejectsUnknownEnumValues(t *testing.T) {
	tests := []struct {
		name string
		doc  string
	}{
		{
			name: "unknown egress backend",
			doc: `{"egress_backend": "made-up-backend", "ip_family": "public_ipv4_only",
				"secret": {"source": "file", "ref": "/example/secret.txt"}}`,
		},
		{
			name: "unknown ip family",
			doc: `{"egress_backend": "restricted-broker-v1", "ip_family": "ipv9",
				"secret": {"source": "file", "ref": "/example/secret.txt"}}`,
		},
		{
			name: "empty egress backend",
			doc: `{"egress_backend": "", "ip_family": "public_ipv4_only",
				"secret": {"source": "file", "ref": "/example/secret.txt"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := LoadRuntime(strings.NewReader(tt.doc)); err == nil {
				t.Fatalf("LoadRuntime accepted invalid document: %s", tt.doc)
			}
		})
	}
}

// TestLoadRuntimeRejectsMalformedJSON proves decode errors on invalid JSON
// surface as errors rather than a zero-value Runtime with no error.
func TestLoadRuntimeRejectsMalformedJSON(t *testing.T) {
	if _, err := LoadRuntime(strings.NewReader(`{not valid json`)); err == nil {
		t.Fatal("LoadRuntime accepted malformed JSON")
	}
}

// TestReadSecretFromFile proves ReadSecret reads referenced file content
// into an owned, redacting Secret whose String() never reveals the bytes,
// while Use still provides the real content within its callback scope.
func TestReadSecretFromFile(t *testing.T) {
	const want = "ghp_EXAMPLETOKEN1234567890"
	secretPath := writeTempSecretFile(t, want)

	s, err := ReadSecret(SecretRef{Source: "file", Ref: secretPath})
	if err != nil {
		t.Fatalf("ReadSecret: %v", err)
	}
	defer s.Destroy()

	if got := s.String(); got != "[REDACTED]" {
		t.Fatalf("String() = %q, want [REDACTED]", got)
	}

	err = s.Use(func(r io.Reader) error {
		got, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		if string(got) != want {
			t.Fatalf("secret content = %q, want %q", got, want)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Use: %v", err)
	}
}

// TestReadSecretRejectsUnsupportedSource proves ReadSecret fails closed for
// a source it does not recognize rather than silently ignoring it.
func TestReadSecretRejectsUnsupportedSource(t *testing.T) {
	if _, err := ReadSecret(SecretRef{Source: "http", Ref: "https://example.invalid/secret"}); err == nil {
		t.Fatal("ReadSecret accepted unsupported source \"http\"")
	}
}

// TestReadSecretFromMissingFilePropagatesError proves a missing file
// source surfaces an error rather than an empty Secret.
func TestReadSecretFromMissingFilePropagatesError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.txt")
	if _, err := ReadSecret(SecretRef{Source: "file", Ref: missing}); err == nil {
		t.Fatal("ReadSecret accepted a reference to a nonexistent file")
	}
}

// TestReadSecretFromMissingFileErrorOmitsPath proves the file-not-found
// error identifies the failure by source kind without embedding the raw
// filesystem path -- paths must never reach logs, and an error string is a
// common place for a path to leak through.
func TestReadSecretFromMissingFileErrorOmitsPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.txt")
	_, err := ReadSecret(SecretRef{Source: "file", Ref: missing})
	if err == nil {
		t.Fatal("ReadSecret accepted a reference to a nonexistent file")
	}
	if strings.Contains(err.Error(), missing) {
		t.Fatalf("error %q contains the raw file path %q", err.Error(), missing)
	}
}
