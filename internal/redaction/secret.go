// Package redaction provides a scoped-secret type and a redacting log
// schema shared by the controller runtime. Nothing in this package ever
// exposes secret bytes or job-controlled log values through a getter,
// formatter, or JSON encoding; access to secret material is bounded to an
// explicit callback scope.
package redaction

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sync"
)

// ErrSecretScopeClosed is returned by a reader obtained from Secret.Use once
// the callback that produced it has returned, or once the owning Secret has
// been destroyed. It is also returned by Use itself when called on an
// already-destroyed Secret.
var ErrSecretScopeClosed = errors.New("redaction: secret scope closed")

// redactedPlaceholder is the fixed value returned by every formatting or
// encoding path on Secret. It never varies with the underlying content.
const redactedPlaceholder = "[REDACTED]"

// noCopy causes `go vet`'s copylocks analysis to flag any accidental
// by-value copy of a type embedding it, because noCopy implements
// sync.Locker. Secret embeds noCopy so that copying a Secret after
// construction -- which would duplicate ownership of its backing bytes and
// break the scope/destroy invariants -- is caught at build time by
// `go vet` (run as part of `go test`/CI) rather than at runtime.
type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

// Secret holds owned, in-memory secret bytes. Construct one with
// SecretFromBytes; thereafter reference it only by pointer -- never copy a
// Secret by value (the embedded noCopy guard makes `go vet` catch this).
//
// Secret never exposes its backing bytes through String, MarshalJSON, or
// any other getter; the only way to read the material is Use, and only for
// the duration of the callback it invokes.
type Secret struct {
	noCopy noCopy //nolint:unused // copylocks guard, not a functional field

	mu        sync.Mutex
	data      []byte
	destroyed bool
}

// SecretFromBytes copies b into a new, owned Secret and best-effort zeroes
// the caller's slice afterward so that, at minimum, no further Go-visible
// reference to the plaintext remains outside the Secret itself.
//
// When the source is an upstream immutable string (for example a JIT
// configuration value delivered as a Go string), convert it immediately at
// the boundary with SecretFromBytes([]byte(s)) and clear the variable or
// struct field that held s. Go's runtime gives no guarantee that the
// string's own backing storage is scrubbed -- the compiler and runtime may
// have interned it, copied it during garbage collection, or retained it in
// another live reference -- so this measure reduces exposure without
// eliminating it.
func SecretFromBytes(b []byte) *Secret {
	owned := make([]byte, len(b))
	copy(owned, b)
	zero(b)
	return &Secret{data: owned}
}

// Use invokes fn with a reader over the secret's bytes. The reader is valid
// only for the duration of fn: any read performed after fn returns, whether
// through a value retained by the caller or otherwise, returns
// ErrSecretScopeClosed. If the Secret has already been destroyed, Use
// returns ErrSecretScopeClosed without invoking fn.
func (s *Secret) Use(fn func(io.Reader) error) error {
	s.mu.Lock()
	if s.destroyed {
		s.mu.Unlock()
		return ErrSecretScopeClosed
	}
	open := true
	r := &scopedReader{secret: s, open: &open, r: bytes.NewReader(s.data)}
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		open = false
		s.mu.Unlock()
	}()

	return fn(r)
}

// Destroy best-effort zeroes the Secret's owned bytes and marks it
// destroyed. Destroy is idempotent: calling it any number of times,
// including concurrently, is safe. After Destroy, Use always returns
// ErrSecretScopeClosed and any in-flight scoped reader also starts
// returning ErrSecretScopeClosed.
func (s *Secret) Destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.destroyed {
		return
	}
	zero(s.data)
	s.data = nil
	s.destroyed = true
}

// String always returns the fixed redacted placeholder, never the
// underlying secret bytes. This also governs fmt's default formatting
// (%v, %s, %+v, ...) since Secret implements fmt.Stringer.
func (s *Secret) String() string {
	return redactedPlaceholder
}

// MarshalJSON always encodes the fixed redacted placeholder, never the
// underlying secret bytes.
func (s *Secret) MarshalJSON() ([]byte, error) {
	return json.Marshal(redactedPlaceholder)
}

// scopedReader is the reader type handed to Secret.Use callbacks. It
// remains readable only while its own scope is open and its owning Secret
// is not destroyed; both are checked against live Secret state on every
// Read, not just captured once at creation.
type scopedReader struct {
	secret *Secret
	open   *bool
	r      *bytes.Reader
}

func (sr *scopedReader) Read(p []byte) (int, error) {
	sr.secret.mu.Lock()
	defer sr.secret.mu.Unlock()

	if sr.secret.destroyed || !*sr.open {
		return 0, ErrSecretScopeClosed
	}
	return sr.r.Read(p)
}

// zero overwrites b in place. It is best-effort: Go provides no guarantee
// that this is the only remaining copy of the bytes in memory (e.g. prior
// copies made during append/growth, or by the caller before handing b to
// us), only that this particular backing array is cleared.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
