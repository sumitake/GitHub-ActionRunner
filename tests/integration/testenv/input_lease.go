package testenv

import (
	"errors"
	"sync"
	"time"
)

var (
	ErrAuthorizationInUse = errors.New(
		"testenv: authorization in use",
	)
	ErrAuthorizationLease = errors.New(
		"testenv: authorization lease invalid",
	)
	ErrAuthorizationConsumedRunAborted = errors.New(
		"testenv: authorization consumed and run aborted",
	)
)

type inputLeaseState uint8

const (
	inputLeaseHeld inputLeaseState = iota + 1
	inputLeaseConsumed
	inputLeaseClosed
)

type inputLeaseOperations interface {
	Revalidate() error
	Unlink() error
	SyncParent() error
	ProveAbsent() error
	Close() error
}

// conformanceInputLease is the one-shot Linux execution authority. It owns
// the retained canonical input bytes and delegates only exact identity/name
// operations to its platform adapter.
type conformanceInputLease struct {
	mu            sync.Mutex
	state         inputLeaseState
	consumeProven bool
	parsed        ParsedConformanceInput
	operations    inputLeaseOperations

	closeOnce sync.Once
	closeErr  error
}

func newConformanceInputLease(
	parsed ParsedConformanceInput,
	operations inputLeaseOperations,
) (*conformanceInputLease, error) {
	if operations == nil || !validateParsedInputEnvelope(parsed) {
		return nil, ErrAuthorizationLease
	}
	owned := parsed
	owned.Document = append([]byte(nil), parsed.Document...)
	return &conformanceInputLease{
		state:      inputLeaseHeld,
		parsed:     owned,
		operations: operations,
	}, nil
}

func (l *conformanceInputLease) Parsed() (
	ParsedConformanceInput,
	error,
) {
	if l == nil {
		return ParsedConformanceInput{}, ErrAuthorizationLease
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state == inputLeaseClosed ||
		!validateParsedInputEnvelope(l.parsed) {
		return ParsedConformanceInput{}, ErrAuthorizationLease
	}
	parsed := l.parsed
	parsed.Document = append([]byte(nil), l.parsed.Document...)
	return parsed, nil
}

func (l *conformanceInputLease) Consume(now time.Time) error {
	if l == nil || now.IsZero() {
		return ErrAuthorizationLease
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state != inputLeaseHeld ||
		l.operations == nil ||
		!authorizationWindowContains(l.parsed.Input.Authorization, now.UTC()) {
		return ErrAuthorizationLease
	}
	if err := l.operations.Revalidate(); err != nil {
		return ErrAuthorizationLease
	}
	if err := l.operations.Unlink(); err != nil {
		return ErrAuthorizationLease
	}
	// Successful unlink irreversibly spends the capability. This transition
	// precedes every fallible durability or absence proof so no retry can
	// unlink a subsequently recreated basename.
	l.state = inputLeaseConsumed
	if err := l.operations.SyncParent(); err != nil {
		return ErrAuthorizationConsumedRunAborted
	}
	if err := l.operations.ProveAbsent(); err != nil {
		return ErrAuthorizationConsumedRunAborted
	}
	l.consumeProven = true
	return nil
}

func (l *conformanceInputLease) Close() error {
	if l == nil {
		return ErrAuthorizationLease
	}
	l.closeOnce.Do(func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.operations != nil {
			l.closeErr = l.operations.Close()
		}
		for index := range l.parsed.Document {
			l.parsed.Document[index] = 0
		}
		l.parsed.Document = nil
		l.state = inputLeaseClosed
	})
	return l.closeErr
}

func authorizationWindowContains(
	authorization Authorization,
	now time.Time,
) bool {
	notBefore, ok := parseCanonicalUTC(authorization.NotBefore)
	if !ok {
		return false
	}
	notAfter, ok := parseCanonicalUTC(authorization.NotAfter)
	return ok &&
		!now.Before(notBefore) &&
		now.Before(notAfter)
}
