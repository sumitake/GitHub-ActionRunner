package upgrade

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestMaintenanceRequestCanonicalJSON(t *testing.T) {
	t.Parallel()

	candidate := strings.Repeat("b", 64)
	request := RunnerMaintenanceStatusRequest{
		Protocol:                runnerMaintenanceStatusProtocol,
		FleetID:                 "portable-example",
		Epoch:                   7,
		SessionID:               "session-example-0001",
		ControlSequence:         11,
		SelectedManifestDigest:  strings.Repeat("a", 64),
		CandidateManifestDigest: &candidate,
	}
	document, err := MarshalRunnerMaintenanceStatusRequest(request)
	if err != nil {
		t.Fatalf("MarshalRunnerMaintenanceStatusRequest() error = %v", err)
	}
	const want = `{"protocol":"portable-ghar.runner-maintenance.status.v1","fleetId":"portable-example","epoch":7,"sessionId":"session-example-0001","controlSequence":11,"selectedManifestDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","candidateManifestDigest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`
	if string(document) != want {
		t.Fatalf("request JSON = %s, want %s", document, want)
	}
}

func TestMaintenanceDirectiveCanonicalFrameAndAuthorization(t *testing.T) {
	t.Parallel()

	candidate, _ := validCandidateAndManifest(t)
	request := validMaintenanceRequest(candidate.ManifestDigest)
	wire := validMaintenanceWire(
		MaintenanceReplacePermitted,
		request,
		&candidate,
	)
	document, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	verifier := &recordingMaintenanceVerifier{}
	directive, err := ParseVerifiedRunnerMaintenanceDirective(
		context.Background(),
		document,
		16<<10,
		verifier,
	)
	if err != nil {
		t.Fatalf("ParseVerifiedRunnerMaintenanceDirective() error = %v", err)
	}
	if verifier.calls != 1 || verifier.responseMAC != wire.ResponseMAC {
		t.Fatalf(
			"verifier calls/mac = %d/%q, want 1/%q",
			verifier.calls,
			verifier.responseMAC,
			wire.ResponseMAC,
		)
	}
	var signed runnerMaintenanceDirectiveSignedWire
	copyMaintenanceSignedWire(&signed, wire)
	signedDocument, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("json.Marshal(signed) error = %v", err)
	}
	wantFrame := append(
		[]byte(
			"portable-ghar-response-v1\n"+
				runnerMaintenanceDirectiveProtocol+
				"\n",
		),
		signedDocument...,
	)
	if string(verifier.frame) != string(wantFrame) {
		t.Fatalf("verifier frame = %s, want %s", verifier.frame, wantFrame)
	}
	if strings.Contains(string(verifier.frame), "responseMac") ||
		strings.Contains(string(verifier.frame), wire.ResponseMAC) {
		t.Fatalf("verifier frame includes response MAC: %s", verifier.frame)
	}

	authorization, err := directive.authorize(
		request,
		fixedDirectiveTime(),
		time.Minute,
		MaintenanceReplacePermitted,
		&candidate,
		19,
		strings.Repeat("c", 64),
		strings.Repeat("d", 64),
	)
	if err != nil {
		t.Fatalf("authorize() error = %v", err)
	}
	if authorization.phase != MaintenanceReplacePermitted ||
		!validRawDigest(authorization.bindingDigest) {
		t.Fatalf("authorization = %#v", authorization)
	}
}

func TestMaintenanceDirectiveRejectsCrossBindingAndInvalidShapes(t *testing.T) {
	t.Parallel()

	candidate, _ := validCandidateAndManifest(t)
	request := validMaintenanceRequest(candidate.ManifestDigest)
	base := validMaintenanceWire(
		MaintenanceReplacePermitted,
		request,
		&candidate,
	)
	tests := []struct {
		name   string
		mutate func(*runnerMaintenanceDirectiveWire)
	}{
		{name: "protocol", mutate: func(value *runnerMaintenanceDirectiveWire) { value.Protocol = "wrong" }},
		{name: "epoch", mutate: func(value *runnerMaintenanceDirectiveWire) { value.Epoch++ }},
		{name: "session", mutate: func(value *runnerMaintenanceDirectiveWire) { value.SessionID += "-stale" }},
		{name: "request sequence", mutate: func(value *runnerMaintenanceDirectiveWire) { value.RequestControlSequence++ }},
		{name: "selected", mutate: func(value *runnerMaintenanceDirectiveWire) {
			value.RequestedSelectedManifestDigest = strings.Repeat("e", 64)
		}},
		{name: "candidate", mutate: func(value *runnerMaintenanceDirectiveWire) {
			changed := strings.Repeat("f", 64)
			value.RequestedCandidateManifestDigest = &changed
		}},
		{name: "transition", mutate: func(value *runnerMaintenanceDirectiveWire) { value.TransitionEpoch = 0 }},
		{name: "permit", mutate: func(value *runnerMaintenanceDirectiveWire) { value.PermitGeneration = 0 }},
		{name: "qualified version", mutate: func(value *runnerMaintenanceDirectiveWire) { changed := "v2.337.0"; value.QualifiedVersion = &changed }},
		{name: "config revision", mutate: func(value *runnerMaintenanceDirectiveWire) { value.ConfigRevision++ }},
		{name: "canary policy", mutate: func(value *runnerMaintenanceDirectiveWire) { value.CanaryPolicyDigest = strings.Repeat("e", 64) }},
		{name: "enabled policy", mutate: func(value *runnerMaintenanceDirectiveWire) { value.EnabledPolicyDigest = strings.Repeat("f", 64) }},
		{name: "expired", mutate: func(value *runnerMaintenanceDirectiveWire) {
			value.ExpiresAtServerMS = fixedDirectiveTime().UnixMilli()
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			wire := base
			test.mutate(&wire)
			document, err := json.Marshal(wire)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			directive, err := ParseVerifiedRunnerMaintenanceDirective(
				context.Background(),
				document,
				16<<10,
				&recordingMaintenanceVerifier{},
			)
			if err == nil {
				_, err = directive.authorize(
					request,
					fixedDirectiveTime(),
					time.Minute,
					MaintenanceReplacePermitted,
					&candidate,
					19,
					strings.Repeat("c", 64),
					strings.Repeat("d", 64),
				)
			}
			if !errors.Is(err, ErrMaintenanceDirectiveUnauthorized) &&
				!errors.Is(err, ErrInvalidMaintenanceDirective) {
				t.Fatalf("error = %v, want closed directive rejection", err)
			}
		})
	}

	t.Run("stage with qualified tuple", func(t *testing.T) {
		t.Parallel()
		wire := validMaintenanceWire(
			MaintenanceStagePermitted,
			request,
			nil,
		)
		qualified := candidate.Version
		wire.QualifiedVersion = &qualified
		document, _ := json.Marshal(wire)
		if _, err := ParseVerifiedRunnerMaintenanceDirective(
			context.Background(),
			document,
			16<<10,
			&recordingMaintenanceVerifier{},
		); !errors.Is(err, ErrInvalidMaintenanceDirective) {
			t.Fatalf("error = %v, want ErrInvalidMaintenanceDirective", err)
		}
	})
}

func TestMaintenanceDirectiveRejectsNoncanonicalAndUnverifiedValues(t *testing.T) {
	t.Parallel()

	candidate, _ := validCandidateAndManifest(t)
	request := validMaintenanceRequest(candidate.ManifestDigest)
	wire := validMaintenanceWire(
		MaintenanceReplacePermitted,
		request,
		&candidate,
	)
	document, _ := json.Marshal(wire)

	t.Run("whitespace", func(t *testing.T) {
		t.Parallel()
		changed := append([]byte(" "), document...)
		if _, err := ParseVerifiedRunnerMaintenanceDirective(
			context.Background(),
			changed,
			16<<10,
			&recordingMaintenanceVerifier{},
		); !errors.Is(err, ErrInvalidMaintenanceDirective) {
			t.Fatalf("error = %v, want ErrInvalidMaintenanceDirective", err)
		}
	})

	t.Run("verifier rejection", func(t *testing.T) {
		t.Parallel()
		if _, err := ParseVerifiedRunnerMaintenanceDirective(
			context.Background(),
			document,
			16<<10,
			&recordingMaintenanceVerifier{err: errors.New("rejected")},
		); !errors.Is(err, ErrInvalidMaintenanceDirective) {
			t.Fatalf("error = %v, want ErrInvalidMaintenanceDirective", err)
		}
	})

	t.Run("zero directive", func(t *testing.T) {
		t.Parallel()
		var directive RunnerMaintenanceDirective
		if _, err := directive.authorize(
			request,
			fixedDirectiveTime(),
			time.Minute,
			MaintenanceReplacePermitted,
			&candidate,
			19,
			strings.Repeat("c", 64),
			strings.Repeat("d", 64),
		); !errors.Is(err, ErrMaintenanceDirectiveUnauthorized) {
			t.Fatalf("error = %v, want ErrMaintenanceDirectiveUnauthorized", err)
		}
	})
}

func TestUnavailableMaintenanceDirectiveProvider(t *testing.T) {
	t.Parallel()

	candidate := strings.Repeat("b", 64)
	request := validMaintenanceRequest(candidate)
	var provider UnavailableMaintenanceDirectiveProvider
	directive, err := provider.Current(context.Background(), request)
	if !errors.Is(err, ErrMaintenanceUnavailable) {
		t.Fatalf("Current() error = %v, want ErrMaintenanceUnavailable", err)
	}
	if directive.verified {
		t.Fatal("unavailable provider returned verified directive")
	}
}

type recordingMaintenanceVerifier struct {
	calls       int
	frame       []byte
	responseMAC string
	err         error
}

func (verifier *recordingMaintenanceVerifier) VerifyRunnerMaintenanceResponse(
	_ context.Context,
	frame []byte,
	responseMAC string,
) error {
	verifier.calls++
	verifier.frame = append([]byte(nil), frame...)
	verifier.responseMAC = responseMAC
	return verifier.err
}

func validMaintenanceRequest(
	candidateManifestDigest string,
) RunnerMaintenanceStatusRequest {
	return RunnerMaintenanceStatusRequest{
		Protocol:                runnerMaintenanceStatusProtocol,
		FleetID:                 "portable-example",
		Epoch:                   7,
		SessionID:               "session-example-0001",
		ControlSequence:         11,
		SelectedManifestDigest:  strings.Repeat("a", 64),
		CandidateManifestDigest: &candidateManifestDigest,
	}
}

func validMaintenanceWire(
	phase RunnerMaintenancePhase,
	request RunnerMaintenanceStatusRequest,
	candidate *Candidate,
) runnerMaintenanceDirectiveWire {
	wire := runnerMaintenanceDirectiveWire{
		Protocol:                         runnerMaintenanceDirectiveProtocol,
		Epoch:                            request.Epoch,
		SessionID:                        request.SessionID,
		RequestControlSequence:           request.ControlSequence,
		RequestedSelectedManifestDigest:  request.SelectedManifestDigest,
		RequestedCandidateManifestDigest: request.CandidateManifestDigest,
		TransitionEpoch:                  17,
		PermitGeneration:                 23,
		Phase:                            phase,
		ConfigRevision:                   19,
		CanaryPolicyDigest:               strings.Repeat("c", 64),
		EnabledPolicyDigest:              strings.Repeat("d", 64),
		ExpiresAtServerMS:                fixedDirectiveTime().Add(30 * time.Second).UnixMilli(),
		ResponseMAC:                      "fixture-response-mac",
	}
	if candidate != nil {
		version := candidate.Version
		manifest := candidate.ManifestDigest
		image := candidate.ImageDigest
		wire.QualifiedVersion = &version
		wire.QualifiedManifestDigest = &manifest
		wire.QualifiedImageDigest = &image
	}
	return wire
}

func fixedDirectiveTime() time.Time {
	return time.Date(2026, time.July, 29, 13, 0, 0, 0, time.UTC)
}
