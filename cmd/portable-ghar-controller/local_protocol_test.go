package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/controller"
)

const testLocalDeadline = int64(1_800_000_000_123_456_789)

func TestLocalRequestCanonicalGoldenVectors(t *testing.T) {
	eligible := "scale-a"
	tests := []struct {
		name    string
		request localRequest
		golden  string
	}{
		{
			name: "probe",
			request: localRequest{
				SchemaVersion:    localProtocolSchemaVersion,
				Method:           localMethodProbe,
				DeadlineUnixNano: testLocalDeadline,
			},
			golden: `{"schema_version":1,"method":"probe","deadline_unix_nano":1800000000123456789}`,
		},
		{
			name: "reconcile",
			request: localRequest{
				SchemaVersion:    localProtocolSchemaVersion,
				Method:           localMethodReconcileOnce,
				DeadlineUnixNano: testLocalDeadline,
			},
			golden: `{"schema_version":1,"method":"reconcile_once","deadline_unix_nano":1800000000123456789}`,
		},
		{
			name: "drain",
			request: localRequest{
				SchemaVersion:    localProtocolSchemaVersion,
				Method:           localMethodDrain,
				DeadlineUnixNano: testLocalDeadline,
				DrainPolicy:      pointerDrainPolicy(controller.DrainWait),
			},
			golden: `{"schema_version":1,"method":"drain","deadline_unix_nano":1800000000123456789,"drain_policy":"wait"}`,
		},
		{
			name: "set acquisition",
			request: localRequest{
				SchemaVersion:    localProtocolSchemaVersion,
				Method:           localMethodSetAcquisition,
				DeadlineUnixNano: testLocalDeadline,
				Acquisition: &localAcquisitionChange{
					Set:              controller.AcquisitionCanaryOnly,
					Expected:         controller.AcquisitionDisabled,
					EligibleScaleSet: &eligible,
				},
			},
			golden: `{"schema_version":1,"method":"set_acquisition","deadline_unix_nano":1800000000123456789,"acquisition":{"set":"canary-only","expected":"disabled","eligible_scale_set":"scale-a"}}`,
		},
		{
			name: "health",
			request: localRequest{
				SchemaVersion:    localProtocolSchemaVersion,
				Method:           localMethodHealth,
				DeadlineUnixNano: testLocalDeadline,
			},
			golden: `{"schema_version":1,"method":"health","deadline_unix_nano":1800000000123456789}`,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			document, err := marshalLocalRequest(test.request)
			if err != nil {
				t.Fatalf("marshalLocalRequest() error = %v", err)
			}
			if string(document) != test.golden {
				t.Fatalf(
					"marshalLocalRequest() = %q, want %q",
					document,
					test.golden,
				)
			}
			parsed, err := parseLocalRequest(document)
			if err != nil {
				t.Fatalf("parseLocalRequest() error = %v", err)
			}
			remarshal, err := marshalLocalRequest(parsed)
			if err != nil || !bytes.Equal(remarshal, document) {
				t.Fatalf(
					"request round trip = %q, %v",
					remarshal,
					err,
				)
			}
		})
	}
}

func TestLocalRequestRejectsNoncanonicalUnknownOversizedAndCrossedShapes(
	t *testing.T,
) {
	valid := `{"schema_version":1,"method":"probe","deadline_unix_nano":1800000000123456789}`
	invalid := []string{
		"",
		" " + valid,
		valid + "\n",
		`{"schema_version":1,"schema_version":1,"method":"probe","deadline_unix_nano":1800000000123456789}`,
		`{"schema_version":1,"method":"probe","deadline_unix_nano":1800000000123456789,"unknown":true}`,
		`{"schema_version":2,"method":"probe","deadline_unix_nano":1800000000123456789}`,
		`{"schema_version":1,"method":"unknown","deadline_unix_nano":1800000000123456789}`,
		`{"schema_version":1,"method":"probe","deadline_unix_nano":0}`,
		`{"schema_version":1,"method":"probe","deadline_unix_nano":1800000000123456789,"drain_policy":"wait"}`,
		`{"schema_version":1,"method":"drain","deadline_unix_nano":1800000000123456789}`,
		`{"schema_version":1,"method":"drain","deadline_unix_nano":1800000000123456789,"drain_policy":"invalid"}`,
		`{"schema_version":1,"method":"health","deadline_unix_nano":1800000000123456789,"acquisition":{"set":"disabled","expected":"disabled"}}`,
		`{"schema_version":1,"method":"set_acquisition","deadline_unix_nano":1800000000123456789}`,
		`{"schema_version":1,"method":"set_acquisition","deadline_unix_nano":1800000000123456789,"acquisition":{"set":"disabled","expected":"disabled","eligible_scale_set":"scale-a"}}`,
		`{"schema_version":1,"method":"set_acquisition","deadline_unix_nano":1800000000123456789,"acquisition":{"set":"canary-only","expected":"disabled"}}`,
	}
	for _, document := range invalid {
		if _, err := parseLocalRequest([]byte(document)); err == nil {
			t.Errorf("parseLocalRequest(%q) accepted invalid input", document)
		}
	}
	oversized := bytes.Repeat([]byte{'x'}, maxLocalRequestBytes+1)
	if _, err := parseLocalRequest(oversized); err == nil {
		t.Fatal("parseLocalRequest() accepted oversized input")
	}
}

func TestLocalResponseCanonicalGoldenAndClosedCrossovers(t *testing.T) {
	policy := &localPolicyStatus{
		Mode:     controller.AcquisitionDisabled,
		Epoch:    9,
		Digest:   strings.Repeat("a", 64),
		Capacity: 0,
	}
	success := localResponse{
		SchemaVersion: localProtocolSchemaVersion,
		Status:        localStatusOK,
		Reason:        localReasonNone,
		Policy:        policy,
	}
	document, err := marshalLocalResponse(localMethodProbe, success)
	if err != nil {
		t.Fatalf("marshalLocalResponse() error = %v", err)
	}
	golden := `{"schema_version":1,"status":"ok","reason":"none","policy":{"mode":"disabled","epoch":9,"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","capacity":0}}`
	if string(document) != golden {
		t.Fatalf("marshalLocalResponse() = %q, want %q", document, golden)
	}
	parsed, err := parseLocalResponse(localMethodProbe, document)
	if err != nil || parsed.Policy == nil || parsed.Policy.Epoch != 9 {
		t.Fatalf("parseLocalResponse() = %#v, %v", parsed, err)
	}

	failure := localResponse{
		SchemaVersion: localProtocolSchemaVersion,
		Status:        localStatusUnavailable,
		Reason:        localReasonNotReady,
	}
	failureDocument, err := marshalLocalResponse(localMethodHealth, failure)
	if err != nil {
		t.Fatalf("marshal failure response: %v", err)
	}
	if string(failureDocument) !=
		`{"schema_version":1,"status":"unavailable","reason":"not_ready"}` {
		t.Fatalf("failure response = %q", failureDocument)
	}

	invalid := []struct {
		method   localMethod
		response localResponse
	}{
		{
			localMethodProbe,
			localResponse{
				SchemaVersion: localProtocolSchemaVersion,
				Status:        localStatusOK,
				Reason:        localReasonNotReady,
				Policy:        policy,
			},
		},
		{
			localMethodProbe,
			localResponse{
				SchemaVersion: localProtocolSchemaVersion,
				Status:        localStatusOK,
				Reason:        localReasonNone,
			},
		},
		{
			localMethodDrain,
			localResponse{
				SchemaVersion: localProtocolSchemaVersion,
				Status:        localStatusOK,
				Reason:        localReasonNone,
				Policy:        policy,
			},
		},
		{
			localMethodHealth,
			localResponse{
				SchemaVersion: localProtocolSchemaVersion,
				Status:        localStatusUnavailable,
				Reason:        localReasonNotReady,
				Policy:        policy,
			},
		},
		{
			localMethodHealth,
			localResponse{
				SchemaVersion: localProtocolSchemaVersion,
				Status:        localStatusConflict,
				Reason:        localReasonNone,
			},
		},
	}
	for _, test := range invalid {
		if _, err := marshalLocalResponse(test.method, test.response); err == nil {
			t.Errorf(
				"marshalLocalResponse(%s, %#v) accepted crossover",
				test.method,
				test.response,
			)
		}
	}
}

func TestLocalResponseRejectsNoncanonicalUnknownAndOversized(t *testing.T) {
	valid := `{"schema_version":1,"status":"unavailable","reason":"not_ready"}`
	invalid := []string{
		"",
		" " + valid,
		valid + "\n",
		`{"schema_version":1,"status":"unavailable","reason":"not_ready","unknown":true}`,
		`{"schema_version":1,"status":"unavailable","reason":"unknown"}`,
	}
	for _, document := range invalid {
		if _, err := parseLocalResponse(
			localMethodHealth,
			[]byte(document),
		); err == nil {
			t.Errorf("parseLocalResponse(%q) accepted invalid input", document)
		}
	}
	if _, err := parseLocalResponse(
		localMethodProbe,
		[]byte(`{"schema_version":1,"status":"ok","reason":"none"}`),
	); err == nil {
		t.Fatal("parseLocalResponse() accepted payload-free probe success")
	}
	oversized := bytes.Repeat([]byte{'x'}, maxLocalResponseBytes+1)
	if _, err := parseLocalResponse(localMethodHealth, oversized); err == nil {
		t.Fatal("parseLocalResponse() accepted oversized input")
	}
}

func pointerDrainPolicy(
	policy controller.DrainPolicy,
) *controller.DrainPolicy {
	return &policy
}
