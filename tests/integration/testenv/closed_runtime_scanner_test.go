package testenv

import (
	"strings"
	"testing"
)

func TestClosedRuntimeSurfaceScannerConsumesExactSessionCapture(
	t *testing.T,
) {
	t.Parallel()

	capture := validRuntimeScannerCaptureForTest()
	raw := capture.Surfaces[2].Document
	scanner, err := newClosedRuntimeSurfaceScanner(64 << 10)
	if err != nil {
		t.Fatalf("newClosedRuntimeSurfaceScanner: %v", err)
	}
	result, err := scanner.ScanSessionCapture(&capture)
	if err != nil {
		t.Fatalf("ScanSessionCapture: %v", err)
	}
	if result.Version != 1 ||
		result.SurfaceCount != 15 ||
		result.SequenceDigest == "" ||
		!result.Clean {
		t.Fatalf("scan result = %+v", result)
	}
	if capture.Surfaces != nil {
		t.Fatalf("capture not consumed: %+v", capture)
	}
	for index, value := range raw {
		if value != 0 {
			t.Fatalf("raw surface byte %d not cleared", index)
		}
	}
}

func TestClosedRuntimeSurfaceScannerDigestBindsSurfaceBytes(
	t *testing.T,
) {
	t.Parallel()

	first := validRuntimeScannerCaptureForTest()
	second := validRuntimeScannerCaptureForTest()
	first.Surfaces[2].Document = []byte("alpha\n")
	second.Surfaces[2].Document = []byte("bravo\n")
	scanner, err := newClosedRuntimeSurfaceScanner(64 << 10)
	if err != nil {
		t.Fatalf("newClosedRuntimeSurfaceScanner: %v", err)
	}
	firstResult, err := scanner.ScanSessionCapture(&first)
	if err != nil {
		t.Fatalf("first ScanSessionCapture: %v", err)
	}
	secondResult, err := scanner.ScanSessionCapture(&second)
	if err != nil {
		t.Fatalf("second ScanSessionCapture: %v", err)
	}
	if firstResult.SequenceDigest == secondResult.SequenceDigest {
		t.Fatal("surface byte substitution retained the scan digest")
	}
}

func TestClosedRuntimeSurfaceScannerScansValuesButNotJSONFieldNames(
	t *testing.T,
) {
	t.Parallel()

	tests := map[string]struct {
		mutate func(*scannerSessionCapture)
		ok     bool
	}{
		"secret-shaped field names are not values": {
			mutate: func(*scannerSessionCapture) {},
			ok:     true,
		},
		"structured environment value": {
			mutate: func(capture *scannerSessionCapture) {
				capture.Surfaces[0].Document = []byte(
					`{"version":1,"env":["TOKEN=not-a-real-secret"],"entrypoint":["/bin/adapter"],"cmd":["hold"],"labels":{},"mounts":[],"binds":[],"devices":[],"security_options":["no-new-privileges=true"]}` + "\n",
				)
			},
		},
		"raw log value": {
			mutate: func(capture *scannerSessionCapture) {
				capture.Surfaces[2].Document = []byte(
					"Authorization: Bearer not-a-real-secret\n",
				)
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			capture := validRuntimeScannerCaptureForTest()
			test.mutate(&capture)
			scanner, err := newClosedRuntimeSurfaceScanner(
				64 << 10,
			)
			if err != nil {
				t.Fatalf(
					"newClosedRuntimeSurfaceScanner: %v",
					err,
				)
			}
			result, err := scanner.ScanSessionCapture(&capture)
			if test.ok {
				if err != nil || !result.Clean {
					t.Fatalf(
						"clean scan result=%+v err=%v",
						result,
						err,
					)
				}
			} else if err == nil {
				t.Fatal("accepted secret-shaped surface value")
			}
			if capture.Surfaces != nil {
				t.Fatal("scanner did not consume failed capture")
			}
		})
	}
}

func TestClosedRuntimeSurfaceScannerRejectsIncompleteOrNoncanonicalSet(
	t *testing.T,
) {
	t.Parallel()

	tests := map[string]func(*scannerSessionCapture){
		"missing": func(capture *scannerSessionCapture) {
			capture.Surfaces = capture.Surfaces[:14]
		},
		"reordered": func(capture *scannerSessionCapture) {
			capture.Surfaces[0], capture.Surfaces[1] =
				capture.Surfaces[1], capture.Surfaces[0]
		},
		"duplicate": func(capture *scannerSessionCapture) {
			capture.Surfaces[1].ID = capture.Surfaces[0].ID
		},
		"wrong encoding": func(capture *scannerSessionCapture) {
			capture.Surfaces[0].Encoding =
				closedRuntimeSurfaceRaw
		},
		"unknown inspect field": func(capture *scannerSessionCapture) {
			capture.Surfaces[0].Document = []byte(
				`{"version":1,"unknown":"x","env":[],"entrypoint":[],"cmd":[],"labels":{},"mounts":[],"binds":[],"devices":[],"security_options":[]}` + "\n",
			)
		},
		"noncanonical inspect": func(capture *scannerSessionCapture) {
			capture.Surfaces[0].Document = []byte(
				"{ \"version\":1,\"env\":[],\"entrypoint\":[],\"cmd\":[],\"labels\":{},\"mounts\":[],\"binds\":[],\"devices\":[],\"security_options\":[]}\n",
			)
		},
		"oversize": func(capture *scannerSessionCapture) {
			capture.Surfaces[2].Document = []byte(
				strings.Repeat("x", 64<<10+1),
			)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			capture := validRuntimeScannerCaptureForTest()
			mutate(&capture)
			scanner, err := newClosedRuntimeSurfaceScanner(
				64 << 10,
			)
			if err != nil {
				t.Fatalf(
					"newClosedRuntimeSurfaceScanner: %v",
					err,
				)
			}
			if _, err := scanner.ScanSessionCapture(
				&capture,
			); err == nil {
				t.Fatal("accepted invalid surface set")
			}
			if capture.Surfaces != nil {
				t.Fatal("scanner did not consume invalid capture")
			}
		})
	}
}

func TestClosedRuntimeSurfaceScannerRequiresCompleteBoundSupplements(
	t *testing.T,
) {
	t.Parallel()

	binding := validClosedNetworkSessionBinding(t)
	preparedRuntime := validNamespaceEvidenceRuntime()
	prepared := preparedRuntime.observation
	prepared.PolicyDigest = binding.Graph.Digest().String()
	prepared.NetworkEgressReport.PolicyDigest =
		binding.Graph.Digest().String()
	prepared.ProbeReport.PolicyDigest =
		binding.Graph.Digest().String()
	flood := preparedRuntime.flood
	closedDenials := permitClosedDenialsObservation(t, binding)
	closedDocument := closedDenialsDocumentForTest(binding.Graph)
	runnerWire, err := parseRunnerConformance(
		validRuntimeScannerCaptureForTest().Surfaces[12].Document,
		"1001:1001",
	)
	if err != nil {
		t.Fatalf("parseRunnerConformance: %v", err)
	}
	supplements := scannerSupplementInput{
		Prepared:      prepared,
		Flood:         flood,
		Graph:         binding.Graph,
		ClosedDenials: closedDenials,
		ClosedDocument: append(
			[]byte(nil),
			closedDocument...,
		),
		RunnerConformance: runnerWire,
		OneShots:          validOneShotTranscriptCaptureForTest(),
		MatrixDocuments:   validMatrixScannerCaptureForTest(),
	}
	retainedClosed := supplements.ClosedDocument
	capture := validRuntimeScannerCaptureForTest()
	if !validFixtureRuntimeObservation(supplements.Prepared) {
		t.Fatal("prepared supplement is invalid")
	}
	if !validFixtureFloodObservation(
		supplements.Flood,
		uint32(supplements.Flood.Report.Attempts),
	) {
		t.Fatal("flood supplement is invalid")
	}
	if !validClosedDenialsSessionObservation(
		supplements.ClosedDenials,
		supplements.Graph,
	) {
		t.Fatal("closed-denials supplement is invalid")
	}
	if !validRunnerSessionConformanceForSupplement(
		supplements.RunnerConformance,
		capture.RunnerUser,
	) {
		t.Fatal("runner supplement is invalid")
	}
	if !validOneShotTranscriptCapture(supplements.OneShots) {
		t.Fatal("one-shot supplement is invalid")
	}
	if !validMatrixScannerCapture(supplements.MatrixDocuments) {
		t.Fatal("matrix supplement is invalid")
	}
	probeSupplements := cloneScannerSupplementForTest(supplements)
	probeCapture := cloneScannerCaptureForTest(capture)
	additional, err := buildScannerSupplementSurfaces(
		probeCapture,
		&probeSupplements,
	)
	if err != nil {
		t.Fatalf("buildScannerSupplementSurfaces: %v", err)
	}
	probeCapture.Surfaces = append(
		probeCapture.Surfaces,
		additional...,
	)
	if !validCompleteRuntimeCapture(probeCapture) {
		t.Fatal("complete runtime capture order is invalid")
	}
	for _, surface := range probeCapture.Surfaces {
		if err := scanClosedRuntimeSurface(
			surface,
			probeCapture.RunnerUser,
		); err != nil {
			t.Fatalf("surface %s: %v", surface.ID, err)
		}
	}
	destroyScannerCapture(&probeCapture)
	destroyScannerSupplementInput(&probeSupplements)
	scanner, err := newClosedRuntimeSurfaceScanner(64 << 10)
	if err != nil {
		t.Fatalf("newClosedRuntimeSurfaceScanner: %v", err)
	}
	result, err := scanner.ScanCompleteCapture(
		&capture,
		&supplements,
	)
	if err != nil {
		t.Fatalf("ScanCompleteCapture: %v", err)
	}
	if result.Version != 1 ||
		result.SurfaceCount != completeRuntimeSurfaceCount ||
		result.SequenceDigest == "" ||
		!result.Clean {
		t.Fatalf("complete scan result = %+v", result)
	}
	if capture.Surfaces != nil ||
		supplements.ClosedDocument != nil {
		t.Fatal("complete scan did not consume its inputs")
	}
	for index, value := range retainedClosed {
		if value != 0 {
			t.Fatalf(
				"closed supplement byte %d not cleared",
				index,
			)
		}
	}

	incompleteCapture := validRuntimeScannerCaptureForTest()
	incomplete := scannerSupplementInput{
		Prepared:          prepared,
		Flood:             flood,
		Graph:             binding.Graph,
		ClosedDenials:     closedDenials,
		RunnerConformance: runnerWire,
		OneShots:          validOneShotTranscriptCaptureForTest(),
		MatrixDocuments:   validMatrixScannerCaptureForTest(),
	}
	if _, err := scanner.ScanCompleteCapture(
		&incompleteCapture,
		&incomplete,
	); err == nil {
		t.Fatal("complete scan accepted a missing closed document")
	}
	if incompleteCapture.Surfaces != nil {
		t.Fatal("failed complete scan did not consume command capture")
	}
}

func cloneScannerSupplementForTest(
	input scannerSupplementInput,
) scannerSupplementInput {
	input.ClosedDocument = append(
		[]byte(nil),
		input.ClosedDocument...,
	)
	input.OneShots.surfaces = cloneClosedSurfacesForTest(
		input.OneShots.surfaces,
	)
	input.MatrixDocuments.surfaces = cloneClosedSurfacesForTest(
		input.MatrixDocuments.surfaces,
	)
	return input
}

func cloneScannerCaptureForTest(
	input scannerSessionCapture,
) scannerSessionCapture {
	input.Surfaces = cloneClosedSurfacesForTest(input.Surfaces)
	return input
}

func cloneClosedSurfacesForTest(
	input []closedRuntimeSurface,
) []closedRuntimeSurface {
	result := make([]closedRuntimeSurface, len(input))
	for index, surface := range input {
		result[index] = surface
		result[index].Document = append(
			[]byte(nil),
			surface.Document...,
		)
	}
	return result
}

func validOneShotTranscriptCaptureForTest() oneShotTranscriptCapture {
	structured := func(id closedRuntimeSurfaceID) closedRuntimeSurface {
		return closedRuntimeSurface{
			ID:       id,
			Encoding: closedRuntimeSurfaceStructuredJSON,
			Document: []byte(
				`{"status":"ok","version":1}` + "\n",
			),
		}
	}
	raw := func(
		id closedRuntimeSurfaceID,
		document string,
	) closedRuntimeSurface {
		return closedRuntimeSurface{
			ID:       id,
			Encoding: closedRuntimeSurfaceRaw,
			Document: []byte(document),
		}
	}
	return oneShotTranscriptCapture{
		valid:              true,
		commandDigest:      inputDigestA,
		mountAbsenceDigest: inputDigestB,
		surfaces: []closedRuntimeSurface{
			structured(surfaceAdapterEmptinessVerifier),
			raw(surfaceAdapterEmptinessAbsence, ""),
			structured(surfacePolicyHelperApplication),
			raw(surfacePolicyHelperAbsence, ""),
			structured(surfaceAuthorityFilesystem),
			structured(surfaceHeldSocketAudit),
			structured(surfaceBrokerRelease),
			structured(surfaceBrokerAudit),
			raw(surfaceAdapterPeerBind, "OK\n"),
			structured(surfaceProxyVerifier),
			raw(surfaceProxyVerifierAbsence, ""),
			structured(surfaceBrokerNamespaceVerifier),
			raw(surfaceBrokerNamespaceAbsence, ""),
			structured(surfaceRunnerPreNamespace),
			structured(surfaceRunnerFinalNamespace),
			structured(surfaceLoopbackFloodVerifier),
			raw(surfaceLoopbackFloodAbsence, ""),
		},
	}
}

func validMatrixScannerCaptureForTest() matrixScannerCapture {
	source, _ := newMatrixScannerCaptureSource(
		matrixScannerBindingForTest(),
	)
	capture, _ := source.Take()
	return capture
}

func validRuntimeScannerCaptureForTest() scannerSessionCapture {
	inspect := func(role string) []byte {
		return []byte(
			`{"version":1,"env":["PATH=/usr/bin"],"entrypoint":["/bin/` +
				role +
				`"],"cmd":["hold"],"labels":{"io.portable-ghar.kind":"` +
				role +
				`"},"mounts":[],"binds":[],"devices":[],"security_options":["no-new-privileges=true"]}` +
				"\n",
		)
	}
	conformance := []byte(
		`{"version":1,"euid":1001,"egid":1001,"capabilities":{"effective":"0000000000000000","permitted":"0000000000000000","inheritable":"0000000000000000","bounding":"0000000000000000","ambient":"0000000000000000"},"raw_socket_denied":true,"bpf_denied":true,"unshare_denied":true,"setns_denied":true,"clone3_denied":true,"namespace_denied":true,"proc_sys_read_only":true,"proc_masks_present":true,"controller_database_absent":true,"docker_authority_absent":true,"host_control_absent":true,"secret_environment_absent":true,"jit_environment_absent":true,"synthetic_token_absent":true}` + "\n",
	)
	return scannerSessionCapture{
		RunnerUser: "1001:1001",
		Surfaces: []closedRuntimeSurface{
			{surfaceAdapterInspect, closedRuntimeSurfaceStructuredJSON, inspect("adapter")},
			{surfaceAdapterTop, closedRuntimeSurfaceRaw, []byte("1 adapter\n")},
			{surfaceAdapterLogsStdout, closedRuntimeSurfaceRaw, nil},
			{surfaceAdapterLogsStderr, closedRuntimeSurfaceRaw, nil},
			{surfaceBrokerInspect, closedRuntimeSurfaceStructuredJSON, inspect("broker")},
			{surfaceBrokerTop, closedRuntimeSurfaceRaw, []byte("2 broker\n")},
			{surfaceBrokerLogsStdout, closedRuntimeSurfaceRaw, nil},
			{surfaceBrokerLogsStderr, closedRuntimeSurfaceRaw, nil},
			{surfaceRunnerInspect, closedRuntimeSurfaceStructuredJSON, inspect("runner")},
			{surfaceRunnerFinalInventory, closedRuntimeSurfaceRaw, []byte("417 /usr/local/bin/portable-ghar-runner-gate hold\n")},
			{surfaceRunnerLogsStdout, closedRuntimeSurfaceRaw, nil},
			{surfaceRunnerLogsStderr, closedRuntimeSurfaceRaw, nil},
			{surfaceRunnerConformance, closedRuntimeSurfaceStructuredJSON, conformance},
			{surfaceRunnerVerifyImage, closedRuntimeSurfaceRaw, []byte("2.336.0\n")},
			{surfaceRunnerListenerVersion, closedRuntimeSurfaceRaw, []byte("2.336.0\n")},
		},
	}
}
