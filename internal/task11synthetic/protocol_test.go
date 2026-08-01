package task11synthetic

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

const (
	testDigestA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testDigestB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testDigestC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	testDigestD = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	testDigestE = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	testDigestF = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
)

func TestInputCanonicalRoundTrip(t *testing.T) {
	t.Parallel()

	input := validInputForTest(ScenarioOneJob)
	document, err := MarshalInput(input, MaximumWireBytes)
	if err != nil {
		t.Fatalf("MarshalInput: %v", err)
	}
	const want = `{"schema_version":1,"protocol_id":"portable-ghar-task11-synthetic-v1","scenario":"one-job","cycle_run_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","sentinel":{"url":"https://example.com/probe","host":"example.com","port":443,"host_identity_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","spki_digest":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","certificate_digest":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","policy_entry_digest":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","policy_evidence_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","response_body_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}` + "\n"
	if string(document) != want {
		t.Fatalf("canonical input = %q, want %q", document, want)
	}
	parsed, err := ParseInput(document, MaximumWireBytes)
	if err != nil {
		t.Fatalf("ParseInput: %v", err)
	}
	if parsed != input {
		t.Fatalf("ParseInput() = %+v, want %+v", parsed, input)
	}

	seedInput := validInputForTest(ScenarioSeedFirst)
	seedDocument, err := MarshalInput(seedInput, MaximumWireBytes)
	if err != nil {
		t.Fatalf("MarshalInput(seed): %v", err)
	}
	if !bytes.HasSuffix(
		seedDocument,
		[]byte(`,"seed_id":"portable-ghar-task11-seed-v1"}`+"\n"),
	) {
		t.Fatalf("seed input omitted or reordered seed_id: %q", seedDocument)
	}
}

func TestInputRejectsNoncanonicalDocuments(t *testing.T) {
	t.Parallel()

	canonical, err := MarshalInput(
		validInputForTest(ScenarioOneJob),
		MaximumWireBytes,
	)
	if err != nil {
		t.Fatalf("MarshalInput: %v", err)
	}
	withoutLF := canonical[:len(canonical)-1]
	reordered := []byte(
		`{"protocol_id":"portable-ghar-task11-synthetic-v1","schema_version":1,"scenario":"one-job","cycle_run_digest":"` +
			testDigestA + `","nonce":"` + testDigestB +
			`","sentinel":{"url":"https://example.com/probe","host":"example.com","port":443,"host_identity_digest":"` +
			testDigestC + `","spki_digest":"` + testDigestD +
			`","certificate_digest":"` + testDigestE +
			`","policy_entry_digest":"` + testDigestF +
			`","policy_evidence_digest":"` + testDigestA +
			`","response_body_digest":"` + testDigestB + `"}}` + "\n",
	)
	duplicate := bytes.Replace(
		canonical,
		[]byte(`{"schema_version":1,`),
		[]byte(`{"schema_version":1,"schema_version":1,`),
		1,
	)
	unknown := bytes.Replace(
		canonical,
		[]byte(`{"schema_version":1,`),
		[]byte(`{"schema_version":1,"unknown":1,`),
		1,
	)
	alternateEscape := bytes.Replace(
		canonical,
		[]byte(`https://example.com/probe`),
		[]byte(`https:\/\/example.com\/probe`),
		1,
	)
	explicitDefault := bytes.Replace(
		canonical,
		[]byte(`}}`+"\n"),
		[]byte(`},"seed_id":""}`+"\n"),
		1,
	)
	oversize := append(
		append([]byte(nil), withoutLF...),
		bytes.Repeat([]byte(" "), int(MaximumWireBytes))...,
	)
	oversize = append(oversize, '\n')

	tests := map[string][]byte{
		"missing LF":           withoutLF,
		"leading whitespace":   append([]byte(" "), canonical...),
		"trailing bytes":       append(append([]byte(nil), canonical...), 'x'),
		"reordered":            reordered,
		"duplicate":            duplicate,
		"unknown":              unknown,
		"alternate escaping":   alternateEscape,
		"explicit default":     explicitDefault,
		"oversize":             oversize,
		"GitHub JIT shaped":    []byte(`{"runner_name":"runner","encoded_jit_config":"x"}` + "\n"),
		"multiple documents":   append(append([]byte(nil), canonical...), canonical...),
		"partial second value": append(append([]byte(nil), canonical...), '{'),
	}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseInput(document, MaximumWireBytes); !errors.Is(
				err,
				ErrInvalidProtocol,
			) {
				t.Fatalf("ParseInput() error = %v, want ErrInvalidProtocol", err)
			}
		})
	}

	if _, err := ParseInput(canonical, uint64(len(canonical)-1)); !errors.Is(
		err,
		ErrInvalidProtocol,
	) {
		t.Fatalf("private bound error = %v, want ErrInvalidProtocol", err)
	}
}

func TestInputRejectsInvalidSemanticValues(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*Input){
		"schema": func(input *Input) {
			input.SchemaVersion = 2
		},
		"protocol": func(input *Input) {
			input.ProtocolID = "portable-ghar-task11-synthetic-v2"
		},
		"scenario": func(input *Input) {
			input.Scenario = Scenario("unknown")
		},
		"cycle digest": func(input *Input) {
			input.CycleRunDigest = strings.ToUpper(testDigestA)
		},
		"nonce": func(input *Input) {
			input.Nonce = "abcd"
		},
		"HTTP sentinel": func(input *Input) {
			input.Sentinel.URL = "http://example.com/probe"
		},
		"sentinel host mismatch": func(input *Input) {
			input.Sentinel.Host = "other.example.com"
		},
		"sentinel port": func(input *Input) {
			input.Sentinel.Port = 0
		},
		"sentinel digest": func(input *Input) {
			input.Sentinel.SPKIDigest = "token=not-allowed"
		},
		"secret shaped URL": func(input *Input) {
			input.Sentinel.URL = "https://example.com/token=not-allowed"
		},
		"seed on non-seed": func(input *Input) {
			input.SeedID = SeedID
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := validInputForTest(ScenarioOneJob)
			mutate(&input)
			if _, err := MarshalInput(input, MaximumWireBytes); !errors.Is(
				err,
				ErrInvalidProtocol,
			) {
				t.Fatalf("MarshalInput() error = %v, want ErrInvalidProtocol", err)
			}
		})
	}

	for _, scenario := range []Scenario{ScenarioSeedFirst, ScenarioSeedSecond} {
		input := validInputForTest(scenario)
		input.SeedID = ""
		if _, err := MarshalInput(input, MaximumWireBytes); !errors.Is(
			err,
			ErrInvalidProtocol,
		) {
			t.Fatalf(
				"MarshalInput(%s without seed) error = %v, want ErrInvalidProtocol",
				scenario,
				err,
			)
		}
	}
}

func TestOutputCanonicalRoundTripAndClosedStreamShapes(t *testing.T) {
	t.Parallel()

	boundary := validBoundaryForTest(ScenarioOneJob)
	terminal := validTerminalForTest(ScenarioOneJob)
	boundaryDocument, err := MarshalBoundaryFrame(boundary)
	if err != nil {
		t.Fatalf("MarshalBoundaryFrame: %v", err)
	}
	terminalDocument, err := MarshalTerminalFrame(terminal)
	if err != nil {
		t.Fatalf("MarshalTerminalFrame: %v", err)
	}
	const wantBoundary = `{"schema_version":1,"protocol_id":"portable-ghar-task11-synthetic-v1","frame":"boundary","scenario":"one-job","cycle_run_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","job_marker_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","boundary":"listener-ready","synthetic_token_absent":true,"immutable_payload_count":1,"upgrade_interruption_exercised":false,"cgroup_version":"2"}` + "\n"
	if string(boundaryDocument) != wantBoundary {
		t.Fatalf("boundary = %q, want %q", boundaryDocument, wantBoundary)
	}
	streamDocument := append(append([]byte(nil), boundaryDocument...), terminalDocument...)
	binding := validStreamBindingForTest(ScenarioOneJob)
	stream, err := ParseStream(streamDocument, binding)
	if err != nil {
		t.Fatalf("ParseStream(normal): %v", err)
	}
	if stream.Boundary != boundary ||
		stream.Terminal == nil ||
		!terminalFramesEqual(*stream.Terminal, terminal) {
		t.Fatalf("normal stream = %+v", stream)
	}

	for _, scenario := range []Scenario{
		ScenarioCleanupListenerCrash,
		ScenarioCleanupUpgradeInterruption,
	} {
		crashBoundary := validBoundaryForTest(scenario)
		document, marshalErr := MarshalBoundaryFrame(crashBoundary)
		if marshalErr != nil {
			t.Fatalf("MarshalBoundaryFrame(%s): %v", scenario, marshalErr)
		}
		parsed, parseErr := ParseStream(
			document,
			validStreamBindingForTest(scenario),
		)
		if parseErr != nil {
			t.Fatalf("ParseStream(%s): %v", scenario, parseErr)
		}
		if parsed.Boundary != crashBoundary || parsed.Terminal != nil {
			t.Fatalf("%s stream = %+v", scenario, parsed)
		}
	}
}

func TestOutputRejectsInvalidStreamShapesAndBindings(t *testing.T) {
	t.Parallel()

	boundary, terminal := validNormalDocumentsForTest(t, ScenarioOneJob)
	crash, _ := validNormalDocumentsForTest(t, ScenarioCleanupListenerCrash)
	tests := map[string]struct {
		document []byte
		binding  StreamBinding
	}{
		"zero frame": {
			document: nil,
			binding:  validStreamBindingForTest(ScenarioOneJob),
		},
		"normal missing terminal": {
			document: boundary,
			binding:  validStreamBindingForTest(ScenarioOneJob),
		},
		"terminal only": {
			document: terminal,
			binding:  validStreamBindingForTest(ScenarioOneJob),
		},
		"third frame": {
			document: append(
				append(append([]byte(nil), boundary...), terminal...),
				boundary...,
			),
			binding: validStreamBindingForTest(ScenarioOneJob),
		},
		"crash with terminal": {
			document: append(append([]byte(nil), crash...), terminal...),
			binding:  validStreamBindingForTest(ScenarioCleanupListenerCrash),
		},
		"partial frame": {
			document: append(append([]byte(nil), boundary...), '{'),
			binding:  validStreamBindingForTest(ScenarioOneJob),
		},
		"wrong cycle binding": {
			document: append(append([]byte(nil), boundary...), terminal...),
			binding: StreamBinding{
				Scenario:        ScenarioOneJob,
				CycleRunDigest:  testDigestC,
				JobMarkerDigest: testDigestB,
				CgroupVersion:   CgroupV2,
			},
		},
		"wrong cgroup binding": {
			document: append(append([]byte(nil), boundary...), terminal...),
			binding: StreamBinding{
				Scenario:        ScenarioOneJob,
				CycleRunDigest:  testDigestA,
				JobMarkerDigest: testDigestB,
				CgroupVersion:   CgroupV1,
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseStream(test.document, test.binding); !errors.Is(
				err,
				ErrInvalidProtocol,
			) {
				t.Fatalf("ParseStream() error = %v, want ErrInvalidProtocol", err)
			}
		})
	}
}

func TestOutputRejectsInvalidBoundaryAndTerminalSemantics(t *testing.T) {
	t.Parallel()

	boundaryTests := map[string]func(*BoundaryFrame){
		"wrong boundary": func(frame *BoundaryFrame) {
			frame.Boundary = BoundaryListenerCrashArmed
		},
		"token present": func(frame *BoundaryFrame) {
			frame.SyntheticTokenAbsent = false
		},
		"payload count": func(frame *BoundaryFrame) {
			frame.ImmutablePayloadCount = 2
		},
		"upgrade flag": func(frame *BoundaryFrame) {
			frame.UpgradeInterruptionExercised = true
		},
		"cgroup": func(frame *BoundaryFrame) {
			frame.CgroupVersion = CgroupVersion("3")
		},
		"seed": func(frame *BoundaryFrame) {
			frame.SeedID = SeedID
		},
	}
	for name, mutate := range boundaryTests {
		t.Run("boundary "+name, func(t *testing.T) {
			frame := validBoundaryForTest(ScenarioOneJob)
			mutate(&frame)
			if _, err := MarshalBoundaryFrame(frame); !errors.Is(
				err,
				ErrInvalidProtocol,
			) {
				t.Fatalf(
					"MarshalBoundaryFrame() error = %v, want ErrInvalidProtocol",
					err,
				)
			}
		})
	}

	terminalTests := map[string]func(*TerminalFrame){
		"outcome": func(frame *TerminalFrame) {
			frame.Outcome = Outcome("failed")
		},
		"registration": func(frame *TerminalFrame) {
			frame.RegistrationRemoved = false
		},
		"token": func(frame *TerminalFrame) {
			frame.SyntheticTokenAbsent = false
		},
		"payload": func(frame *TerminalFrame) {
			frame.ImmutablePayloadCount = 2
		},
		"upgrade": func(frame *TerminalFrame) {
			frame.UpgradeInterruptionExercised = true
		},
		"missing resource": func(frame *TerminalFrame) {
			frame.Resources = frame.Resources[:len(frame.Resources)-1]
		},
		"reordered resource": func(frame *TerminalFrame) {
			frame.Resources[0], frame.Resources[1] =
				frame.Resources[1], frame.Resources[0]
		},
		"seed": func(frame *TerminalFrame) {
			frame.Seed = validSeedProofForTest(ScenarioSeedFirst)
		},
	}
	for name, mutate := range terminalTests {
		t.Run("terminal "+name, func(t *testing.T) {
			frame := validTerminalForTest(ScenarioOneJob)
			mutate(&frame)
			if _, err := MarshalTerminalFrame(frame); !errors.Is(
				err,
				ErrInvalidProtocol,
			) {
				t.Fatalf(
					"MarshalTerminalFrame() error = %v, want ErrInvalidProtocol",
					err,
				)
			}
		})
	}
}

func TestSeedFrameSemanticsAreScenarioBound(t *testing.T) {
	t.Parallel()

	for _, scenario := range []Scenario{ScenarioSeedFirst, ScenarioSeedSecond} {
		boundary := validBoundaryForTest(scenario)
		terminal := validTerminalForTest(scenario)
		boundaryDocument, err := MarshalBoundaryFrame(boundary)
		if err != nil {
			t.Fatalf("MarshalBoundaryFrame(%s): %v", scenario, err)
		}
		terminalDocument, err := MarshalTerminalFrame(terminal)
		if err != nil {
			t.Fatalf("MarshalTerminalFrame(%s): %v", scenario, err)
		}
		document := append(boundaryDocument, terminalDocument...)
		stream, err := ParseStream(
			document,
			validStreamBindingForTest(scenario),
		)
		if err != nil || stream.Terminal == nil {
			t.Fatalf("ParseStream(%s) = %+v, %v", scenario, stream, err)
		}
	}

	tests := map[string]func(*TerminalFrame){
		"first says mutation absent": func(frame *TerminalFrame) {
			frame.Seed.MutationAbsent = true
		},
		"wrong source": func(frame *TerminalFrame) {
			frame.Seed.SourceDigest = testDigestA
		},
		"wrong copy": func(frame *TerminalFrame) {
			frame.Seed.CopyDigest = testDigestA
		},
		"wrong mutation": func(frame *TerminalFrame) {
			frame.Seed.MutationDigest = testDigestA
		},
		"source changed": func(frame *TerminalFrame) {
			frame.Seed.SourcePostDigest = testDigestA
		},
		"source mutable": func(frame *TerminalFrame) {
			frame.Seed.SourceImmutable = false
		},
		"missing seed": func(frame *TerminalFrame) {
			frame.Seed = nil
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			frame := validTerminalForTest(ScenarioSeedFirst)
			mutate(&frame)
			if _, err := MarshalTerminalFrame(frame); !errors.Is(
				err,
				ErrInvalidProtocol,
			) {
				t.Fatalf(
					"MarshalTerminalFrame() error = %v, want ErrInvalidProtocol",
					err,
				)
			}
		})
	}
}

func TestDigestConstructorsMatchClosedGoldenValues(t *testing.T) {
	t.Parallel()

	zero := strings.Repeat("00", 32)
	one := strings.Repeat("11", 32)
	two := strings.Repeat("22", 32)
	three := strings.Repeat("33", 32)
	four := strings.Repeat("44", 32)
	five := strings.Repeat("55", 32)

	cycle, err := DeriveCycleRunDigest(zero, CycleOneJob, 0)
	if err != nil ||
		cycle != "66d08963e0ffbdbb6ed9d37a975bd83ac51ffd58223a737a6fe689c740c7e2d1" {
		t.Fatalf("DeriveCycleRunDigest() = %q, %v", cycle, err)
	}
	restart, err := DeriveRestartCycleRunDigest(
		one,
		SetupStageRunnerCreate,
		9,
	)
	if err != nil ||
		restart != "ccdccd4db9cf591de924cb6a9cdbbb5618277d8d67ca0161534fb02821964680" {
		t.Fatalf("DeriveRestartCycleRunDigest() = %q, %v", restart, err)
	}
	marker, err := DeriveJobMarkerDigest(cycle, one)
	if err != nil ||
		marker != "4169a7cbb5395142dcc56268196f5b0ba59d30bd5be96d93cc1f1d05757ae749" {
		t.Fatalf("DeriveJobMarkerDigest() = %q, %v", marker, err)
	}
	proxy, err := DeriveProxyRequestDigest(
		cycle,
		one,
		two,
		three,
		four,
	)
	if err != nil ||
		proxy != "8f2f64ac4416662aae27db6de267068cd34148b65440769ce669b4ca0558c8a2" {
		t.Fatalf("DeriveProxyRequestDigest() = %q, %v", proxy, err)
	}
	response, err := DeriveResponseBodyProofDigest(
		cycle,
		one,
		four,
		five,
	)
	if err != nil ||
		response != "d9bcfd8b1e580616f87830b8f6398d134df42339b62c247d8773f52029516e1b" {
		t.Fatalf("DeriveResponseBodyProofDigest() = %q, %v", response, err)
	}
	terminal, err := MarshalTerminalFrame(
		validTerminalForTest(ScenarioOneJob),
	)
	if err != nil {
		t.Fatalf("MarshalTerminalFrame: %v", err)
	}
	completion, err := DeriveJobCompletionDigest(cycle, marker, terminal)
	if err != nil ||
		completion != "54308466d5eb98de99029961823f881725a6800e1d0247025e176f0a87e96bcb" {
		t.Fatalf("DeriveJobCompletionDigest() = %q, %v", completion, err)
	}
	deregistration, err := DeriveDeregistrationDigest(
		cycle,
		marker,
		terminal,
	)
	if err != nil ||
		deregistration != "cf9c83297c132715eac11dd4833bf032d009bd62aeff7a58aee882b472a75cf1" {
		t.Fatalf("DeriveDeregistrationDigest() = %q, %v", deregistration, err)
	}
	cleanup, err := DeriveCleanupDigest(cycle)
	if err != nil ||
		cleanup != "0191dcb02cad6d1334181a7691371f35812738920e21fa359ca0b1ea454664e3" {
		t.Fatalf("DeriveCleanupDigest() = %q, %v", cleanup, err)
	}
	observation := validCleanupObservationForTest()
	observationDocument, err := MarshalCleanupObservation(observation)
	if err != nil {
		t.Fatalf("MarshalCleanupObservation: %v", err)
	}
	const wantObservation = `{"schema_version":1,"protocol_id":"portable-ghar-task11-synthetic-v1","cycle_run_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","cleanup_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","cgroup_version":"2","containers_absent":true,"cgroups_absent":true,"tmpfs_absent":true,"work_absent":true,"work_update_absent":true,"processes_absent":true,"namespaces_absent":true,"sockets_absent":true,"authorities_absent":true,"temporary_files_absent":true,"host_backed_work_absent":true,"unexpected_objects_absent":true,"payload_version_count":1,"assertion_count":13}`
	if string(observationDocument) != wantObservation {
		t.Fatalf(
			"cleanup observation = %q, want %q",
			observationDocument,
			wantObservation,
		)
	}
	observationDigest, err := DeriveCleanupObservationDigest(observation)
	if err != nil ||
		observationDigest != "71c78ad79704f5f064bb1da8950620e1599744a97f89f180673aba81505b704b" {
		t.Fatalf("DeriveCleanupObservationDigest() = %q, %v", observationDigest, err)
	}
	postrelease, err := DerivePostreleaseResolutionEvidence(
		cycle,
		observationDigest,
	)
	if err != nil ||
		postrelease != "7bf8876858b71d91c72bd42ee367fd26546b7c7112e0a9b6a9af9b12f64bcaea" {
		t.Fatalf(
			"DerivePostreleaseResolutionEvidence() = %q, %v",
			postrelease,
			err,
		)
	}
	if got := SeedSourceDigest(SeedSourceBytes()); got != SeedSourceSHA256 {
		t.Fatalf("SeedSourceDigest() = %q, want %q", got, SeedSourceSHA256)
	}
	if got := SeedCopyDigest(SeedSourceBytes()); got != SeedSourceSHA256 {
		t.Fatalf("SeedCopyDigest() = %q, want %q", got, SeedSourceSHA256)
	}
	if got := DeriveSeedMutationDigest(SeedSourceBytes()); got != SeedMutationSHA256 {
		t.Fatalf("DeriveSeedMutationDigest() = %q, want %q", got, SeedMutationSHA256)
	}
}

func TestDigestConstructorsRejectInvalidBindings(t *testing.T) {
	t.Parallel()

	valid := testDigestA
	if _, err := DeriveCycleRunDigest("ABC", CycleOneJob, 0); !errors.Is(
		err,
		ErrInvalidProtocol,
	) {
		t.Fatalf("invalid primary digest error = %v", err)
	}
	if _, err := DeriveCycleRunDigest(valid, CycleKind("unknown"), 0); !errors.Is(
		err,
		ErrInvalidProtocol,
	) {
		t.Fatalf("invalid cycle kind error = %v", err)
	}
	if _, err := DeriveRestartCycleRunDigest(
		valid,
		SetupStageRunnerCreate,
		8,
	); !errors.Is(err, ErrInvalidProtocol) {
		t.Fatalf("mismatched setup index error = %v", err)
	}
	if _, err := DeriveJobMarkerDigest(valid, "not-a-nonce"); !errors.Is(
		err,
		ErrInvalidProtocol,
	) {
		t.Fatalf("invalid nonce error = %v", err)
	}
	if _, err := DeriveJobCompletionDigest(
		valid,
		testDigestB,
		[]byte(`{"terminal":"fixture"}`),
	); !errors.Is(err, ErrInvalidProtocol) {
		t.Fatalf("terminal without LF error = %v", err)
	}
	invalidObservation := validCleanupObservationForTest()
	invalidObservation.ProcessesAbsent = false
	if _, err := DeriveCleanupObservationDigest(
		invalidObservation,
	); !errors.Is(err, ErrInvalidProtocol) {
		t.Fatalf("incomplete cleanup observation error = %v", err)
	}
	if _, err := ParseCleanupObservation(
		[]byte("{ " + `"schema_version":1}`),
	); !errors.Is(err, ErrInvalidProtocol) {
		t.Fatalf("noncanonical cleanup observation parse error = %v", err)
	}
}

func TestClosedRegistriesAreCompleteAndDefensive(t *testing.T) {
	t.Parallel()

	wantScenarios := []Scenario{
		ScenarioOneJob,
		ScenarioCleanupSuccess,
		ScenarioCleanupListenerCrash,
		ScenarioCleanupUpgradeInterruption,
		ScenarioReclamation,
		ScenarioSeedFirst,
		ScenarioSeedSecond,
	}
	if got := Scenarios(); !equalScenarios(got, wantScenarios) {
		t.Fatalf("Scenarios() = %v, want %v", got, wantScenarios)
	}
	gotScenarios := Scenarios()
	gotScenarios[0] = Scenario("mutated")
	if got := Scenarios(); !equalScenarios(got, wantScenarios) {
		t.Fatalf("Scenarios() shared mutable storage: %v", got)
	}

	wantResources := []Resource{
		ResourceMemoryBytes,
		ResourceSwapBytes,
		ResourceRunnerTmpfsBytes,
		ResourceTmpBytes,
		ResourceScratchBytes,
		ResourceContainers,
		ResourceProcesses,
		ResourceFileDescriptors,
		ResourceNamespaces,
		ResourceConntrackRows,
		ResourceInodes,
	}
	if got := Resources(); !equalResources(got, wantResources) {
		t.Fatalf("Resources() = %v, want %v", got, wantResources)
	}
	gotResources := Resources()
	gotResources[0] = Resource("mutated")
	if got := Resources(); !equalResources(got, wantResources) {
		t.Fatalf("Resources() shared mutable storage: %v", got)
	}

	stages := RestartSetupStages()
	if len(stages) != 16 ||
		stages[0] != SetupStageAdapterCreate ||
		stages[9] != SetupStageRunnerCreate ||
		stages[15] != SetupStageRunnerAuthorize {
		t.Fatalf("RestartSetupStages() = %v", stages)
	}
	stages[0] = SetupStage("mutated")
	if RestartSetupStages()[0] != SetupStageAdapterCreate {
		t.Fatal("RestartSetupStages() shared mutable storage")
	}
}

func validInputForTest(scenario Scenario) Input {
	input := Input{
		SchemaVersion:  SchemaVersion,
		ProtocolID:     ProtocolID,
		Scenario:       scenario,
		CycleRunDigest: testDigestA,
		Nonce:          testDigestB,
		Sentinel: Sentinel{
			URL:                  "https://example.com/probe",
			Host:                 "example.com",
			Port:                 443,
			HostIdentityDigest:   testDigestC,
			SPKIDigest:           testDigestD,
			CertificateDigest:    testDigestE,
			PolicyEntryDigest:    testDigestF,
			PolicyEvidenceDigest: testDigestA,
			ResponseBodyDigest:   testDigestB,
		},
	}
	if scenario == ScenarioSeedFirst || scenario == ScenarioSeedSecond {
		input.SeedID = SeedID
	}
	return input
}

func validBoundaryForTest(scenario Scenario) BoundaryFrame {
	boundary := BoundaryListenerReady
	upgrade := false
	switch scenario {
	case ScenarioCleanupListenerCrash:
		boundary = BoundaryListenerCrashArmed
	case ScenarioCleanupUpgradeInterruption:
		boundary = BoundaryUpgradeInterruptionArmed
		upgrade = true
	}
	frame := BoundaryFrame{
		SchemaVersion:                SchemaVersion,
		ProtocolID:                   ProtocolID,
		Frame:                        FrameBoundary,
		Scenario:                     scenario,
		CycleRunDigest:               testDigestA,
		JobMarkerDigest:              testDigestB,
		Boundary:                     boundary,
		SyntheticTokenAbsent:         true,
		ImmutablePayloadCount:        1,
		UpgradeInterruptionExercised: upgrade,
		CgroupVersion:                CgroupV2,
	}
	if scenario == ScenarioSeedFirst || scenario == ScenarioSeedSecond {
		frame.SeedID = SeedID
	}
	return frame
}

func validTerminalForTest(scenario Scenario) TerminalFrame {
	resources := Resources()
	observations := make([]ResourceHighWater, len(resources))
	for index, resource := range resources {
		observations[index] = ResourceHighWater{
			Resource:  resource,
			HighWater: uint64(index + 1),
		}
	}
	frame := TerminalFrame{
		SchemaVersion:                SchemaVersion,
		ProtocolID:                   ProtocolID,
		Frame:                        FrameTerminal,
		Scenario:                     scenario,
		CycleRunDigest:               testDigestA,
		JobMarkerDigest:              testDigestB,
		Outcome:                      OutcomeCompleted,
		ProxyRequestDigest:           testDigestC,
		ResponseBodyProofDigest:      testDigestD,
		RegistrationRemoved:          true,
		SyntheticTokenAbsent:         true,
		ImmutablePayloadCount:        1,
		UpgradeInterruptionExercised: false,
		CgroupVersion:                CgroupV2,
		Resources:                    observations,
	}
	if scenario == ScenarioSeedFirst || scenario == ScenarioSeedSecond {
		frame.Seed = validSeedProofForTest(scenario)
	}
	return frame
}

func validSeedProofForTest(scenario Scenario) *SeedProof {
	return &SeedProof{
		SeedID:           SeedID,
		SourceDigest:     SeedSourceSHA256,
		CopyDigest:       SeedSourceSHA256,
		MutationDigest:   SeedMutationSHA256,
		SourcePostDigest: SeedSourceSHA256,
		MutationAbsent:   scenario == ScenarioSeedSecond,
		SourceImmutable:  true,
	}
}

func validStreamBindingForTest(scenario Scenario) StreamBinding {
	return StreamBinding{
		Scenario:        scenario,
		CycleRunDigest:  testDigestA,
		JobMarkerDigest: testDigestB,
		CgroupVersion:   CgroupV2,
	}
}

func validCleanupObservationForTest() CleanupObservation {
	return CleanupObservation{
		SchemaVersion:           SchemaVersion,
		ProtocolID:              ProtocolID,
		CycleRunDigest:          testDigestA,
		CleanupDigest:           testDigestB,
		CgroupVersion:           CgroupV2,
		ContainersAbsent:        true,
		CgroupsAbsent:           true,
		TmpfsAbsent:             true,
		WorkAbsent:              true,
		WorkUpdateAbsent:        true,
		ProcessesAbsent:         true,
		NamespacesAbsent:        true,
		SocketsAbsent:           true,
		AuthoritiesAbsent:       true,
		TemporaryFilesAbsent:    true,
		HostBackedWorkAbsent:    true,
		UnexpectedObjectsAbsent: true,
		PayloadVersionCount:     1,
		AssertionCount:          13,
	}
}

func validNormalDocumentsForTest(
	t *testing.T,
	scenario Scenario,
) ([]byte, []byte) {
	t.Helper()
	boundary, err := MarshalBoundaryFrame(validBoundaryForTest(scenario))
	if err != nil {
		t.Fatalf("MarshalBoundaryFrame(%s): %v", scenario, err)
	}
	terminal, terminalErr := MarshalTerminalFrame(
		validTerminalForTest(ScenarioOneJob),
	)
	if terminalErr != nil {
		t.Fatalf("MarshalTerminalFrame: %v", terminalErr)
	}
	return boundary, terminal
}

func terminalFramesEqual(left, right TerminalFrame) bool {
	leftDocument, leftErr := MarshalTerminalFrame(left)
	rightDocument, rightErr := MarshalTerminalFrame(right)
	return leftErr == nil &&
		rightErr == nil &&
		bytes.Equal(leftDocument, rightDocument)
}

func equalScenarios(left, right []Scenario) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalResources(left, right []Resource) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
