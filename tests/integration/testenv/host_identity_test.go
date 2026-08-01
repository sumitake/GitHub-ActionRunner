package testenv

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"golang.org/x/sys/unix"
)

func TestExecutionHostIdentityUsesExactCanonicalPreimage(t *testing.T) {
	t.Parallel()

	input := validExecutionHostIdentityInput()
	document, digest, err := computeExecutionHostIdentity(input)
	if err != nil {
		t.Fatalf("computeExecutionHostIdentity: %v", err)
	}
	wantDocument := `{"schema_version":1,"operating_system":"linux","architecture":"amd64","euid":1000,"fixture_parent_device":7,"fixture_parent_inode":11,"docker_binary_device":9,"docker_binary_inode":13,"docker_server_observation_digest":"` +
		strings.Repeat("a", 64) + `"}`
	if string(document) != wantDocument {
		t.Fatalf("canonical document = %q, want %q", document, wantDocument)
	}
	const wantDigest = "a9113dee8c0ae630f657e3d749e96f8abdbf063897cee12afcc718178f614913"
	if digest != wantDigest {
		t.Fatalf("digest = %s, want %s", digest, wantDigest)
	}
}

func TestExecutionHostIdentityRejectsInvalidAndChangesOnEveryField(
	t *testing.T,
) {
	t.Parallel()

	base := validExecutionHostIdentityInput()
	_, baseDigest, err := computeExecutionHostIdentity(base)
	if err != nil {
		t.Fatalf("compute base: %v", err)
	}
	mutations := map[string]func(*executionHostIdentityWire){
		"schema": func(value *executionHostIdentityWire) {
			value.SchemaVersion++
		},
		"operating system": func(value *executionHostIdentityWire) {
			value.OperatingSystem = "darwin"
		},
		"architecture": func(value *executionHostIdentityWire) {
			value.Architecture = "arm64"
		},
		"euid": func(value *executionHostIdentityWire) {
			value.EUID++
		},
		"parent device": func(value *executionHostIdentityWire) {
			value.FixtureParentDevice++
		},
		"parent inode": func(value *executionHostIdentityWire) {
			value.FixtureParentInode++
		},
		"docker device": func(value *executionHostIdentityWire) {
			value.DockerBinaryDevice++
		},
		"docker inode": func(value *executionHostIdentityWire) {
			value.DockerBinaryInode++
		},
		"docker observation": func(value *executionHostIdentityWire) {
			value.DockerServerObservationDigest = strings.Repeat("b", 64)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			_, digest, err := computeExecutionHostIdentity(candidate)
			if name == "schema" || name == "operating system" {
				if err == nil {
					t.Fatal("invalid identity field was accepted")
				}
				return
			}
			if err != nil {
				t.Fatalf("compute mutated identity: %v", err)
			}
			if digest == baseDigest {
				t.Fatal("field mutation preserved identity digest")
			}
		})
	}

	for name, mutate := range map[string]func(*executionHostIdentityWire){
		"unknown architecture": func(value *executionHostIdentityWire) {
			value.Architecture = "ppc64"
		},
		"zero parent device": func(value *executionHostIdentityWire) {
			value.FixtureParentDevice = 0
		},
		"zero parent inode": func(value *executionHostIdentityWire) {
			value.FixtureParentInode = 0
		},
		"zero docker device": func(value *executionHostIdentityWire) {
			value.DockerBinaryDevice = 0
		},
		"zero docker inode": func(value *executionHostIdentityWire) {
			value.DockerBinaryInode = 0
		},
		"invalid observation": func(value *executionHostIdentityWire) {
			value.DockerServerObservationDigest = "not-a-digest"
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			if _, _, err := computeExecutionHostIdentity(candidate); err == nil {
				t.Fatal("invalid identity was accepted")
			}
		})
	}
}

func TestExecutionHostFileIdentityRulesFailClosed(t *testing.T) {
	t.Parallel()

	parent := executionHostFileIdentity{
		Device: 7,
		Inode:  11,
		Mode:   unix.S_IFDIR | 0o700,
		NLink:  2,
	}
	if !validFixtureParentIdentity(parent, 7, 11) {
		t.Fatal("valid fixture parent was rejected")
	}
	for name, candidate := range map[string]executionHostFileIdentity{
		"wrong device": {Device: 8, Inode: 11, Mode: unix.S_IFDIR | 0o700, NLink: 2},
		"wrong inode":  {Device: 7, Inode: 12, Mode: unix.S_IFDIR | 0o700, NLink: 2},
		"regular":      {Device: 7, Inode: 11, Mode: unix.S_IFREG | 0o700, NLink: 1},
		"symlink":      {Device: 7, Inode: 11, Mode: unix.S_IFLNK | 0o700, NLink: 1},
	} {
		t.Run("parent "+name, func(t *testing.T) {
			if validFixtureParentIdentity(candidate, 7, 11) {
				t.Fatal("unsafe fixture parent was accepted")
			}
		})
	}

	docker := executionHostFileIdentity{
		Device: 9,
		Inode:  13,
		Mode:   unix.S_IFREG | 0o500,
		NLink:  1,
	}
	if !validDockerBinaryIdentity(docker) {
		t.Fatal("valid Docker binary was rejected")
	}
	for name, candidate := range map[string]executionHostFileIdentity{
		"symlink":     {Device: 9, Inode: 13, Mode: unix.S_IFLNK | 0o500, NLink: 1},
		"directory":   {Device: 9, Inode: 13, Mode: unix.S_IFDIR | 0o500, NLink: 1},
		"not exec":    {Device: 9, Inode: 13, Mode: unix.S_IFREG | 0o400, NLink: 1},
		"group write": {Device: 9, Inode: 13, Mode: unix.S_IFREG | 0o520, NLink: 1},
		"other write": {Device: 9, Inode: 13, Mode: unix.S_IFREG | 0o502, NLink: 1},
		"multilink":   {Device: 9, Inode: 13, Mode: unix.S_IFREG | 0o500, NLink: 2},
	} {
		t.Run("docker "+name, func(t *testing.T) {
			if validDockerBinaryIdentity(candidate) {
				t.Fatal("unsafe Docker binary was accepted")
			}
		})
	}
}

type scriptedExecutionHostStatSource struct {
	identities map[string][]executionHostFileIdentity
	err        error
}

func (s *scriptedExecutionHostStatSource) Lstat(
	path string,
) (executionHostFileIdentity, error) {
	if s.err != nil {
		return executionHostFileIdentity{}, s.err
	}
	values := s.identities[path]
	if len(values) == 0 {
		return executionHostFileIdentity{}, errors.New("unexpected stat")
	}
	value := values[0]
	s.identities[path] = values[1:]
	return value, nil
}

func TestObserveExecutionHostIdentityRechecksFilesAndExpectedAnchor(
	t *testing.T,
) {
	t.Parallel()

	parent := executionHostFileIdentity{
		Device: 7,
		Inode:  11,
		Mode:   unix.S_IFDIR | 0o700,
		NLink:  2,
	}
	docker := executionHostFileIdentity{
		Device: 9,
		Inode:  13,
		Mode:   unix.S_IFREG | 0o500,
		NLink:  1,
	}
	commandRunner := &scriptedClosedRunner{result: hostruntime.Result{
		Stdout: []byte(`{"Version":"1.2.3"}`),
	}}
	session, err := newPreflightSession(closedCommandConfig{
		DockerPath:   "/usr/bin/docker",
		FixtureRoot:  "/private/tmp/portable-ghar-fixture",
		MaximumBytes: 1024,
	}, commandRunner)
	if err != nil {
		t.Fatalf("newPreflightSession: %v", err)
	}
	statSource := func() *scriptedExecutionHostStatSource {
		return &scriptedExecutionHostStatSource{
			identities: map[string][]executionHostFileIdentity{
				"/private/tmp":    {parent, parent},
				"/usr/bin/docker": {docker, docker},
			},
		}
	}
	config := executionHostObservationConfig{
		OperatingSystem:       "linux",
		Architecture:          "amd64",
		EUID:                  1000,
		FixtureParentPath:     "/private/tmp",
		FixtureParentDevice:   7,
		FixtureParentInode:    11,
		DockerBinaryPath:      "/usr/bin/docker",
		ExpectedTargetDigest:  "",
		ExpectedControlDigest: strings.Repeat("b", 64),
	}
	first, err := observeExecutionHostIdentity(
		context.Background(),
		config,
		statSource(),
		session,
	)
	if err == nil {
		t.Fatal("empty expected target digest was accepted")
	}
	config.ExpectedTargetDigest = first

	// Compute the anchor independently from the typed closed-command digest.
	commandDigest := closedCommandDigestForTest(
		ClosedDockerServerVersion,
		[]byte(`{"Version":"1.2.3"}`),
	)
	_, expected, err := computeExecutionHostIdentity(executionHostIdentityWire{
		SchemaVersion:                 1,
		OperatingSystem:               "linux",
		Architecture:                  "amd64",
		EUID:                          1000,
		FixtureParentDevice:           7,
		FixtureParentInode:            11,
		DockerBinaryDevice:            9,
		DockerBinaryInode:             13,
		DockerServerObservationDigest: commandDigest,
	})
	if err != nil {
		t.Fatalf("compute expected identity: %v", err)
	}
	config.ExpectedTargetDigest = expected
	commandRunner.result.Stdout = []byte(`{"Version":"1.2.3"}`)
	got, err := observeExecutionHostIdentity(
		context.Background(),
		config,
		statSource(),
		session,
	)
	if err != nil {
		t.Fatalf("observeExecutionHostIdentity: %v", err)
	}
	if got != expected {
		t.Fatalf("identity = %s, want %s", got, expected)
	}

	replaced := statSource()
	replaced.identities["/usr/bin/docker"][1].Inode++
	commandRunner.result.Stdout = []byte(`{"Version":"1.2.3"}`)
	if _, err := observeExecutionHostIdentity(
		context.Background(),
		config,
		replaced,
		session,
	); err == nil {
		t.Fatal("Docker binary replacement was accepted")
	}

	sameControl := config
	sameControl.ExpectedControlDigest = expected
	commandRunner.result.Stdout = []byte(`{"Version":"1.2.3"}`)
	if _, err := observeExecutionHostIdentity(
		context.Background(),
		sameControl,
		statSource(),
		session,
	); err == nil {
		t.Fatal("same target/control identity was accepted")
	}
}

func closedCommandDigestForTest(
	operation ClosedOperation,
	stdout []byte,
) string {
	runner := &scriptedClosedRunner{
		result: hostruntime.Result{Stdout: append([]byte(nil), stdout...)},
	}
	session, err := newPreflightSession(closedCommandConfig{
		DockerPath:   "/usr/bin/docker",
		FixtureRoot:  "/private/tmp/portable-ghar-fixture",
		MaximumBytes: 1024,
	}, runner)
	if err != nil {
		panic(err)
	}
	observation, err := session.Run(context.Background(), operation)
	if err != nil {
		panic(err)
	}
	return observation.Digest
}

func validExecutionHostIdentityInput() executionHostIdentityWire {
	return executionHostIdentityWire{
		SchemaVersion:                 1,
		OperatingSystem:               "linux",
		Architecture:                  "amd64",
		EUID:                          1000,
		FixtureParentDevice:           7,
		FixtureParentInode:            11,
		DockerBinaryDevice:            9,
		DockerBinaryInode:             13,
		DockerServerObservationDigest: strings.Repeat("a", 64),
	}
}
