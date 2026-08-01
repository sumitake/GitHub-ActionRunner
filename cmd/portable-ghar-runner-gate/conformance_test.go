package main

import (
	"bytes"
	"errors"
	"math"
	"syscall"
	"testing"

	"github.com/sumitake/portable-ghar/internal/linuxcap"
	"github.com/sumitake/portable-ghar/internal/networkjail"
)

func TestRunConformanceObserveEmitsExactCanonicalWire(t *testing.T) {
	wire := completeRunnerConformanceWire()
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"conformance-observe"},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
		gateRuntime{
			observeConformance: func() (runnerConformanceWire, error) {
				return wire, nil
			},
		},
	)
	want := `{"version":1,"euid":65532,"egid":65532,` +
		`"capabilities":{"effective":"0000000000000000",` +
		`"permitted":"0000000000000000","inheritable":"0000000000000000",` +
		`"bounding":"0000000000000000","ambient":"0000000000000000"},` +
		`"raw_socket_denied":true,"bpf_denied":true,"unshare_denied":true,` +
		`"setns_denied":true,"clone3_denied":true,"namespace_denied":true,` +
		`"proc_sys_read_only":true,"proc_masks_present":true,` +
		`"controller_database_absent":true,"docker_authority_absent":true,` +
		`"host_control_absent":true,"secret_environment_absent":true,` +
		`"jit_environment_absent":true,"synthetic_token_absent":true}` + "\n"
	if code != 0 || stdout.String() != want || stderr.Len() != 0 {
		t.Fatalf(
			"code=%d stdout=%q stderr=%q",
			code,
			stdout.String(),
			stderr.String(),
		)
	}
}

func TestRunConformanceObserveRejectsInputOrFalseSubfact(t *testing.T) {
	for name, configure := range map[string]func(*runnerConformanceWire){
		"raw socket": func(wire *runnerConformanceWire) {
			wire.RawSocketDenied = false
		},
		"proc sys": func(wire *runnerConformanceWire) {
			wire.ProcSysReadOnly = false
		},
		"controller database": func(wire *runnerConformanceWire) {
			wire.ControllerDatabaseAbsent = false
		},
		"synthetic token": func(wire *runnerConformanceWire) {
			wire.SyntheticTokenAbsent = false
		},
	} {
		t.Run(name, func(t *testing.T) {
			wire := completeRunnerConformanceWire()
			configure(&wire)
			var stdout, stderr bytes.Buffer
			code := run(
				[]string{"conformance-observe"},
				bytes.NewReader(nil),
				&stdout,
				&stderr,
				gateRuntime{
					observeConformance: func() (runnerConformanceWire, error) {
						return wire, nil
					},
				},
			)
			if code != 1 || stdout.Len() != 0 ||
				stderr.String() != "portable-ghar-runner-gate: unavailable\n" {
				t.Fatalf(
					"code=%d stdout=%q stderr=%q",
					code,
					stdout.String(),
					stderr.String(),
				)
			}
		})
	}

	called := false
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"conformance-observe"},
		bytes.NewBufferString("unexpected"),
		&stdout,
		&stderr,
		gateRuntime{
			observeConformance: func() (runnerConformanceWire, error) {
				called = true
				return completeRunnerConformanceWire(), nil
			},
		},
	)
	if code != 1 || called || stdout.Len() != 0 {
		t.Fatalf(
			"input case code=%d called=%v stdout=%q stderr=%q",
			code,
			called,
			stdout.String(),
			stderr.String(),
		)
	}
}

func TestObserveRunnerConformanceRequiresEveryClosedFact(t *testing.T) {
	valid := validRunnerConformanceProbeRuntime()
	wire, err := observeRunnerConformance(valid)
	if err != nil || wire != completeRunnerConformanceWire() {
		t.Fatalf("valid wire=%+v err=%v", wire, err)
	}

	tests := map[string]func(*runnerConformanceProbeRuntime){
		"uid overflow": func(runtime *runnerConformanceProbeRuntime) {
			runtime.identity = func() (uint64, uint64, error) {
				return math.MaxUint32 + 1, 65532, nil
			}
		},
		"capability": func(runtime *runnerConformanceProbeRuntime) {
			runtime.capabilities = func() (linuxcap.Wire, error) {
				wire := emptyRunnerCapabilities()
				wire.Effective = "0000000000000001"
				return wire, nil
			}
		},
		"raw socket succeeded": func(runtime *runnerConformanceProbeRuntime) {
			runtime.rawSocket = func() error { return nil }
		},
		"raw socket wrong errno": func(runtime *runnerConformanceProbeRuntime) {
			runtime.rawSocket = func() error { return syscall.EINVAL }
		},
		"bpf succeeded": func(runtime *runnerConformanceProbeRuntime) {
			runtime.bpf = func() error { return nil }
		},
		"unshare succeeded": func(runtime *runnerConformanceProbeRuntime) {
			runtime.unshare = func() error { return nil }
		},
		"setns succeeded": func(runtime *runnerConformanceProbeRuntime) {
			runtime.setns = func() error { return nil }
		},
		"clone3 succeeded": func(runtime *runnerConformanceProbeRuntime) {
			runtime.clone3 = func() error { return nil }
		},
		"namespace changed": func(runtime *runnerConformanceProbeRuntime) {
			calls := 0
			runtime.namespace = func() (networkjail.NamespaceIdentity, error) {
				calls++
				return networkjail.NamespaceIdentity{
					Device: 11,
					Inode:  uint64(20 + calls),
				}, nil
			}
		},
		"proc sys writable": func(runtime *runnerConformanceProbeRuntime) {
			runtime.proc = func() (runnerProcFacts, error) {
				return runnerProcFacts{MasksPresent: true}, nil
			}
		},
		"proc mask missing": func(runtime *runnerConformanceProbeRuntime) {
			runtime.proc = func() (runnerProcFacts, error) {
				return runnerProcFacts{SysReadOnly: true}, nil
			}
		},
		"docker authority present": func(runtime *runnerConformanceProbeRuntime) {
			runtime.projections = func() (runnerProjectionFacts, error) {
				facts := validRunnerProjectionFacts()
				facts.DockerAuthorityAbsent = false
				return facts, nil
			}
		},
		"jit environment present": func(runtime *runnerConformanceProbeRuntime) {
			runtime.projections = func() (runnerProjectionFacts, error) {
				facts := validRunnerProjectionFacts()
				facts.JITEnvironmentAbsent = false
				return facts, nil
			}
		},
		"missing probe": func(runtime *runnerConformanceProbeRuntime) {
			runtime.clone3 = nil
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			runtime := validRunnerConformanceProbeRuntime()
			mutate(&runtime)
			if _, err := observeRunnerConformance(runtime); err == nil {
				t.Fatal("invalid conformance facts were accepted")
			}
		})
	}
}

func validRunnerConformanceProbeRuntime() runnerConformanceProbeRuntime {
	namespace := networkjail.NamespaceIdentity{Device: 11, Inode: 22}
	denied := func() error { return syscall.EPERM }
	return runnerConformanceProbeRuntime{
		identity: func() (uint64, uint64, error) {
			return 65532, 65532, nil
		},
		capabilities: func() (linuxcap.Wire, error) {
			return emptyRunnerCapabilities(), nil
		},
		namespace: func() (networkjail.NamespaceIdentity, error) {
			return namespace, nil
		},
		rawSocket: denied,
		bpf:       denied,
		unshare:   denied,
		setns:     denied,
		clone3:    denied,
		proc: func() (runnerProcFacts, error) {
			return runnerProcFacts{SysReadOnly: true, MasksPresent: true}, nil
		},
		projections: func() (runnerProjectionFacts, error) {
			return validRunnerProjectionFacts(), nil
		},
	}
}

func validRunnerProjectionFacts() runnerProjectionFacts {
	return runnerProjectionFacts{
		ControllerDatabaseAbsent: true,
		DockerAuthorityAbsent:    true,
		HostControlAbsent:        true,
		SecretEnvironmentAbsent:  true,
		JITEnvironmentAbsent:     true,
		SyntheticTokenAbsent:     true,
	}
}

func completeRunnerConformanceWire() runnerConformanceWire {
	return runnerConformanceWire{
		Version:                  1,
		EUID:                     65532,
		EGID:                     65532,
		Capabilities:             emptyRunnerCapabilities(),
		RawSocketDenied:          true,
		BPFDenied:                true,
		UnshareDenied:            true,
		SetNSDenied:              true,
		Clone3Denied:             true,
		NamespaceDenied:          true,
		ProcSysReadOnly:          true,
		ProcMasksPresent:         true,
		ControllerDatabaseAbsent: true,
		DockerAuthorityAbsent:    true,
		HostControlAbsent:        true,
		SecretEnvironmentAbsent:  true,
		JITEnvironmentAbsent:     true,
		SyntheticTokenAbsent:     true,
	}
}

func emptyRunnerCapabilities() linuxcap.Wire {
	return linuxcap.Wire{
		Effective:   "0000000000000000",
		Permitted:   "0000000000000000",
		Inheritable: "0000000000000000",
		Bounding:    "0000000000000000",
		Ambient:     "0000000000000000",
	}
}

func TestObserveRunnerConformanceRejectsNonPermissionErrors(t *testing.T) {
	runtime := validRunnerConformanceProbeRuntime()
	runtime.setns = func() error { return errors.New("synthetic") }
	if _, err := observeRunnerConformance(runtime); err == nil {
		t.Fatal("non-permission setns error was accepted")
	}
}
