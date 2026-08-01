package main

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/linuxcap"
)

func TestRunApplyRestoresAndReadsBackBothFamiliesBeforeProof(t *testing.T) {
	artifact := helperTestArtifact(t, hostruntime.PolicyIPv6DenyViaIP6Tables)
	frame, err := hostruntime.EncodePolicyArtifact(artifact)
	if err != nil {
		t.Fatalf("EncodePolicyArtifact: %v", err)
	}
	var events []string
	runtime := helperRuntime{
		ioTimeout:   time.Second,
		xtablesLock: func() string { return "/run/xtables.lock" },
		capabilities: func() (linuxcap.Wire, error) {
			return helperNetAdminCapabilities(), nil
		},
		restore: func(_ context.Context, family policyFamily, program []byte) error {
			events = append(events, "restore:"+family.String())
			want := artifact.IPv4Program()
			if family == familyIPv6 {
				want = artifact.IPv6Program()
			}
			if !bytes.Equal(program, want) {
				t.Fatalf("restore(%s) program drifted", family)
			}
			return nil
		},
		save: func(_ context.Context, family policyFamily) ([]byte, error) {
			events = append(events, "save:"+family.String())
			if family == familyIPv6 {
				return artifact.IPv6Program(), nil
			}
			return artifact.IPv4Program(), nil
		},
		disableIPv6: func() error {
			t.Fatal("dual-stack policy attempted to disable IPv6")
			return nil
		},
	}
	var stdout, stderr bytes.Buffer
	if code := run(
		[]string{"apply"},
		bytes.NewReader(frame),
		&stdout,
		&stderr,
		runtime,
	); code != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !slices.Equal(events, []string{
		"restore:ipv4", "save:ipv4", "restore:ipv6", "save:ipv6",
	}) {
		t.Fatalf("events=%q", events)
	}
	want := `{"version":2,"policy_digest":"` + artifact.Digest() +
		`","ipv6_posture":"deny-via-ip6tables","capabilities":{` +
		`"effective":"0000000000001000","permitted":"0000000000001000",` +
		`"inheritable":"0000000000000000","bounding":"0000000000001000",` +
		`"ambient":"0000000000000000"}}` + "\n"
	if stdout.String() != want || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunApplyKernelDisabledProvesPostureAndOmitsIP6Tables(t *testing.T) {
	artifact := helperTestArtifact(t, hostruntime.PolicyIPv6KernelDisabled)
	frame, err := hostruntime.EncodePolicyArtifact(artifact)
	if err != nil {
		t.Fatalf("EncodePolicyArtifact: %v", err)
	}
	ipv6Disabled := 0
	runtime := helperRuntime{
		ioTimeout:   time.Second,
		xtablesLock: func() string { return "/run/xtables.lock" },
		capabilities: func() (linuxcap.Wire, error) {
			return helperNetAdminCapabilities(), nil
		},
		restore: func(_ context.Context, family policyFamily, _ []byte) error {
			if family != familyIPv4 {
				t.Fatal("kernel-disabled policy invoked IPv6 restore")
			}
			return nil
		},
		save: func(_ context.Context, family policyFamily) ([]byte, error) {
			if family != familyIPv4 {
				t.Fatal("kernel-disabled policy invoked IPv6 save")
			}
			return artifact.IPv4Program(), nil
		},
		disableIPv6: func() error {
			ipv6Disabled++
			return nil
		},
	}
	var stdout, stderr bytes.Buffer
	if code := run(
		[]string{"apply"},
		bytes.NewReader(frame),
		&stdout,
		&stderr,
		runtime,
	); code != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if ipv6Disabled != 1 ||
		!strings.Contains(stdout.String(), `"ipv6_posture":"kernel-disabled"`) {
		t.Fatalf("disable calls=%d stdout=%q", ipv6Disabled, stdout.String())
	}
}

func TestProveIPv6DisabledReadsBothNamespaceValues(t *testing.T) {
	wantPaths := []string{
		"/proc/sys/net/ipv6/conf/all/disable_ipv6",
		"/proc/sys/net/ipv6/conf/default/disable_ipv6",
	}
	var gotPaths []string
	err := proveIPv6Disabled(func(path string) ([]byte, error) {
		gotPaths = append(gotPaths, path)
		return []byte("1\n"), nil
	})
	if err != nil {
		t.Fatalf("proveIPv6Disabled: %v", err)
	}
	if !slices.Equal(gotPaths, wantPaths) {
		t.Fatalf("read paths = %q, want %q", gotPaths, wantPaths)
	}
	if err := proveIPv6Disabled(func(string) ([]byte, error) {
		return []byte("0\n"), nil
	}); err == nil {
		t.Fatal("proveIPv6Disabled accepted an enabled namespace value")
	}
}

func TestRunApplyRejectsCapabilityProfilesOtherThanNetAdminOnly(t *testing.T) {
	artifact := helperTestArtifact(t, hostruntime.PolicyIPv6DenyViaIP6Tables)
	frame, err := hostruntime.EncodePolicyArtifact(artifact)
	if err != nil {
		t.Fatalf("EncodePolicyArtifact: %v", err)
	}
	for name, capabilities := range map[string]linuxcap.Wire{
		"empty": {},
		"extra effective bit": func() linuxcap.Wire {
			wire := helperNetAdminCapabilities()
			wire.Effective = "0000000000001001"
			return wire
		}(),
		"ambient bit": func() linuxcap.Wire {
			wire := helperNetAdminCapabilities()
			wire.Ambient = "0000000000001000"
			return wire
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			called := false
			runtime := helperRuntime{
				ioTimeout:   time.Second,
				xtablesLock: func() string { return "/run/xtables.lock" },
				capabilities: func() (linuxcap.Wire, error) {
					return capabilities, nil
				},
				restore: func(context.Context, policyFamily, []byte) error {
					called = true
					return nil
				},
				save: func(context.Context, policyFamily) ([]byte, error) {
					called = true
					return nil, nil
				},
				disableIPv6: func() error {
					called = true
					return nil
				},
			}
			var stdout, stderr bytes.Buffer
			if code := run(
				[]string{"apply"},
				bytes.NewReader(frame),
				&stdout,
				&stderr,
				runtime,
			); code != 1 || called || stdout.Len() != 0 {
				t.Fatalf(
					"code=%d called=%v stdout=%q stderr=%q",
					code,
					called,
					stdout.String(),
					stderr.String(),
				)
			}
		})
	}
}

func TestCanonicalSavedPolicyAcceptsOnlyPinnedSaveWrapper(t *testing.T) {
	program := helperTestProgram()
	wrapped := append(
		[]byte("# Generated by iptables-save v1.8.9 (legacy) on synthetic\n"),
		program...,
	)
	wrapped = append(wrapped, []byte("# Completed on synthetic\n")...)
	got, err := canonicalSavedPolicy(wrapped)
	if err != nil {
		t.Fatalf("canonicalSavedPolicy(valid): %v", err)
	}
	if !bytes.Equal(got, program) {
		t.Fatalf("canonicalSavedPolicy(valid) = %q, want %q", got, program)
	}
	for name, document := range map[string][]byte{
		"unexpected comment": append(
			[]byte("# untrusted\n"),
			program...,
		),
		"missing completion": append(
			[]byte("# Generated by iptables-save v1.8.9 (legacy) on synthetic\n"),
			program...,
		),
		"counter drift": bytes.Replace(
			wrapped,
			[]byte(":INPUT DROP [0:0]"),
			[]byte(":INPUT DROP [1:1]"),
			1,
		),
		"trailing table": append(
			append([]byte{}, wrapped...),
			[]byte("*raw\nCOMMIT\n")...,
		),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := canonicalSavedPolicy(document); err == nil {
				t.Fatal("canonicalSavedPolicy accepted invalid readback")
			}
		})
	}
}

func TestRunApplyFailsClosedBeforeProof(t *testing.T) {
	artifact := helperTestArtifact(t, hostruntime.PolicyIPv6DenyViaIP6Tables)
	frame, err := hostruntime.EncodePolicyArtifact(artifact)
	if err != nil {
		t.Fatalf("EncodePolicyArtifact: %v", err)
	}
	tests := []struct {
		name    string
		frame   []byte
		runtime helperRuntime
	}{
		{
			name:  "wrong lock",
			frame: frame,
			runtime: helperRuntime{
				xtablesLock: func() string { return "/tmp/other" },
			},
		},
		{
			name:  "restore failure",
			frame: frame,
			runtime: helperRuntime{
				xtablesLock: func() string { return "/run/xtables.lock" },
				restore: func(context.Context, policyFamily, []byte) error {
					return errors.New("synthetic")
				},
			},
		},
		{
			name:  "readback mismatch",
			frame: frame,
			runtime: helperRuntime{
				xtablesLock: func() string { return "/run/xtables.lock" },
				restore:     func(context.Context, policyFamily, []byte) error { return nil },
				save: func(context.Context, policyFamily) ([]byte, error) {
					return []byte("*filter\nCOMMIT\n"), nil
				},
			},
		},
		{
			name:  "trailing frame",
			frame: append(append([]byte{}, frame...), 'x'),
			runtime: helperRuntime{
				xtablesLock: func() string { return "/run/xtables.lock" },
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(
				[]string{"apply"},
				bytes.NewReader(test.frame),
				&stdout,
				&stderr,
				test.runtime,
			); code != 1 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if stdout.Len() != 0 ||
				stderr.String() != "portable-ghar-network-helper: unavailable\n" {
				t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
	}
}

func helperTestArtifact(
	t *testing.T,
	posture hostruntime.PolicyIPv6Posture,
) hostruntime.PolicyArtifact {
	t.Helper()
	ipv4 := helperTestProgram()
	var ipv6 []byte
	if posture == hostruntime.PolicyIPv6DenyViaIP6Tables {
		ipv6 = helperTestProgram()
	}
	artifact, err := hostruntime.NewPolicyArtifact(
		ipv4,
		ipv6,
		[]byte("{\"version\":1}\n"),
		posture,
	)
	if err != nil {
		t.Fatalf("NewPolicyArtifact: %v", err)
	}
	return artifact
}

func helperTestProgram() []byte {
	return []byte(
		"*filter\n" +
			":INPUT DROP [0:0]\n" +
			":FORWARD DROP [0:0]\n" +
			":OUTPUT DROP [0:0]\n" +
			"-A INPUT -i lo -j ACCEPT\n" +
			"-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n" +
			"-A OUTPUT -o lo -j ACCEPT\n" +
			"-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n" +
			"COMMIT\n",
	)
}

func helperNetAdminCapabilities() linuxcap.Wire {
	return linuxcap.Wire{
		Effective:   "0000000000001000",
		Permitted:   "0000000000001000",
		Inheritable: "0000000000000000",
		Bounding:    "0000000000001000",
		Ambient:     "0000000000000000",
	}
}
