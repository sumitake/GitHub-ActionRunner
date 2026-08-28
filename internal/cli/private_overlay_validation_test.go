package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

func TestRunPrivateOverlayValidationEmitsMinimalDisabledReceipt(t *testing.T) {
	t.Parallel()

	overlay := hostruntime.PrivateOverlay{
		SchemaVersion: 1,
		Target: hostruntime.TargetIdentityOverlay{
			OS:                        "linux",
			Architecture:              "amd64",
			ExpectedEUID:              0,
			HostIdentityDigest:        strings.Repeat("1", 64),
			ControlHostIdentityDigest: strings.Repeat("2", 64),
			ProfileID:                 "qts-capless-root",
		},
		Policy: hostruntime.PolicyOverlay{AcquisitionDefault: "disabled"},
	}
	revision := strings.Repeat("a", 64)
	receipt, err := RunPrivateOverlayValidation(
		[]string{
			"validate-private-overlay",
			"--private",
			"/private/controller-runtime.json",
		},
		func(path string) (hostruntime.PrivateOverlay, string, error) {
			if path != "/private/controller-runtime.json" {
				t.Fatalf("loader path = %q", path)
			}
			return overlay, revision, nil
		},
	)
	if err != nil {
		t.Fatalf("RunPrivateOverlayValidation() error = %v", err)
	}
	want := PrivateOverlayValidationReceipt{
		SchemaVersion:               1,
		PrivateOverlaySchemaVersion: 1,
		PrivateOverlayRevision:      revision,
		Mode:                        "disabled-observer",
		TargetOS:                    "linux",
		TargetArchitecture:          "amd64",
		ProfileID:                   "qts-capless-root",
	}
	if receipt != want {
		t.Fatalf("receipt = %#v, want %#v", receipt, want)
	}
}

func TestRunPrivateOverlayValidationAcceptsOnlyExactGrammar(t *testing.T) {
	t.Parallel()

	invalid := [][]string{
		nil,
		{"validate-private-overlay"},
		{"validate-private-overlay", "--private", "relative.json"},
		{"validate-private-overlay", "--private=/private/overlay.json"},
		{"validate-private-overlay", "--private", "/private/../overlay.json"},
		{"validate-private-overlay", "--private", "/private/overlay.json", "extra"},
	}
	for _, args := range invalid {
		if _, err := RunPrivateOverlayValidation(
			args,
			func(string) (hostruntime.PrivateOverlay, string, error) {
				t.Fatalf("loader called for invalid args %v", args)
				return hostruntime.PrivateOverlay{}, "", nil
			},
		); !errors.Is(err, ErrHostUsage) {
			t.Errorf("RunPrivateOverlayValidation(%v) error = %v", args, err)
		}
	}
}

func TestRunPrivateOverlayValidationRejectsUntrustedLoaderOutput(t *testing.T) {
	t.Parallel()

	valid := hostruntime.PrivateOverlay{
		SchemaVersion: 1,
		Target: hostruntime.TargetIdentityOverlay{
			OS:                        "linux",
			Architecture:              "amd64",
			ExpectedEUID:              0,
			HostIdentityDigest:        strings.Repeat("1", 64),
			ControlHostIdentityDigest: strings.Repeat("2", 64),
			ProfileID:                 "strict-linux",
		},
		Policy: hostruntime.PolicyOverlay{AcquisitionDefault: "disabled"},
	}
	tests := map[string]struct {
		overlay  hostruntime.PrivateOverlay
		revision string
		loadErr  error
	}{
		"load failure": {
			overlay: valid,
			loadErr: errors.New("secret /private/path"),
		},
		"bad revision": {
			overlay:  valid,
			revision: "A",
		},
		"wrong schema": {
			overlay: func() hostruntime.PrivateOverlay {
				value := valid
				value.SchemaVersion = 2
				return value
			}(),
			revision: strings.Repeat("a", 64),
		},
		"wrong target": {
			overlay: func() hostruntime.PrivateOverlay {
				value := valid
				value.Target.OS = "darwin"
				return value
			}(),
			revision: strings.Repeat("a", 64),
		},
		"unknown profile": {
			overlay: func() hostruntime.PrivateOverlay {
				value := valid
				value.Target.ProfileID = "generic-linux"
				return value
			}(),
			revision: strings.Repeat("a", 64),
		},
		"active mode": {
			overlay: func() hostruntime.PrivateOverlay {
				value := valid
				value.Policy.AcquisitionDefault = "enabled"
				return value
			}(),
			revision: strings.Repeat("a", 64),
		},
	}
	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := RunPrivateOverlayValidation(
				[]string{
					"validate-private-overlay",
					"--private",
					"/private/controller-runtime.json",
				},
				func(string) (hostruntime.PrivateOverlay, string, error) {
					return test.overlay, test.revision, test.loadErr
				},
			); !errors.Is(err, ErrHostCommandFailed) {
				t.Fatalf("RunPrivateOverlayValidation() error = %v", err)
			}
		})
	}
}

func TestPrivateOverlayControlFilesMustBeInsidePrivateRoot(t *testing.T) {
	t.Parallel()

	overlay := hostruntime.PrivateOverlay{
		ManagementTransport: hostruntime.ManagementTransportOverlay{
			KnownHostsFile: "/private/ssh/known_hosts",
			CredentialName: "ssh-control",
		},
		Secrets: []hostruntime.NamedSecretRef{
			{
				Name: "github",
				Ref: hostruntime.SecretRefOverlay{
					Source: "file",
					Ref:    "/run/secrets/github",
				},
			},
			{
				Name: "ssh-control",
				Ref: hostruntime.SecretRefOverlay{
					Source: "file",
					Ref:    "/private/ssh/id_ed25519",
				},
			},
		},
	}
	if !privateOverlayControlFilesUnderRoot(
		"/private/controller-runtime.json",
		overlay,
	) {
		t.Fatal("control files inside private root were rejected")
	}
	for name, mutate := range map[string]func(*hostruntime.PrivateOverlay){
		"known hosts outside": func(value *hostruntime.PrivateOverlay) {
			value.ManagementTransport.KnownHostsFile = "/outside/known_hosts"
		},
		"credential outside": func(value *hostruntime.PrivateOverlay) {
			value.Secrets[1].Ref.Ref = "/outside/id_ed25519"
		},
		"sibling prefix": func(value *hostruntime.PrivateOverlay) {
			value.Secrets[1].Ref.Ref = "/private-other/id_ed25519"
		},
		"environment credential": func(value *hostruntime.PrivateOverlay) {
			value.Secrets[1].Ref.Source = "env"
			value.Secrets[1].Ref.Ref = "SSH_CONTROL"
		},
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			value := overlay
			value.Secrets = append(
				[]hostruntime.NamedSecretRef(nil),
				overlay.Secrets...,
			)
			mutate(&value)
			if privateOverlayControlFilesUnderRoot(
				"/private/controller-runtime.json",
				value,
			) {
				t.Fatal("outside/ambiguous control file was accepted")
			}
		})
	}
}
