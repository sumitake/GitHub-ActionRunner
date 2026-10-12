package hostruntime

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

// externalPrivateOverlay returns the golden overlay with both external
// service sections set, the shape an acquiring controller reads.
func externalPrivateOverlay() PrivateOverlay {
	overlay := goldenPrivateOverlay()
	overlay.Secrets = append(overlay.Secrets, NamedSecretRef{
		Name: "worker-hmac",
		Ref:  SecretRefOverlay{Source: "file", Ref: "/run/secrets/worker-hmac"},
	})
	overlay.Worker = &WorkerOverlay{
		BaseURL:            "https://failover.example.invalid",
		HMACCredentialName: "worker-hmac",
		FleetID:            "example-fleet",
		TimestampWindow:    "5m0s",
		LeaseDuration:      "2m0s",
		HeartbeatDeadline:  "10s",
		ShorteningMargin:   "5s",
		LostRenewals:       2,
		TerminationTail:    "30s",
	}
	overlay.GitHub = &GitHubOverlay{
		MaxResponseBytes:      1 << 20,
		OperationTimeout:      "1m0s",
		ResponseHeaderTimeout: "55s",
	}
	return overlay
}

func TestPrivateOverlayExternalSectionsRoundTrip(t *testing.T) {
	t.Parallel()

	encoded, revision, err := MarshalPrivateOverlay(externalPrivateOverlay())
	if err != nil {
		t.Fatalf("MarshalPrivateOverlay() error = %v", err)
	}
	_, goldenRevision, err := MarshalPrivateOverlay(goldenPrivateOverlay())
	if err != nil {
		t.Fatalf("MarshalPrivateOverlay(golden) error = %v", err)
	}
	if revision == goldenRevision {
		t.Fatal("external sections do not change the overlay revision")
	}
	decoded, decodedRevision, err := ParsePrivateOverlay(encoded, len(encoded))
	if err != nil {
		t.Fatalf("ParsePrivateOverlay() error = %v", err)
	}
	if decodedRevision != revision ||
		decoded.Worker == nil ||
		*decoded.Worker != *externalPrivateOverlay().Worker ||
		decoded.GitHub == nil ||
		*decoded.GitHub != *externalPrivateOverlay().GitHub {
		t.Fatalf("ParsePrivateOverlay() = %+v, %+v", decoded.Worker, decoded.GitHub)
	}
}

func TestPrivateOverlayOmitsAbsentExternalSections(t *testing.T) {
	t.Parallel()

	encoded, _, err := MarshalPrivateOverlay(goldenPrivateOverlay())
	if err != nil {
		t.Fatalf("MarshalPrivateOverlay() error = %v", err)
	}
	if strings.Contains(string(encoded), `"worker":`) ||
		strings.Contains(string(encoded), `"github":`) {
		t.Fatalf("absent sections were encoded: %s", encoded)
	}
	for name, section := range map[string]string{
		"null worker": `"worker":null`,
		"null github": `"github":null`,
	} {
		document := []byte(strings.TrimSuffix(string(encoded), "}") + "," + section + "}")
		if _, _, err := ParsePrivateOverlay(
			document,
			len(document),
		); !errors.Is(err, ErrInvalidPrivateOverlay) {
			t.Errorf("%s: ParsePrivateOverlay() error = %v", name, err)
		}
	}
}

func TestPrivateOverlayRejectsInvalidExternalSections(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*PrivateOverlay){
		"http worker URL": func(overlay *PrivateOverlay) {
			overlay.Worker.BaseURL = "http://failover.example.invalid"
		},
		"worker URL with path": func(overlay *PrivateOverlay) {
			overlay.Worker.BaseURL = "https://failover.example.invalid/v1"
		},
		"worker URL with trailing slash": func(overlay *PrivateOverlay) {
			overlay.Worker.BaseURL = "https://failover.example.invalid/"
		},
		"worker URL with user": func(overlay *PrivateOverlay) {
			withUser := url.URL{
				Scheme: "https",
				User:   url.User("operator"),
				Host:   "failover.example.invalid",
			}
			overlay.Worker.BaseURL = withUser.String()
		},
		"worker URL with port and no host": func(overlay *PrivateOverlay) {
			overlay.Worker.BaseURL = "https://:443"
		},
		"worker URL with out-of-range port": func(overlay *PrivateOverlay) {
			overlay.Worker.BaseURL = "https://failover.example.invalid:65536"
		},
		"worker URL with explicit port": func(overlay *PrivateOverlay) {
			overlay.Worker.BaseURL = "https://failover.example.invalid:443"
		},
		"worker URL with empty port": func(overlay *PrivateOverlay) {
			overlay.Worker.BaseURL = "https://failover.example.invalid:"
		},
		"uppercase fleet": func(overlay *PrivateOverlay) {
			overlay.Worker.FleetID = "Example-fleet"
		},
		"empty fleet": func(overlay *PrivateOverlay) {
			overlay.Worker.FleetID = ""
		},
		"missing HMAC secret": func(overlay *PrivateOverlay) {
			overlay.Worker.HMACCredentialName = "absent"
		},
		"HMAC is the management credential": func(overlay *PrivateOverlay) {
			overlay.Worker.HMACCredentialName =
				overlay.ManagementTransport.CredentialName
		},
		"HMAC is a repository credential": func(overlay *PrivateOverlay) {
			overlay.Worker.HMACCredentialName =
				overlay.Repositories[0].CredentialName
		},
		"HMAC file shared with a repository credential": func(overlay *PrivateOverlay) {
			shareSecretRef(overlay, "worker-hmac", overlay.Repositories[0].CredentialName)
		},
		"HMAC file shared with the management credential": func(overlay *PrivateOverlay) {
			shareSecretRef(overlay, "worker-hmac", overlay.ManagementTransport.CredentialName)
		},
		"repository token file shared with the management credential": func(overlay *PrivateOverlay) {
			shareSecretRef(overlay, overlay.Repositories[0].CredentialName, overlay.ManagementTransport.CredentialName)
		},
		"HMAC from environment": func(overlay *PrivateOverlay) {
			for index := range overlay.Secrets {
				if overlay.Secrets[index].Name == "worker-hmac" {
					overlay.Secrets[index].Ref = SecretRefOverlay{
						Source: "env",
						Ref:    "WORKER_HMAC",
					}
				}
			}
		},
		"zero lost renewals": func(overlay *PrivateOverlay) {
			overlay.Worker.LostRenewals = 0
		},
		"noncanonical lease duration": func(overlay *PrivateOverlay) {
			overlay.Worker.LeaseDuration = "120s"
		},
		"submillisecond deadline": func(overlay *PrivateOverlay) {
			overlay.Worker.HeartbeatDeadline = "1.5ms"
		},
		"missing termination tail": func(overlay *PrivateOverlay) {
			overlay.Worker.TerminationTail = ""
		},
		"zero response bytes": func(overlay *PrivateOverlay) {
			overlay.GitHub.MaxResponseBytes = 0
		},
		"unbounded response bytes": func(overlay *PrivateOverlay) {
			overlay.GitHub.MaxResponseBytes = maxGitHubResponseBytes + 1
		},
		"header timeout over operation timeout": func(overlay *PrivateOverlay) {
			overlay.GitHub.ResponseHeaderTimeout = "2m0s"
		},
		"submillisecond operation timeout": func(overlay *PrivateOverlay) {
			overlay.GitHub.OperationTimeout = "1.5ms"
			overlay.GitHub.ResponseHeaderTimeout = "1ms"
		},
		"submillisecond header timeout": func(overlay *PrivateOverlay) {
			overlay.GitHub.ResponseHeaderTimeout = "1.5ms"
		},
		"repository URL without hostname": func(overlay *PrivateOverlay) {
			overlay.Repositories[0].ConfigURL = "https://:443/example/repository"
		},
		"repository URL with port": func(overlay *PrivateOverlay) {
			overlay.Repositories[0].ConfigURL = "https://github.example.invalid:65536/example/repository"
		},
		"repository token missing": func(overlay *PrivateOverlay) {
			overlay.Repositories[0].CredentialName = "absent"
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			overlay := externalPrivateOverlay()
			mutate(&overlay)
			if _, _, err := MarshalPrivateOverlay(overlay); !errors.Is(err, ErrInvalidPrivateOverlay) {
				t.Fatalf("MarshalPrivateOverlay() error = %v", err)
			}
		})
	}
}

// shareSecretRef points the secret named target at the same reference as the
// secret named source.
func shareSecretRef(overlay *PrivateOverlay, target, source string) {
	var ref SecretRefOverlay
	for _, secret := range overlay.Secrets {
		if secret.Name == source {
			ref = secret.Ref
		}
	}
	for index := range overlay.Secrets {
		if overlay.Secrets[index].Name == target {
			overlay.Secrets[index].Ref = ref
		}
	}
}
