package hostruntime

import (
	"errors"
	"strings"
	"testing"
)

// jailPrivateOverlay returns the golden overlay, which uses the capless-root
// profile, with a valid jail section.
func jailPrivateOverlay() PrivateOverlay {
	overlay := goldenPrivateOverlay()
	overlay.Jail = &JailOverlay{
		AdapterBrokerUser:        "1001:1001",
		RunnerUser:               "0:0",
		VerifierUser:             "1002:1002",
		SeccompProfilePath:       overlay.Paths.SeccompRoot + "/jail.json",
		ContainerLogMaxBytes:     1 << 20,
		ContainerLogMaxFiles:     2,
		DialReservationBlockSize: 4,
		DialAuthorityMaxClients:  4,
		DialAuthorityTimeout:     "2s",
	}
	return overlay
}

func TestPrivateOverlayJailSectionRoundTrip(t *testing.T) {
	t.Parallel()

	encoded, revision, err := MarshalPrivateOverlay(jailPrivateOverlay())
	if err != nil {
		t.Fatalf("MarshalPrivateOverlay() error = %v", err)
	}
	decoded, decodedRevision, err := ParsePrivateOverlay(encoded, len(encoded))
	if err != nil {
		t.Fatalf("ParsePrivateOverlay() error = %v", err)
	}
	if decodedRevision != revision || decoded.Jail == nil ||
		*decoded.Jail != *jailPrivateOverlay().Jail {
		t.Fatalf("ParsePrivateOverlay() jail = %+v", decoded.Jail)
	}

	golden, _, err := MarshalPrivateOverlay(goldenPrivateOverlay())
	if err != nil {
		t.Fatalf("MarshalPrivateOverlay(golden) error = %v", err)
	}
	if strings.Contains(string(golden), `"jail":`) {
		t.Fatalf("absent jail section was encoded: %s", golden)
	}
}

func TestPrivateOverlayJailSectionFollowsTheHostProfile(t *testing.T) {
	t.Parallel()

	strict := jailPrivateOverlay()
	strict.Target.ProfileID = string(HostProfileStrictLinux)
	strict.Target.DegradedAcknowledged = false
	strict.Jail.RunnerUser = "1003:1003"
	if _, _, err := MarshalPrivateOverlay(strict); err != nil {
		t.Fatalf("strict profile with an unprivileged runner: %v", err)
	}
	strict.Jail.RunnerUser = "0:0"
	if _, _, err := MarshalPrivateOverlay(strict); !errors.Is(err, ErrInvalidPrivateOverlay) {
		t.Fatalf("strict profile with a root runner: error = %v", err)
	}
}

func TestPrivateOverlayRejectsInvalidJailSection(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*JailOverlay){
		"root adapter":           func(jail *JailOverlay) { jail.AdapterBrokerUser = "0:1001" },
		"named adapter":          func(jail *JailOverlay) { jail.AdapterBrokerUser = "broker" },
		"root verifier":          func(jail *JailOverlay) { jail.VerifierUser = "0:0" },
		"missing verifier gid":   func(jail *JailOverlay) { jail.VerifierUser = "1002" },
		"unprivileged runner":    func(jail *JailOverlay) { jail.RunnerUser = "1003:1003" },
		"runner with root uid":   func(jail *JailOverlay) { jail.RunnerUser = "0:1003" },
		"seccomp outside root":   func(jail *JailOverlay) { jail.SeccompProfilePath = "/etc/seccomp.json" },
		"seccomp is the root":    func(jail *JailOverlay) { jail.SeccompProfilePath = "/opt/portable/seccomp" },
		"relative seccomp":       func(jail *JailOverlay) { jail.SeccompProfilePath = "seccomp/jail.json" },
		"unclean seccomp":        func(jail *JailOverlay) { jail.SeccompProfilePath = "/opt/portable/seccomp/../jail.json" },
		"zero log bytes":         func(jail *JailOverlay) { jail.ContainerLogMaxBytes = 0 },
		"zero log files":         func(jail *JailOverlay) { jail.ContainerLogMaxFiles = 0 },
		"zero block size":        func(jail *JailOverlay) { jail.DialReservationBlockSize = 0 },
		"block size over uint32": func(jail *JailOverlay) { jail.DialReservationBlockSize = 1 << 32 },
		"zero clients":           func(jail *JailOverlay) { jail.DialAuthorityMaxClients = 0 },
		"clients over the pids":  func(jail *JailOverlay) { jail.DialAuthorityMaxClients = 9 },
		"zero timeout":           func(jail *JailOverlay) { jail.DialAuthorityTimeout = "0s" },
		"timeout over 30s":       func(jail *JailOverlay) { jail.DialAuthorityTimeout = "31s" },
		"sub-millisecond timeout": func(jail *JailOverlay) {
			jail.DialAuthorityTimeout = "1.0000001s"
		},
		"non-canonical timeout": func(jail *JailOverlay) { jail.DialAuthorityTimeout = "2000ms" },
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			overlay := jailPrivateOverlay()
			mutate(overlay.Jail)
			if _, _, err := MarshalPrivateOverlay(overlay); !errors.Is(err, ErrInvalidPrivateOverlay) {
				t.Fatalf("MarshalPrivateOverlay() error = %v", err)
			}
		})
	}
}
