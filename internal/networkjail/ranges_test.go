package networkjail

import (
	"net/netip"
	"testing"
)

func TestNormalizeDestinationRejectsEveryDenyClass(t *testing.T) {
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile error = %v", err)
	}
	denied := []string{
		"127.0.0.1",
		"10.0.0.1",
		"172.16.0.1",
		"192.168.0.1",
		"169.254.1.1",
		"169.254.169.254",
		"100.64.0.1",
		"0.0.0.1",
		"192.0.0.1",
		"192.0.2.1",
		"198.51.100.1",
		"203.0.113.1",
		"198.18.0.1",
		"240.0.0.1",
		"224.0.0.1",
		"255.255.255.255",
		"::",
		"::1",
		"fc00::1",
		"fe80::1",
		"2001:db8::1",
		"ff00::1",
		"::ffff:169.254.169.254",
		"::169.254.169.254",
		"2002:c000:0201::",
		"2001:0000:4136:e378:8000:63bf:3fff:fdd2",
	}
	for _, raw := range denied {
		t.Run(raw, func(t *testing.T) {
			if _, err := graph.NormalizeDestination(raw, 443); err == nil {
				t.Fatal("NormalizeDestination accepted denied address")
			}
		})
	}
	for _, raw := range []string{"0x7f000001", "0177.0.0.1", "127.1", "2130706433"} {
		t.Run("alternate-"+raw, func(t *testing.T) {
			if _, err := graph.NormalizeDestination(raw, 443); err == nil {
				t.Fatal("NormalizeDestination accepted alternate loopback")
			}
		})
	}
}

func TestNormalizeDestinationCanonicalizesPublicLiteralAndIDNA(t *testing.T) {
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile error = %v", err)
	}
	public := publicV4(8, 8, 4, 4)
	for _, raw := range []string{
		public.String(),
		"0x08080404",
		"010.010.04.04",
	} {
		request, err := graph.NormalizeDestination(raw, 443)
		if err != nil {
			t.Fatalf("NormalizeDestination(%q) error = %v", raw, err)
		}
		if request.Host != public.String() || request.Port != 443 {
			t.Fatalf("request = %+v, want canonical public literal", request)
		}
	}
	request, err := graph.NormalizeDestination("BÜCHER.example.", 443)
	if err != nil {
		t.Fatalf("NormalizeDestination(IDNA) error = %v", err)
	}
	if request.Host != "xn--bcher-kva.example" {
		t.Fatalf("IDNA host = %q", request.Host)
	}
}

func TestNormalizeDestinationRejectsAmbiguousOrMalformedLiteral(t *testing.T) {
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile error = %v", err)
	}
	for _, raw := range []string{
		"08.0.0.1",
		"0x100000000",
		"1.2.3.256",
		"[2001:db8::1",
		"[2001:db8::1]suffix",
		"fe80::1%eth0",
		"fe80::1%25eth0",
		"1..2",
		"１２７.0.0.1",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := graph.NormalizeDestination(raw, 443); err == nil {
				t.Fatal("NormalizeDestination accepted malformed/ambiguous input")
			}
		})
	}
}

func TestValidateAnswersRejectsMixedOrDuplicateRRSet(t *testing.T) {
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile error = %v", err)
	}
	request, err := graph.NormalizeDestination("example.com", 443)
	if err != nil {
		t.Fatalf("NormalizeDestination error = %v", err)
	}
	public := publicV4(8, 8, 4, 4)
	denied := deniedDocumentationV4()
	if _, err := graph.ValidateAnswers(request, []netip.Addr{public, denied}); err == nil {
		t.Fatal("ValidateAnswers accepted mixed public/denied RRset")
	}
	if _, err := graph.ValidateAnswers(request, []netip.Addr{public, public}); err == nil {
		t.Fatal("ValidateAnswers accepted duplicate RRset")
	}
	got, err := graph.ValidateAnswers(request, []netip.Addr{
		netip.MustParseAddr("2606:4700:4700::1111"),
		public,
	})
	if err != nil {
		t.Fatalf("ValidateAnswers(valid) error = %v", err)
	}
	if len(got) != 2 || got[0].Compare(got[1]) >= 0 {
		t.Fatalf("answers = %v, want deterministic sorted copy", got)
	}
	got[0] = denied
	again, err := graph.ValidateAnswers(request, []netip.Addr{
		netip.MustParseAddr("2606:4700:4700::1111"),
		public,
	})
	if err != nil || again[0] == denied {
		t.Fatal("ValidateAnswers exposed mutable backing storage")
	}
}

func TestIPv4OnlyRejectsEveryIPv6Answer(t *testing.T) {
	manifest := validPolicyManifest()
	manifest.IPFamily = PublicIPv4Only
	manifest.BrokerIPv6Posture = IPv6KernelDisabled
	graph, _, err := Compile(manifest)
	if err != nil {
		t.Fatalf("Compile error = %v", err)
	}
	request, err := graph.NormalizeDestination("example.com", 443)
	if err != nil {
		t.Fatalf("NormalizeDestination error = %v", err)
	}
	if _, err := graph.ValidateAnswers(request, []netip.Addr{
		publicV4(8, 8, 4, 4),
		netip.MustParseAddr("2606:4700:4700::1111"),
	}); err == nil {
		t.Fatal("ValidateAnswers accepted AAAA under IPv4-only policy")
	}
}

func TestDynamicDenyAndDockerHostAreAppliedAfterNormalization(t *testing.T) {
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile error = %v", err)
	}
	for _, raw := range []string{
		publicV4(9, 9, 9, 9).String(),
		publicV4(11, 11, 11, 11).String(),
	} {
		if _, err := graph.NormalizeDestination(raw, 443); err == nil {
			t.Fatalf("NormalizeDestination(%q) accepted dynamic deny", raw)
		}
	}
}
