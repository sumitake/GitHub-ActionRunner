package testenv

import (
	"testing"

	"github.com/sumitake/portable-ghar/internal/networkjail"
)

func TestProbeMembershipSealBindsEverySentinelAndPreparedUsage(
	t *testing.T,
) {
	t.Parallel()

	sentinels, graph := validProbeMembershipInputs(t)
	seal, err := newProbeMembershipSeal(sentinels, graph)
	if err != nil {
		t.Fatalf("newProbeMembershipSeal: %v", err)
	}
	if !isLowerHex(seal.Digest(), 64) {
		t.Fatalf("seal digest = %q", seal.Digest())
	}
	report := validProbeMembershipReport(graph)
	binding, err := seal.BindPreparedReport(
		report,
		inputDigestA,
		inputDigestB,
	)
	if err != nil || !isLowerHex(binding, 64) {
		t.Fatalf("BindPreparedReport = %q/%v", binding, err)
	}
	again, err := newProbeMembershipSeal(sentinels, graph)
	if err != nil || again.Digest() != seal.Digest() {
		t.Fatalf(
			"stable seal = %q/%q err=%v",
			seal.Digest(),
			again.Digest(),
			err,
		)
	}
}

func TestProbeMembershipSealRejectsMissingDuplicateOrUnclassifiedMember(
	t *testing.T,
) {
	t.Parallel()

	tests := map[string]func(*SentinelBindings, *networkjail.PolicyManifest){
		"missing literal sentinel": func(
			sentinels *SentinelBindings,
			_ *networkjail.PolicyManifest,
		) {
			sentinels.LiteralDeny = sentinels.LiteralDeny[:1]
		},
		"duplicate literal sentinel": func(
			sentinels *SentinelBindings,
			_ *networkjail.PolicyManifest,
		) {
			sentinels.LiteralDeny = append(
				sentinels.LiteralDeny,
				sentinels.LiteralDeny[0],
			)
		},
		"reclassified DNS sentinel": func(
			sentinels *SentinelBindings,
			_ *networkjail.PolicyManifest,
		) {
			sentinels.DNSDeny[0].Host = "10.0.0.1"
		},
		"unclassified graph deny": func(
			_ *SentinelBindings,
			manifest *networkjail.PolicyManifest,
		) {
			manifest.NegativeProbes = append(
				manifest.NegativeProbes,
				networkjail.Probe{
					Protocol: networkjail.HTTPConnect,
					Host:     "unclassified.example.com",
					Port:     443,
				},
			)
		},
		"duplicate positive match": func(
			_ *SentinelBindings,
			manifest *networkjail.PolicyManifest,
		) {
			manifest.PositiveProbes = append(
				manifest.PositiveProbes,
				networkjail.Probe{
					Protocol: networkjail.HTTPConnect,
					Host:     "example.com",
					Port:     443,
				},
			)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			sentinels, manifest := validProbeMembershipManifest()
			mutate(&sentinels, &manifest)
			graph, _, err := networkjail.Compile(manifest)
			if err != nil {
				return
			}
			if _, err := newProbeMembershipSeal(
				sentinels,
				graph,
			); err == nil {
				t.Fatal("accepted incomplete probe membership")
			}
		})
	}
}

func TestProbeMembershipSealRejectsSubstitutedPreparedReport(
	t *testing.T,
) {
	t.Parallel()

	sentinels, graph := validProbeMembershipInputs(t)
	seal, err := newProbeMembershipSeal(sentinels, graph)
	if err != nil {
		t.Fatalf("newProbeMembershipSeal: %v", err)
	}
	tests := map[string]func(*networkjail.ProbeReport){
		"policy": func(report *networkjail.ProbeReport) {
			report.PolicyDigest = inputDigestD
		},
		"positive": func(report *networkjail.ProbeReport) {
			report.PositiveOK = false
		},
		"negative": func(report *networkjail.ProbeReport) {
			report.NegativeOK = false
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			report := validProbeMembershipReport(graph)
			mutate(&report)
			if _, err := seal.BindPreparedReport(
				report,
				inputDigestA,
				inputDigestB,
			); err == nil {
				t.Fatal("accepted substituted prepared report")
			}
		})
	}
	if _, err := seal.BindPreparedReport(
		validProbeMembershipReport(graph),
		"",
		inputDigestB,
	); err == nil {
		t.Fatal("accepted missing permit-usage digest")
	}
}

func validProbeMembershipInputs(
	t *testing.T,
) (SentinelBindings, networkjail.DecisionGraph) {
	t.Helper()
	sentinels, manifest := validProbeMembershipManifest()
	graph, _, err := networkjail.Compile(manifest)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return sentinels, graph
}

func validProbeMembershipManifest() (
	SentinelBindings,
	networkjail.PolicyManifest,
) {
	manifest := validCompositionPolicyManifest()
	manifest.PositiveProbes = []networkjail.Probe{{
		Protocol: networkjail.HTTPConnect,
		Host:     "example.com",
		Port:     443,
	}}
	manifest.NegativeProbes = []networkjail.Probe{
		{
			Protocol: networkjail.HTTPConnect,
			Host:     "10.0.0.1",
			Port:     443,
		},
		{
			Protocol: networkjail.HTTPConnect,
			Host:     "127.0.0.1",
			Port:     443,
		},
		{
			Protocol: networkjail.HTTPConnect,
			Host:     "blocked.example.com",
			Port:     443,
		},
	}
	return SentinelBindings{
		Positive: PublicHTTPSSentinel{
			ID:                   "public-https",
			URL:                  "https://example.com/probe",
			Host:                 "example.com",
			Port:                 443,
			HostIdentityDigest:   inputDigestA,
			SPKIDigest:           inputDigestB,
			CertificateDigest:    inputDigestC,
			PolicyEntryDigest:    inputDigestD,
			PolicyEvidenceDigest: inputDigestC,
			ResponseBodyDigest:   inputDigestA,
		},
		LiteralDeny: []LiteralDenySentinel{
			{
				ID: "deny-loopback", Address: "127.0.0.1",
				Class: AddressLoopback, EvidenceDigest: inputDigestA,
			},
			{
				ID: "deny-private", Address: "10.0.0.1",
				Class: AddressPrivate, EvidenceDigest: inputDigestB,
			},
		},
		DNSDeny: []DNSDenySentinel{{
			ID: "deny-private-dns", Host: "blocked.example.com",
			Class: AddressPrivate, EvidenceDigest: inputDigestC,
		}},
	}, manifest
}

func validProbeMembershipReport(
	graph networkjail.DecisionGraph,
) networkjail.ProbeReport {
	return networkjail.ProbeReport{
		Version:       1,
		PolicyDigest:  graph.Digest().String(),
		EgressBackend: graph.EgressBackend(),
		RunnerNetNSID: networkjail.NamespaceIdentity{
			Device: 1,
			Inode:  2,
		},
		BrokerNetNSID: networkjail.NamespaceIdentity{
			Device: 3,
			Inode:  4,
		},
		RunnerLoopbackOnly:   true,
		RunnerTablesEmpty:    true,
		RunnerConntrackEmpty: true,
		ParserHasNoSocket:    true,
		PositiveOK:           true,
		NegativeOK:           true,
		ConntrackBudgetOK:    true,
	}
}
