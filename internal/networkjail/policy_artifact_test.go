package networkjail

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

func TestDecisionGraphWireRoundTripIsCanonicalAndBoundToDigest(t *testing.T) {
	graph, digest, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	document, err := EncodeDecisionGraph(graph)
	if err != nil {
		t.Fatalf("EncodeDecisionGraph: %v", err)
	}
	decoded, err := DecodeDecisionGraph(bytes.NewReader(document))
	if err != nil {
		t.Fatalf("DecodeDecisionGraph: %v", err)
	}
	if decoded.Digest() != digest {
		t.Fatalf("decoded digest = %s, want %s", decoded.Digest(), digest)
	}
	reencoded, err := EncodeDecisionGraph(decoded)
	if err != nil {
		t.Fatalf("EncodeDecisionGraph(decoded): %v", err)
	}
	if !bytes.Equal(document, reencoded) {
		t.Fatal("decision graph wire encoding is not stable")
	}

	for name, payload := range map[string][]byte{
		"trailing": append(append([]byte{}, document...), 'x'),
		"unknown": bytes.Replace(
			document,
			[]byte(`"version":1`),
			[]byte(`"version":1,"unknown":true`),
			1,
		),
		"digest": bytes.Replace(
			document,
			[]byte(digest.String()),
			[]byte(strings.Repeat("0", 64)),
			1,
		),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeDecisionGraph(bytes.NewReader(payload)); err == nil {
				t.Fatal("DecodeDecisionGraph accepted an invalid document")
			}
		})
	}
}

func TestCompilePolicyArtifactEmitsDefaultDropAndExactDenyBeforeAllow(t *testing.T) {
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	artifact, err := CompilePolicyArtifact(graph)
	if err != nil {
		t.Fatalf("CompilePolicyArtifact: %v", err)
	}
	if !artifact.Valid() ||
		artifact.IPv6Posture() != hostruntime.PolicyIPv6DenyViaIP6Tables {
		t.Fatal("compiled policy artifact is invalid")
	}

	ipv4 := string(artifact.IPv4Program())
	for _, line := range []string{
		":INPUT DROP [0:0]\n",
		":FORWARD DROP [0:0]\n",
		":OUTPUT DROP [0:0]\n",
		"-A OUTPUT -d 127.0.0.0/8 -j DROP\n",
		"-A OUTPUT -d 169.254.0.0/16 -j DROP\n",
		"-A OUTPUT -d 9.9.9.9/32 -j DROP\n",
		"-A OUTPUT -d 11.11.11.11/32 -j DROP\n",
		"-A OUTPUT -p tcp -d 8.8.8.8/32 --dport 443 -m conntrack --ctstate NEW -j ACCEPT\n",
		"-A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT\n",
		"-A OUTPUT -p tcp --dport 8443 -m conntrack --ctstate NEW -j ACCEPT\n",
	} {
		if !strings.Contains(ipv4, line) {
			t.Errorf("IPv4 program missing %q:\n%s", line, ipv4)
		}
	}
	if strings.Index(ipv4, "-A OUTPUT -d 169.254.0.0/16 -j DROP\n") >
		strings.Index(ipv4, "-A OUTPUT -p tcp --dport 443") {
		t.Fatal("IPv4 allow precedes deny")
	}

	runtimePolicy := artifact.RuntimePolicy()
	if len(runtimePolicy) == 0 {
		t.Fatal("compiled artifact omitted runtime decision graph")
	}
	decoded, err := DecodeDecisionGraph(bytes.NewReader(runtimePolicy))
	if err != nil {
		t.Fatalf("DecodeDecisionGraph(artifact): %v", err)
	}
	if decoded.Digest() != graph.Digest() {
		t.Fatal("runtime decision graph digest drifted")
	}
}

func TestCompilePolicyArtifactKernelDisabledOmitsIPv6Program(t *testing.T) {
	manifest := validPolicyManifest()
	manifest.IPFamily = PublicIPv4Only
	manifest.BrokerIPv6Posture = IPv6KernelDisabled
	graph, _, err := Compile(manifest)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	artifact, err := CompilePolicyArtifact(graph)
	if err != nil {
		t.Fatalf("CompilePolicyArtifact: %v", err)
	}
	if artifact.IPv6Posture() != hostruntime.PolicyIPv6KernelDisabled ||
		len(artifact.IPv6Program()) != 0 {
		t.Fatal("kernel-disabled policy emitted an IPv6 restore program")
	}
}
