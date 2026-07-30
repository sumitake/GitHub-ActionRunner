package testenv

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"

	"github.com/sumitake/portable-ghar/internal/networkjail"
)

const probeMembershipDomain = "portable-ghar.task11.probe-membership.v1\x00"
const probePreparedBindingDomain = "portable-ghar.task11.probe-prepared.v1\x00"
const probeVerifierTopology = "verify-proxy-egress-ordered-v1"

type probeMembershipClass uint8

const (
	probeMembershipLiteral probeMembershipClass = iota + 1
	probeMembershipDNS
)

type classifiedNegativeProbe struct {
	index         uint32
	class         probeMembershipClass
	sentinelIndex uint32
}

// probeMembershipSeal is compiled before effects from the exact private
// sentinel bindings and immutable decision graph. It exposes only its digest.
type probeMembershipSeal struct {
	digest      [sha256.Size]byte
	graphDigest string
	valid       bool
}

func newProbeMembershipSeal(
	sentinels SentinelBindings,
	graph networkjail.DecisionGraph,
) (probeMembershipSeal, error) {
	graphDigest := graph.Digest().String()
	positive := graph.PositiveProbes()
	negative := graph.NegativeProbes()
	if !isLowerHex(graphDigest, sha256.Size*2) ||
		!validID(sentinels.Positive.ID) ||
		!validDNSName(sentinels.Positive.Host) ||
		net.ParseIP(sentinels.Positive.Host) != nil ||
		sentinels.Positive.Port == 0 ||
		len(positive) == 0 ||
		len(negative) == 0 ||
		len(sentinels.LiteralDeny) == 0 ||
		len(sentinels.DNSDeny) == 0 {
		return probeMembershipSeal{}, ErrFixtureStart
	}

	positiveMatch := -1
	for index, probe := range positive {
		if probe.Protocol == networkjail.HTTPConnect &&
			probe.Host == sentinels.Positive.Host &&
			probe.Port == sentinels.Positive.Port {
			if positiveMatch >= 0 {
				return probeMembershipSeal{}, ErrFixtureStart
			}
			positiveMatch = index
		}
	}
	if positiveMatch < 0 {
		return probeMembershipSeal{}, ErrFixtureStart
	}

	literalIndexes := make(map[string]uint32, len(sentinels.LiteralDeny))
	dnsIndexes := make(map[string]uint32, len(sentinels.DNSDeny))
	seenIDs := map[string]struct{}{sentinels.Positive.ID: {}}
	for index, sentinel := range sentinels.LiteralDeny {
		if !validID(sentinel.ID) ||
			!addressMatchesClass(sentinel.Address, sentinel.Class) ||
			!isLowerHex(sentinel.EvidenceDigest, sha256.Size*2) {
			return probeMembershipSeal{}, ErrFixtureStart
		}
		if _, found := seenIDs[sentinel.ID]; found {
			return probeMembershipSeal{}, ErrFixtureStart
		}
		if _, found := literalIndexes[sentinel.Address]; found {
			return probeMembershipSeal{}, ErrFixtureStart
		}
		seenIDs[sentinel.ID] = struct{}{}
		literalIndexes[sentinel.Address] = uint32(index)
	}
	for index, sentinel := range sentinels.DNSDeny {
		if !validID(sentinel.ID) ||
			!validDNSName(sentinel.Host) ||
			net.ParseIP(sentinel.Host) != nil ||
			!validAddressClass(sentinel.Class) ||
			!isLowerHex(sentinel.EvidenceDigest, sha256.Size*2) {
			return probeMembershipSeal{}, ErrFixtureStart
		}
		if _, found := seenIDs[sentinel.ID]; found {
			return probeMembershipSeal{}, ErrFixtureStart
		}
		if _, found := dnsIndexes[sentinel.Host]; found {
			return probeMembershipSeal{}, ErrFixtureStart
		}
		seenIDs[sentinel.ID] = struct{}{}
		dnsIndexes[sentinel.Host] = uint32(index)
	}

	literalCounts := make([]uint32, len(sentinels.LiteralDeny))
	dnsCounts := make([]uint32, len(sentinels.DNSDeny))
	classified := make([]classifiedNegativeProbe, len(negative))
	for index, probe := range negative {
		literalIndex, literal := literalIndexes[probe.Host]
		dnsIndex, dns := dnsIndexes[probe.Host]
		if literal == dns {
			return probeMembershipSeal{}, ErrFixtureStart
		}
		classified[index].index = uint32(index)
		if literal {
			classified[index].class = probeMembershipLiteral
			classified[index].sentinelIndex = literalIndex
			literalCounts[literalIndex]++
			continue
		}
		classified[index].class = probeMembershipDNS
		classified[index].sentinelIndex = dnsIndex
		dnsCounts[dnsIndex]++
	}
	for _, count := range append(literalCounts, dnsCounts...) {
		if count == 0 {
			return probeMembershipSeal{}, ErrFixtureStart
		}
	}

	var preimage bytes.Buffer
	preimage.WriteString(probeMembershipDomain)
	writeProbeMembershipString(&preimage, probeVerifierTopology)
	writeProbeMembershipString(&preimage, graphDigest)
	writeProbeMembershipSentinels(&preimage, sentinels)
	writeProbeMembershipUint32(&preimage, uint32(positiveMatch))
	writeProbeMembershipProbes(&preimage, positive, nil)
	writeProbeMembershipProbes(&preimage, negative, classified)
	return probeMembershipSeal{
		digest:      sha256.Sum256(preimage.Bytes()),
		graphDigest: graphDigest,
		valid:       true,
	}, nil
}

func writeProbeMembershipSentinels(
	target *bytes.Buffer,
	sentinels SentinelBindings,
) {
	positive := sentinels.Positive
	for _, value := range []string{
		positive.ID,
		positive.URL,
		positive.Host,
		positive.HostIdentityDigest,
		positive.SPKIDigest,
		positive.CertificateDigest,
		positive.PolicyEntryDigest,
		positive.PolicyEvidenceDigest,
		positive.ResponseBodyDigest,
	} {
		writeProbeMembershipString(target, value)
	}
	writeProbeMembershipUint32(target, uint32(positive.Port))
	writeProbeMembershipUint32(
		target,
		uint32(len(sentinels.LiteralDeny)),
	)
	for _, sentinel := range sentinels.LiteralDeny {
		writeProbeMembershipString(target, sentinel.ID)
		writeProbeMembershipString(target, sentinel.Address)
		writeProbeMembershipString(target, string(sentinel.Class))
		writeProbeMembershipString(target, sentinel.EvidenceDigest)
	}
	writeProbeMembershipUint32(target, uint32(len(sentinels.DNSDeny)))
	for _, sentinel := range sentinels.DNSDeny {
		writeProbeMembershipString(target, sentinel.ID)
		writeProbeMembershipString(target, sentinel.Host)
		writeProbeMembershipString(target, string(sentinel.Class))
		writeProbeMembershipString(target, sentinel.EvidenceDigest)
	}
}

func writeProbeMembershipProbes(
	target *bytes.Buffer,
	probes []networkjail.Probe,
	classified []classifiedNegativeProbe,
) {
	writeProbeMembershipUint32(target, uint32(len(probes)))
	for index, probe := range probes {
		writeProbeMembershipUint32(target, uint32(index))
		writeProbeMembershipString(target, string(probe.Protocol))
		writeProbeMembershipString(target, probe.Host)
		writeProbeMembershipUint32(target, uint32(probe.Port))
		if classified != nil {
			target.WriteByte(byte(classified[index].class))
			writeProbeMembershipUint32(
				target,
				classified[index].sentinelIndex,
			)
		}
	}
}

func writeProbeMembershipString(target *bytes.Buffer, value string) {
	writeProbeMembershipUint32(target, uint32(len(value)))
	target.WriteString(value)
}

func writeProbeMembershipUint32(target *bytes.Buffer, value uint32) {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	target.Write(encoded[:])
}

func (seal probeMembershipSeal) Digest() string {
	if !seal.valid {
		return ""
	}
	return hex.EncodeToString(seal.digest[:])
}

func (seal probeMembershipSeal) BindPreparedReport(
	report networkjail.ProbeReport,
	permitUsageDigest string,
	authorityBindingDigest string,
) (string, error) {
	if !seal.valid ||
		networkjail.ValidateProbeReport(report) != nil ||
		report.PolicyDigest != seal.graphDigest ||
		!report.PositiveOK ||
		!report.NegativeOK ||
		!isLowerHex(permitUsageDigest, sha256.Size*2) ||
		!isLowerHex(authorityBindingDigest, sha256.Size*2) {
		return "", ErrFixtureStart
	}
	document, err := json.Marshal(report)
	if err != nil {
		return "", ErrFixtureStart
	}
	var preimage bytes.Buffer
	preimage.WriteString(probePreparedBindingDomain)
	preimage.Write(seal.digest[:])
	writeProbeMembershipString(&preimage, permitUsageDigest)
	writeProbeMembershipString(&preimage, authorityBindingDigest)
	writeProbeMembershipUint32(&preimage, uint32(len(document)))
	preimage.Write(document)
	digest := sha256.Sum256(preimage.Bytes())
	return hex.EncodeToString(digest[:]), nil
}
