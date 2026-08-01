package task11synthetic

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"math"
)

const (
	cycleDigestDomain             = "portable-ghar.task11.synthetic-cycle.v1\x00"
	restartCycleDigestDomain      = "portable-ghar.task11.synthetic-restart-cycle.v1\x00"
	jobMarkerDigestDomain         = "portable-ghar.task11.synthetic-job-marker.v1\x00"
	proxyRequestDigestDomain      = "portable-ghar.task11.synthetic-proxy-proof.v1\x00"
	responseBodyProofDigestDomain = "portable-ghar.task11.synthetic-response-proof.v1\x00"
	jobCompletionDigestDomain     = "portable-ghar.task11.synthetic-completion.v1\x00"
	registrationDigestDomain      = "portable-ghar.task11.synthetic-registration.v1\x00"
	cleanupDigestDomain           = "portable-ghar.task11.synthetic-cleanup.v1\x00"
	cleanupEvidenceDigestDomain   = "portable-ghar.task11.cleanup-evidence.v1\x00"
	postreleaseDigestDomain       = "portable-ghar.task11.post-release-resolution.v1\x00"
)

func DeriveCycleRunDigest(
	primaryRunDigest string,
	cycleKind CycleKind,
	ordinal uint64,
) (string, error) {
	primary, ok := decodeDigest(primaryRunDigest)
	if !ok || !validCycleKind(cycleKind) {
		return "", ErrInvalidProtocol
	}
	kind := []byte(cycleKind)
	if len(kind) > math.MaxUint16 {
		return "", ErrInvalidProtocol
	}
	digest := sha256.New()
	writeBytes(digest, []byte(cycleDigestDomain))
	writeBytes(digest, primary[:])
	writeText(digest, kind)
	writeUint64(digest, ordinal)
	return encodeHash(digest), nil
}

func DeriveRestartCycleRunDigest(
	cleanupControllerRestartCycleDigest string,
	setupStage SetupStage,
	declarationIndex uint64,
) (string, error) {
	parent, ok := decodeDigest(cleanupControllerRestartCycleDigest)
	if !ok ||
		declarationIndex >= uint64(len(restartSetupStages)) ||
		restartSetupStages[declarationIndex] != setupStage {
		return "", ErrInvalidProtocol
	}
	stage := []byte(setupStage)
	if len(stage) > math.MaxUint16 {
		return "", ErrInvalidProtocol
	}
	digest := sha256.New()
	writeBytes(digest, []byte(restartCycleDigestDomain))
	writeBytes(digest, parent[:])
	writeText(digest, stage)
	writeUint64(digest, declarationIndex)
	return encodeHash(digest), nil
}

func DeriveJobMarkerDigest(
	cycleRunDigest string,
	nonce string,
) (string, error) {
	cycle, cycleOK := decodeDigest(cycleRunDigest)
	nonceBytes, nonceOK := decodeDigest(nonce)
	if !cycleOK || !nonceOK {
		return "", ErrInvalidProtocol
	}
	return digestRaw(
		jobMarkerDigestDomain,
		cycle[:],
		nonceBytes[:],
	), nil
}

func DeriveProxyRequestDigest(
	cycleRunDigest string,
	nonce string,
	policyEntryDigest string,
	policyEvidenceDigest string,
	observedResponseBodySHA256 string,
) (string, error) {
	cycle, cycleOK := decodeDigest(cycleRunDigest)
	nonceBytes, nonceOK := decodeDigest(nonce)
	policyEntry, entryOK := decodeDigest(policyEntryDigest)
	policyEvidence, evidenceOK := decodeDigest(policyEvidenceDigest)
	observedBody, bodyOK := decodeDigest(observedResponseBodySHA256)
	if !cycleOK || !nonceOK || !entryOK || !evidenceOK || !bodyOK {
		return "", ErrInvalidProtocol
	}
	return digestRaw(
		proxyRequestDigestDomain,
		cycle[:],
		nonceBytes[:],
		policyEntry[:],
		policyEvidence[:],
		observedBody[:],
	), nil
}

func DeriveResponseBodyProofDigest(
	cycleRunDigest string,
	nonce string,
	observedResponseBodySHA256 string,
	expectedResponseBodyDigest string,
) (string, error) {
	cycle, cycleOK := decodeDigest(cycleRunDigest)
	nonceBytes, nonceOK := decodeDigest(nonce)
	observedBody, observedOK := decodeDigest(observedResponseBodySHA256)
	expectedBody, expectedOK := decodeDigest(expectedResponseBodyDigest)
	if !cycleOK || !nonceOK || !observedOK || !expectedOK {
		return "", ErrInvalidProtocol
	}
	return digestRaw(
		responseBodyProofDigestDomain,
		cycle[:],
		nonceBytes[:],
		observedBody[:],
		expectedBody[:],
	), nil
}

func DeriveJobCompletionDigest(
	cycleRunDigest string,
	jobMarkerDigest string,
	canonicalTerminalFrameWithLF []byte,
) (string, error) {
	return deriveTerminalDigest(
		jobCompletionDigestDomain,
		cycleRunDigest,
		jobMarkerDigest,
		canonicalTerminalFrameWithLF,
	)
}

func DeriveDeregistrationDigest(
	cycleRunDigest string,
	jobMarkerDigest string,
	canonicalTerminalFrameWithLF []byte,
) (string, error) {
	return deriveTerminalDigest(
		registrationDigestDomain,
		cycleRunDigest,
		jobMarkerDigest,
		canonicalTerminalFrameWithLF,
	)
}

func DeriveCleanupDigest(cycleRunDigest string) (string, error) {
	cycle, ok := decodeDigest(cycleRunDigest)
	if !ok {
		return "", ErrInvalidProtocol
	}
	return digestRaw(cleanupDigestDomain, cycle[:]), nil
}

func DeriveCleanupObservationDigest(
	observation CleanupObservation,
) (string, error) {
	canonical, err := MarshalCleanupObservation(observation)
	if err != nil {
		return "", ErrInvalidProtocol
	}
	return digestRaw(cleanupEvidenceDigestDomain, canonical), nil
}

func DerivePostreleaseResolutionEvidence(
	cycleRunDigest string,
	cleanupObservationDigest string,
) (string, error) {
	cycle, cycleOK := decodeDigest(cycleRunDigest)
	observation, observationOK := decodeDigest(cleanupObservationDigest)
	if !cycleOK || !observationOK {
		return "", ErrInvalidProtocol
	}
	return digestRaw(
		postreleaseDigestDomain,
		cycle[:],
		observation[:],
	), nil
}

func SeedSourceDigest(source []byte) string {
	sum := sha256.Sum256(source)
	return hex.EncodeToString(sum[:])
}

func SeedCopyDigest(copyBytes []byte) string {
	sum := sha256.Sum256(copyBytes)
	return hex.EncodeToString(sum[:])
}

func DeriveSeedMutationDigest(source []byte) string {
	digest := sha256.New()
	writeBytes(digest, source)
	writeBytes(digest, []byte(seedMutationSuffix))
	return encodeHash(digest)
}

func deriveTerminalDigest(
	domain string,
	cycleRunDigest string,
	jobMarkerDigest string,
	canonicalTerminalFrameWithLF []byte,
) (string, error) {
	cycle, cycleOK := decodeDigest(cycleRunDigest)
	marker, markerOK := decodeDigest(jobMarkerDigest)
	var terminal TerminalFrame
	if !cycleOK ||
		!markerOK ||
		decodeCanonical(canonicalTerminalFrameWithLF, &terminal) != nil ||
		!validTerminalFrame(terminal) {
		return "", ErrInvalidProtocol
	}
	return digestRaw(
		domain,
		cycle[:],
		marker[:],
		canonicalTerminalFrameWithLF,
	), nil
}

func digestRaw(domain string, components ...[]byte) string {
	digest := sha256.New()
	writeBytes(digest, []byte(domain))
	for _, component := range components {
		writeBytes(digest, component)
	}
	return encodeHash(digest)
}

func decodeDigest(value string) ([sha256.Size]byte, bool) {
	var result [sha256.Size]byte
	if !validDigest(value) {
		return result, false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(result) {
		return result, false
	}
	copy(result[:], decoded)
	return result, true
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func writeText(digest hash.Hash, value []byte) {
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(value)))
	writeBytes(digest, length[:])
	writeBytes(digest, value)
}

func writeUint64(digest hash.Hash, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	writeBytes(digest, encoded[:])
}

func writeBytes(digest hash.Hash, value []byte) {
	_, _ = digest.Write(value)
}

func encodeHash(digest hash.Hash) string {
	return hex.EncodeToString(digest.Sum(nil))
}
