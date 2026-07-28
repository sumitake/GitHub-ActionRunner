package hostruntime

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

const (
	maxPolicyProgramBytes  = 256 << 10
	maxRuntimePolicyBytes  = 128 << 10
	policyFrameHeaderBytes = 21
)

var policyFrameMagic = [8]byte{'P', 'G', 'H', 'R', 'P', 'O', 'L', '1'}

// PolicyIPv6Posture is the exact host-runtime application posture. It is
// intentionally separate from networkjail's compile-time enum so hostruntime
// remains below, rather than depending on, the orchestration package.
type PolicyIPv6Posture uint8

const (
	PolicyIPv6DenyViaIP6Tables PolicyIPv6Posture = iota + 1
	PolicyIPv6KernelDisabled
)

// PolicyArtifact is immutable after construction. Its digest is derived from
// the exact canonical restore programs and posture; callers cannot inject it.
type PolicyArtifact struct {
	ipv4          []byte
	ipv6          []byte
	runtimePolicy []byte
	posture       PolicyIPv6Posture
	digest        [sha256.Size]byte
}

// NewPolicyArtifact validates and copies the complete restore programs before
// deriving their canonical digest.
func NewPolicyArtifact(
	ipv4,
	ipv6,
	runtimePolicy []byte,
	posture PolicyIPv6Posture,
) (PolicyArtifact, error) {
	if err := validatePolicyProgram(ipv4); err != nil {
		return PolicyArtifact{}, err
	}
	if err := validateRuntimePolicy(runtimePolicy); err != nil {
		return PolicyArtifact{}, err
	}
	switch posture {
	case PolicyIPv6DenyViaIP6Tables:
		if err := validatePolicyProgram(ipv6); err != nil {
			return PolicyArtifact{}, err
		}
	case PolicyIPv6KernelDisabled:
		if len(ipv6) != 0 {
			return PolicyArtifact{}, errors.New("hostruntime: kernel-disabled policy has ipv6 program")
		}
	default:
		return PolicyArtifact{}, errors.New("hostruntime: policy ipv6 posture invalid")
	}
	artifact := PolicyArtifact{
		ipv4:          slices.Clone(ipv4),
		ipv6:          slices.Clone(ipv6),
		runtimePolicy: slices.Clone(runtimePolicy),
		posture:       posture,
	}
	preimage := encodePolicyPreimage(artifact)
	artifact.digest = sha256.Sum256(preimage)
	zeroBytes(preimage)
	return artifact, nil
}

// Digest returns the nonsecret canonical SHA-256 identity.
func (a PolicyArtifact) Digest() string {
	return hex.EncodeToString(a.digest[:])
}

// Valid reports whether the immutable artifact still matches its derived
// digest. It exposes no policy bytes.
func (a PolicyArtifact) Valid() bool {
	return a.valid()
}

// IPv4Program returns a copy of the canonical iptables-restore input.
func (a PolicyArtifact) IPv4Program() []byte {
	return slices.Clone(a.ipv4)
}

// IPv6Program returns a copy of the canonical ip6tables-restore input. It is
// empty only for the exact kernel-disabled posture.
func (a PolicyArtifact) IPv6Program() []byte {
	return slices.Clone(a.ipv6)
}

// IPv6Posture returns the closed application posture.
func (a PolicyArtifact) IPv6Posture() PolicyIPv6Posture {
	return a.posture
}

// RuntimePolicy returns a copy of the canonical broker decision graph. It is
// opaque to hostruntime but is covered by the artifact digest and handed to
// the released broker over the one-use control frame.
func (a PolicyArtifact) RuntimePolicy() []byte {
	return slices.Clone(a.runtimePolicy)
}

// DecodePolicyArtifact parses the exact controller/helper frame, validates its
// embedded digest, and reconstructs an immutable artifact.
func DecodePolicyArtifact(reader io.Reader) (PolicyArtifact, error) {
	if reader == nil {
		return PolicyArtifact{}, errors.New("hostruntime: policy artifact unavailable")
	}
	maxFrameBytes := policyFrameHeaderBytes + sha256.Size +
		2*maxPolicyProgramBytes + maxRuntimePolicyBytes
	frame, err := io.ReadAll(io.LimitReader(reader, int64(maxFrameBytes+1)))
	if err != nil || len(frame) < policyFrameHeaderBytes+sha256.Size ||
		len(frame) > maxFrameBytes ||
		!bytes.Equal(frame[:8], policyFrameMagic[:]) {
		return PolicyArtifact{}, errors.New("hostruntime: policy artifact frame invalid")
	}
	ipv4Bytes := int(binary.BigEndian.Uint32(frame[9:13]))
	ipv6Bytes := int(binary.BigEndian.Uint32(frame[13:17]))
	runtimeBytes := int(binary.BigEndian.Uint32(frame[17:21]))
	if ipv4Bytes > maxPolicyProgramBytes || ipv6Bytes > maxPolicyProgramBytes ||
		runtimeBytes > maxRuntimePolicyBytes ||
		len(frame) != policyFrameHeaderBytes+sha256.Size+
			ipv4Bytes+ipv6Bytes+runtimeBytes {
		return PolicyArtifact{}, errors.New("hostruntime: policy artifact length invalid")
	}
	posture := PolicyIPv6Posture(frame[8])
	payloadOffset := policyFrameHeaderBytes + sha256.Size
	artifact, err := NewPolicyArtifact(
		frame[payloadOffset:payloadOffset+ipv4Bytes],
		frame[payloadOffset+ipv4Bytes:payloadOffset+ipv4Bytes+ipv6Bytes],
		frame[payloadOffset+ipv4Bytes+ipv6Bytes:],
		posture,
	)
	if err != nil ||
		!bytes.Equal(
			frame[policyFrameHeaderBytes:policyFrameHeaderBytes+sha256.Size],
			artifact.digest[:],
		) {
		return PolicyArtifact{}, errors.New("hostruntime: policy artifact digest invalid")
	}
	return artifact, nil
}

// EncodePolicyArtifact returns the exact bounded helper frame. The artifact is
// nonsecret policy data; callers receive an owned copy.
func EncodePolicyArtifact(artifact PolicyArtifact) ([]byte, error) {
	return encodePolicyArtifact(artifact)
}

func (a PolicyArtifact) valid() bool {
	if !nonzero32(a.digest) ||
		validatePolicyProgram(a.ipv4) != nil ||
		validateRuntimePolicy(a.runtimePolicy) != nil {
		return false
	}
	switch a.posture {
	case PolicyIPv6DenyViaIP6Tables:
		if validatePolicyProgram(a.ipv6) != nil {
			return false
		}
	case PolicyIPv6KernelDisabled:
		if len(a.ipv6) != 0 {
			return false
		}
	default:
		return false
	}
	preimage := encodePolicyPreimage(a)
	digest := sha256.Sum256(preimage)
	zeroBytes(preimage)
	return digest == a.digest
}

func encodePolicyArtifact(artifact PolicyArtifact) ([]byte, error) {
	if !artifact.valid() {
		return nil, errors.New("hostruntime: policy artifact invalid")
	}
	preimage := encodePolicyPreimage(artifact)
	frame := make([]byte, 0, len(preimage)+sha256.Size)
	frame = append(frame, preimage[:policyFrameHeaderBytes]...)
	frame = append(frame, artifact.digest[:]...)
	frame = append(frame, preimage[policyFrameHeaderBytes:]...)
	zeroBytes(preimage)
	return frame, nil
}

func encodePolicyPreimage(artifact PolicyArtifact) []byte {
	frame := make(
		[]byte,
		policyFrameHeaderBytes+
			len(artifact.ipv4)+len(artifact.ipv6)+len(artifact.runtimePolicy),
	)
	copy(frame[:8], policyFrameMagic[:])
	frame[8] = byte(artifact.posture)
	binary.BigEndian.PutUint32(frame[9:13], uint32(len(artifact.ipv4)))
	binary.BigEndian.PutUint32(frame[13:17], uint32(len(artifact.ipv6)))
	binary.BigEndian.PutUint32(frame[17:21], uint32(len(artifact.runtimePolicy)))
	copy(frame[policyFrameHeaderBytes:], artifact.ipv4)
	copy(frame[policyFrameHeaderBytes+len(artifact.ipv4):], artifact.ipv6)
	copy(
		frame[policyFrameHeaderBytes+len(artifact.ipv4)+len(artifact.ipv6):],
		artifact.runtimePolicy,
	)
	return frame
}

func validatePolicyProgram(program []byte) error {
	if len(program) == 0 || len(program) > maxPolicyProgramBytes ||
		program[len(program)-1] != '\n' {
		return errors.New("hostruntime: policy program size invalid")
	}
	for _, value := range program {
		if value == 0 || value == '\r' ||
			(value < 0x20 && value != '\n' && value != '\t') ||
			value > 0x7e {
			return errors.New("hostruntime: policy program bytes invalid")
		}
	}
	lines := strings.Split(string(program[:len(program)-1]), "\n")
	if len(lines) < 8 ||
		lines[0] != "*filter" ||
		lines[1] != ":INPUT DROP [0:0]" ||
		lines[2] != ":FORWARD DROP [0:0]" ||
		lines[3] != ":OUTPUT DROP [0:0]" ||
		lines[len(lines)-1] != "COMMIT" {
		return errors.New("hostruntime: policy program shape invalid")
	}
	seen := make(map[string]struct{}, len(lines))
	required := map[string]bool{
		"-A INPUT -i lo -j ACCEPT":                                       false,
		"-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT":  false,
		"-A OUTPUT -o lo -j ACCEPT":                                      false,
		"-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT": false,
	}
	tcpAllowSeen := false
	for _, line := range lines[4 : len(lines)-1] {
		if line == "" {
			return errors.New("hostruntime: policy program empty rule")
		}
		if _, duplicate := seen[line]; duplicate {
			return errors.New("hostruntime: policy program duplicated rule")
		}
		seen[line] = struct{}{}
		if _, found := required[line]; found {
			required[line] = true
			continue
		}
		rule, err := validatePolicyRule(line)
		if err != nil {
			return err
		}
		if rule == policyRuleDeny && tcpAllowSeen {
			return errors.New("hostruntime: policy deny follows tcp allow")
		}
		if rule == policyRuleTCPAllow {
			tcpAllowSeen = true
		}
	}
	for _, found := range required {
		if !found {
			return errors.New("hostruntime: policy base rule missing")
		}
	}
	return nil
}

type policyRuleKind uint8

const (
	policyRuleOther policyRuleKind = iota + 1
	policyRuleDeny
	policyRuleTCPAllow
)

func validatePolicyRule(line string) (policyRuleKind, error) {
	fields := strings.Fields(line)
	if len(fields) == 6 &&
		fields[0] == "-A" && fields[1] == "OUTPUT" &&
		fields[2] == "-d" && fields[4] == "-j" && fields[5] == "DROP" {
		prefix, err := netip.ParsePrefix(fields[3])
		if err != nil || prefix.String() != fields[3] ||
			prefix != prefix.Masked() {
			return 0, errors.New("hostruntime: policy deny prefix invalid")
		}
		return policyRuleDeny, nil
	}
	if validTCPAllowRule(fields) {
		return policyRuleTCPAllow, nil
	}
	if validICMPRule(fields) {
		return policyRuleOther, nil
	}
	return 0, errors.New("hostruntime: policy rule invalid")
}

func validTCPAllowRule(fields []string) bool {
	index := 0
	if len(fields) != 12 && len(fields) != 14 {
		return false
	}
	if fields[0] != "-A" || fields[1] != "OUTPUT" ||
		fields[2] != "-p" || fields[3] != "tcp" {
		return false
	}
	index = 4
	if len(fields) == 14 {
		if fields[index] != "-d" {
			return false
		}
		prefix, err := netip.ParsePrefix(fields[index+1])
		if err != nil || prefix.String() != fields[index+1] ||
			prefix != prefix.Masked() {
			return false
		}
		index += 2
	}
	if fields[index] != "--dport" {
		return false
	}
	port, err := strconv.ParseUint(fields[index+1], 10, 16)
	if err != nil || port == 0 || strconv.FormatUint(port, 10) != fields[index+1] {
		return false
	}
	return slices.Equal(fields[index+2:], []string{
		"-m", "conntrack", "--ctstate", "NEW", "-j", "ACCEPT",
	})
}

func validICMPRule(fields []string) bool {
	if len(fields) != 8 || fields[0] != "-A" ||
		(fields[1] != "INPUT" && fields[1] != "OUTPUT") ||
		fields[2] != "-p" || fields[6] != "-j" || fields[7] != "ACCEPT" {
		return false
	}
	switch {
	case fields[3] == "icmp" && fields[1] == "INPUT" &&
		fields[4] == "--icmp-type":
		return fields[5] == "3" || fields[5] == "11"
	case fields[3] == "ipv6-icmp" && fields[4] == "--icmpv6-type":
		kind, err := strconv.ParseUint(fields[5], 10, 8)
		if err != nil || strconv.FormatUint(kind, 10) != fields[5] {
			return false
		}
		if fields[1] == "INPUT" {
			return kind == 1 || kind == 2 || kind == 3 || kind == 4 ||
				kind == 134 || kind == 135 || kind == 136
		}
		return kind == 133 || kind == 135 || kind == 136
	default:
		return false
	}
}

func validateRuntimePolicy(document []byte) error {
	if len(document) == 0 || len(document) > maxRuntimePolicyBytes ||
		document[len(document)-1] != '\n' {
		return errors.New("hostruntime: runtime policy size invalid")
	}
	for _, value := range document {
		if value == 0 || value == '\r' ||
			(value < 0x20 && value != '\n') ||
			value > 0x7e {
			return errors.New("hostruntime: runtime policy bytes invalid")
		}
	}
	return nil
}
