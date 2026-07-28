package hostruntime

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"slices"
)

const maxBrokerReleaseFrameBytes = brokerReleasePrefix +
	releaseTokenBytes + maxRuntimePolicyBytes + maxAuthorityProofBytes

type BrokerReleaseCommand struct {
	policyDigest        [sha256.Size]byte
	runtimePolicyDigest [sha256.Size]byte
	token               [releaseTokenBytes]byte
	runtimePolicy       []byte
	authority           AuthorityBinding
}

func DecodeBrokerArmDigest(reader io.Reader) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	if reader == nil {
		return digest, errors.New("hostruntime: broker arm unavailable")
	}
	frame, err := io.ReadAll(io.LimitReader(reader, brokerArmFrameBytes+1))
	if err != nil || len(frame) != brokerArmFrameBytes ||
		!bytes.Equal(frame[:8], []byte("PGHBRARM")) ||
		frame[8] != 1 || frame[9] != 1 ||
		binary.BigEndian.Uint16(frame[10:12]) != sha256.Size {
		zeroBytes(frame)
		return digest, errors.New("hostruntime: broker arm invalid")
	}
	copy(digest[:], frame[12:])
	zeroBytes(frame)
	if !nonzero32(digest) {
		return [sha256.Size]byte{}, errors.New("hostruntime: broker arm digest invalid")
	}
	return digest, nil
}

func DecodeBrokerReleaseCommand(reader io.Reader) (BrokerReleaseCommand, error) {
	if reader == nil {
		return BrokerReleaseCommand{}, errors.New("hostruntime: broker release unavailable")
	}
	frame, err := io.ReadAll(io.LimitReader(reader, maxBrokerReleaseFrameBytes+1))
	if err != nil || len(frame) < brokerReleasePrefix+releaseTokenBytes ||
		len(frame) > maxBrokerReleaseFrameBytes ||
		!bytes.Equal(frame[:8], []byte("PGHBRREL")) ||
		frame[8] != 1 ||
		binary.BigEndian.Uint16(frame[9:11]) != releaseTokenBytes {
		zeroBytes(frame)
		return BrokerReleaseCommand{}, errors.New("hostruntime: broker release invalid")
	}
	authorityBytes := int(binary.BigEndian.Uint32(frame[43:47]))
	runtimeBytes := int(binary.BigEndian.Uint32(frame[47:51]))
	if authorityBytes <= 0 || authorityBytes > maxAuthorityProofBytes ||
		runtimeBytes <= 0 || runtimeBytes > maxRuntimePolicyBytes ||
		len(frame) != brokerReleasePrefix+releaseTokenBytes+
			runtimeBytes+authorityBytes {
		zeroBytes(frame)
		return BrokerReleaseCommand{}, errors.New("hostruntime: broker release length invalid")
	}
	var command BrokerReleaseCommand
	copy(command.policyDigest[:], frame[11:43])
	copy(command.runtimePolicyDigest[:], frame[51:83])
	copy(
		command.token[:],
		frame[brokerReleasePrefix:brokerReleasePrefix+releaseTokenBytes],
	)
	runtimeOffset := brokerReleasePrefix + releaseTokenBytes
	command.runtimePolicy = slices.Clone(
		frame[runtimeOffset : runtimeOffset+runtimeBytes],
	)
	authorityDocument := frame[runtimeOffset+runtimeBytes:]
	authority, authorityErr := parseAuthorityBinding(authorityDocument)
	zeroBytes(frame)
	if authorityErr != nil ||
		!nonzero32(command.policyDigest) ||
		!nonzero32(command.runtimePolicyDigest) ||
		!nonzero32(command.token) ||
		validateRuntimePolicy(command.runtimePolicy) != nil ||
		sha256.Sum256(command.runtimePolicy) != command.runtimePolicyDigest {
		command.Destroy()
		return BrokerReleaseCommand{}, errors.New("hostruntime: broker release fields invalid")
	}
	command.authority = authority
	return command, nil
}

func (command BrokerReleaseCommand) PolicyDigest() [sha256.Size]byte {
	return command.policyDigest
}

func (command BrokerReleaseCommand) RuntimePolicyDigest() [sha256.Size]byte {
	return command.runtimePolicyDigest
}

func (command BrokerReleaseCommand) ReleaseToken() [releaseTokenBytes]byte {
	return command.token
}

func (command BrokerReleaseCommand) RuntimePolicy() []byte {
	return slices.Clone(command.runtimePolicy)
}

func (command BrokerReleaseCommand) Authority() AuthorityBinding {
	return command.authority
}

func (command *BrokerReleaseCommand) Destroy() {
	if command == nil {
		return
	}
	zeroBytes(command.policyDigest[:])
	zeroBytes(command.runtimePolicyDigest[:])
	zeroBytes(command.token[:])
	zeroBytes(command.runtimePolicy)
	command.runtimePolicy = nil
	command.authority = AuthorityBinding{}
}
