package hostruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const (
	dialAuthoritySocketName = "dial-authority.sock"
	maxAuthorityProofBytes  = 4096
)

// DirectoryIdentity and SocketIdentity contain only nonsecret kernel identity
// metadata. BindDialAuthority independently reads the mounted objects back;
// these values are never sufficient on their own.
type DirectoryIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Mode   uint32 `json:"mode"`
}

type SocketIdentity struct {
	Name   string `json:"name"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Mode   uint32 `json:"mode"`
}

type ProcessIdentity struct {
	PID       uint32 `json:"pid"`
	StartTime uint64 `json:"start_time"`
}

// AuthorityBinding is the controller-owned, nonsecret identity expected at
// the broker's fixed read-only authority mount.
type AuthorityBinding struct {
	Version        uint8             `json:"version"`
	CapacitySlotID uint32            `json:"capacity_slot_id"`
	JobGeneration  uint64            `json:"job_generation"`
	LedgerRevision uint64            `json:"ledger_revision"`
	Directory      DirectoryIdentity `json:"directory"`
	Socket         SocketIdentity    `json:"socket"`
	Peer           ProcessIdentity   `json:"peer"`
}

// AuthorityProof hides the binding after validation. Live directory/socket
// readback and post-release peer proof remain mandatory.
type AuthorityProof struct {
	binding AuthorityBinding
}

type authorityFilesystemWire struct {
	Version   uint8             `json:"version"`
	Directory DirectoryIdentity `json:"directory"`
	Socket    SocketIdentity    `json:"socket"`
}

func NewAuthorityProof(binding AuthorityBinding) (AuthorityProof, error) {
	if err := validateAuthorityBinding(binding); err != nil {
		return AuthorityProof{}, err
	}
	return AuthorityProof{binding: binding}, nil
}

// MatchesPermitActivation reveals only whether this opaque proof binds the
// exact assignment tuple and activation revision. It exposes no filesystem,
// socket, peer, or raw authority metadata.
func (proof AuthorityProof) MatchesPermitActivation(
	slot uint32,
	generation uint64,
	activationRevision uint64,
) bool {
	return slot != 0 && generation != 0 && activationRevision != 0 &&
		proof.binding.CapacitySlotID == slot &&
		proof.binding.JobGeneration == generation &&
		proof.binding.LedgerRevision == activationRevision
}

func DecodeAuthorityBinding(reader io.Reader) (AuthorityBinding, error) {
	if reader == nil {
		return AuthorityBinding{}, errors.New("hostruntime: authority identity unavailable")
	}
	document, err := io.ReadAll(io.LimitReader(reader, maxAuthorityProofBytes+1))
	if err != nil || len(document) == 0 || len(document) > maxAuthorityProofBytes {
		zeroBytes(document)
		return AuthorityBinding{}, errors.New("hostruntime: authority identity invalid")
	}
	binding, err := parseAuthorityBinding(document)
	zeroBytes(document)
	return binding, err
}

func validateAuthorityBinding(binding AuthorityBinding) error {
	if binding.Version != 1 || binding.CapacitySlotID == 0 ||
		binding.JobGeneration == 0 || binding.LedgerRevision == 0 ||
		binding.Directory.Device == 0 || binding.Directory.Inode == 0 ||
		binding.Directory.Mode != 0o700 ||
		binding.Socket.Name != dialAuthoritySocketName ||
		binding.Socket.Device != binding.Directory.Device ||
		binding.Socket.Inode == 0 ||
		binding.Socket.UID != binding.Directory.UID ||
		binding.Socket.GID != binding.Directory.GID ||
		binding.Socket.Mode != 0o600 ||
		binding.Peer.PID == 0 || binding.Peer.StartTime == 0 {
		return errors.New("hostruntime: authority binding invalid")
	}
	return nil
}

func encodeAuthorityBinding(binding AuthorityBinding) ([]byte, error) {
	if err := validateAuthorityBinding(binding); err != nil {
		return nil, err
	}
	document, err := json.Marshal(binding)
	if err != nil || len(document)+1 > maxAuthorityProofBytes {
		return nil, errors.New("hostruntime: authority binding encoding failed")
	}
	return append(document, '\n'), nil
}

func parseAuthorityBinding(data []byte) (AuthorityBinding, error) {
	if len(data) == 0 || len(data) > maxAuthorityProofBytes {
		return AuthorityBinding{}, errors.New("hostruntime: authority identity invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var binding AuthorityBinding
	if err := decoder.Decode(&binding); err != nil {
		return AuthorityBinding{}, errors.New("hostruntime: authority identity invalid")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return AuthorityBinding{}, errors.New("hostruntime: authority identity invalid")
	}
	if err := validateAuthorityBinding(binding); err != nil {
		return AuthorityBinding{}, err
	}
	canonical, err := encodeAuthorityBinding(binding)
	if err != nil || !bytes.Equal(canonical, data) {
		return AuthorityBinding{}, errors.New("hostruntime: authority identity noncanonical")
	}
	return binding, nil
}

func parseAuthorityFilesystem(data []byte) (authorityFilesystemWire, error) {
	if len(data) == 0 || len(data) > maxAuthorityProofBytes {
		return authorityFilesystemWire{}, errors.New("hostruntime: authority filesystem identity invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var wire authorityFilesystemWire
	if err := decoder.Decode(&wire); err != nil ||
		decoder.Decode(&struct{}{}) != io.EOF ||
		wire.Version != 1 ||
		wire.Directory.Device == 0 || wire.Directory.Inode == 0 ||
		wire.Directory.Mode != 0o700 ||
		wire.Socket.Name != dialAuthoritySocketName ||
		wire.Socket.Device != wire.Directory.Device ||
		wire.Socket.Inode == 0 ||
		wire.Socket.UID != wire.Directory.UID ||
		wire.Socket.GID != wire.Directory.GID ||
		wire.Socket.Mode != 0o600 {
		return authorityFilesystemWire{}, errors.New("hostruntime: authority filesystem identity invalid")
	}
	canonical, err := json.Marshal(wire)
	if err != nil {
		return authorityFilesystemWire{}, errors.New("hostruntime: authority filesystem identity invalid")
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(canonical, data) {
		return authorityFilesystemWire{}, errors.New("hostruntime: authority filesystem identity noncanonical")
	}
	return wire, nil
}
