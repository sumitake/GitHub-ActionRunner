// Package relaycontract defines the closed, bounded controller-to-adapter
// broker identity frame. It carries no authority by itself: hostruntime emits
// it only after consuming an opaque BrokerPeerProof, and the adapter rechecks
// every identity against live descriptors.
package relaycontract

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const (
	HTTPSProxySocket = "https.sock"
	MaxBindingBytes  = 4096
)

type Binding struct {
	Version          uint8     `json:"version"`
	BrokerGeneration uint64    `json:"broker_generation"`
	Directory        Directory `json:"directory"`
	Socket           Socket    `json:"socket"`
	Peer             Process   `json:"peer"`
}

type Directory struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Mode   uint32 `json:"mode"`
}

type Socket struct {
	Name   string `json:"name"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Mode   uint32 `json:"mode"`
}

type Process struct {
	PID       uint32 `json:"pid"`
	StartTime uint64 `json:"start_time"`
}

func Validate(binding Binding) error {
	if binding.Version != 1 || binding.BrokerGeneration == 0 ||
		binding.Directory.Device == 0 || binding.Directory.Inode == 0 ||
		binding.Directory.Mode != 0o700 ||
		binding.Socket.Name != HTTPSProxySocket ||
		binding.Socket.Device != binding.Directory.Device || binding.Socket.Inode == 0 ||
		binding.Socket.UID != binding.Directory.UID || binding.Socket.GID != binding.Directory.GID ||
		binding.Socket.Mode != 0o600 ||
		binding.Peer.PID == 0 || binding.Peer.StartTime == 0 {
		return errors.New("relaycontract: binding invalid")
	}
	return nil
}

func Encode(binding Binding) ([]byte, error) {
	if err := Validate(binding); err != nil {
		return nil, err
	}
	document, err := json.Marshal(binding)
	if err != nil || len(document)+1 > MaxBindingBytes {
		return nil, errors.New("relaycontract: binding encoding failed")
	}
	return append(document, '\n'), nil
}

func Load(reader io.Reader) (Binding, error) {
	if reader == nil {
		return Binding{}, errors.New("relaycontract: binding reader required")
	}
	data, err := io.ReadAll(io.LimitReader(reader, MaxBindingBytes+1))
	if err != nil || len(data) == 0 || len(data) > MaxBindingBytes {
		return Binding{}, errors.New("relaycontract: binding size invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var binding Binding
	if err := decoder.Decode(&binding); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Binding{}, errors.New("relaycontract: binding json invalid")
	}
	if err := Validate(binding); err != nil {
		return Binding{}, err
	}
	canonical, err := Encode(binding)
	if err != nil || !bytes.Equal(canonical, data) {
		return Binding{}, errors.New("relaycontract: binding noncanonical")
	}
	return binding, nil
}
