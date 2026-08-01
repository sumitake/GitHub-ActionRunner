//go:build linux || darwin

package networkjail

import (
	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/unixsocketguard"
)

const authoritySocketLiteral = "dial-authority.sock"

type authoritySocketPin struct {
	guard *unixsocketguard.OwnedGuard
}

func openAuthoritySocketPin(
	directoryPath string,
	directory hostruntime.DirectoryIdentity,
	socket hostruntime.SocketIdentity,
) (*authoritySocketPin, error) {
	if socket.Name != authoritySocketLiteral {
		return nil, ErrPermitAuthorityUnavailable
	}
	guard, err := unixsocketguard.OpenOwned(
		directoryPath,
		unixsocketguard.Snapshot{
			Directory: unixsocketguard.DirectoryIdentity{
				Device: directory.Device,
				Inode:  directory.Inode,
				UID:    directory.UID,
				GID:    directory.GID,
				Mode:   directory.Mode,
			},
			Socket: unixsocketguard.SocketIdentity{
				Name:   socket.Name,
				Device: socket.Device,
				Inode:  socket.Inode,
				UID:    socket.UID,
				GID:    socket.GID,
				Mode:   socket.Mode,
			},
		},
	)
	if err != nil {
		return nil, ErrPermitAuthorityUnavailable
	}
	return &authoritySocketPin{guard: guard}, nil
}

func (pin *authoritySocketPin) verify() error {
	if pin == nil || pin.guard == nil || pin.guard.Verify() != nil {
		return ErrPermitAuthorityUnavailable
	}
	return nil
}

func (pin *authoritySocketPin) remove() error {
	if pin == nil || pin.guard == nil || pin.guard.Remove() != nil {
		return ErrPermitAuthorityUnavailable
	}
	return nil
}

func (pin *authoritySocketPin) close() error {
	if pin == nil || pin.guard == nil {
		return nil
	}
	err := pin.guard.Close()
	pin.guard = nil
	if err != nil {
		return ErrPermitAuthorityUnavailable
	}
	return nil
}
