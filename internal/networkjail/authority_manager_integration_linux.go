//go:build integration && linux

package networkjail

import (
	"context"
	"errors"
	"os"
	"path/filepath"
)

// ShutdownIntegrationAuthority provides exact process-loss hygiene for the
// Linux integration restart matrix. It is intentionally absent from
// production builds and returns no reusable authority or cleanup evidence.
func (manager *UnixAuthorityManager) ShutdownIntegrationAuthority(
	ctx context.Context,
	slot CapacitySlotID,
	generation JobGeneration,
	directory string,
) error {
	if manager == nil ||
		ctx == nil ||
		ctx.Err() != nil ||
		slot == 0 ||
		generation == 0 ||
		!filepath.IsAbs(directory) ||
		filepath.Clean(directory) != directory {
		return ErrPermitAuthorityUnavailable
	}
	socketPath := filepath.Join(directory, "dial-authority.sock")
	if filepath.Dir(socketPath) != directory {
		return ErrPermitAuthorityUnavailable
	}

	manager.mu.Lock()
	endpoint, exact, valid := manager.integrationAuthorityClaimLocked(
		slot,
		generation,
		socketPath,
	)
	manager.mu.Unlock()
	if !valid {
		return ErrPermitAuthorityUnavailable
	}

	if !exact {
		if _, err := os.Lstat(socketPath); !errors.Is(
			err,
			os.ErrNotExist,
		) {
			return ErrPermitAuthorityUnavailable
		}
		if _, err := manager.authority.ActiveRevision(
			ctx,
			slot,
			generation,
		); !errors.Is(err, ErrPermitAssignment) {
			return ErrPermitAuthorityUnavailable
		}
		return manager.proveIntegrationAuthorityAbsent(
			ctx,
			slot,
			generation,
			socketPath,
		)
	}

	if endpoint == nil {
		return ErrPermitAuthorityUnavailable
	}
	if err := manager.Stop(ctx, authorityLease{
		slotID:        uint32(slot),
		jobGeneration: uint64(generation),
		socketPath:    socketPath,
		socket:        endpoint.socket,
		endpoint:      endpoint,
		valid:         true,
	}); err != nil {
		return ErrPermitAuthorityUnavailable
	}
	return manager.proveIntegrationAuthorityAbsent(
		ctx,
		slot,
		generation,
		socketPath,
	)
}

func (manager *UnixAuthorityManager) integrationAuthorityClaimLocked(
	slot CapacitySlotID,
	generation JobGeneration,
	socketPath string,
) (*managedUnixAuthority, bool, bool) {
	var exact *managedUnixAuthority
	for key, endpoint := range manager.active {
		if endpoint == nil {
			if key == socketPath {
				return nil, false, false
			}
			continue
		}
		claimsPath := key == socketPath ||
			endpoint.socketPath == socketPath
		claimsSlot := endpoint.slot == slot
		claimsGeneration := endpoint.generation == generation
		if !claimsPath && !claimsSlot && !claimsGeneration {
			continue
		}
		if key != socketPath ||
			endpoint.socketPath != socketPath ||
			!claimsSlot ||
			!claimsGeneration ||
			exact != nil {
			return nil, false, false
		}
		exact = endpoint
	}
	if exact == nil {
		return nil, false, true
	}
	return exact, true, true
}

// ProveIntegrationAuthorityAbsent is a read-only exact-tuple absence proof for
// the Linux integration harness. Unlike ShutdownIntegrationAuthority, it
// never stops an endpoint, removes a socket, or deactivates a permit ledger.
func (manager *UnixAuthorityManager) ProveIntegrationAuthorityAbsent(
	ctx context.Context,
	slot CapacitySlotID,
	generation JobGeneration,
	directory string,
) error {
	if manager == nil ||
		ctx == nil ||
		ctx.Err() != nil ||
		slot == 0 ||
		generation == 0 ||
		!filepath.IsAbs(directory) ||
		filepath.Clean(directory) != directory {
		return ErrPermitAuthorityUnavailable
	}
	socketPath := filepath.Join(directory, "dial-authority.sock")
	if filepath.Dir(socketPath) != directory {
		return ErrPermitAuthorityUnavailable
	}
	return manager.proveIntegrationAuthorityAbsent(
		ctx,
		slot,
		generation,
		socketPath,
	)
}

func (manager *UnixAuthorityManager) proveIntegrationAuthorityAbsent(
	ctx context.Context,
	slot CapacitySlotID,
	generation JobGeneration,
	socketPath string,
) error {
	if _, err := os.Lstat(socketPath); !errors.Is(
		err,
		os.ErrNotExist,
	) {
		return ErrPermitAuthorityUnavailable
	}
	if _, err := manager.authority.ActiveRevision(
		ctx,
		slot,
		generation,
	); !errors.Is(err, ErrPermitAssignment) {
		return ErrPermitAuthorityUnavailable
	}
	manager.mu.Lock()
	_, exact, valid := manager.integrationAuthorityClaimLocked(
		slot,
		generation,
		socketPath,
	)
	manager.mu.Unlock()
	if !valid || exact {
		return ErrPermitAuthorityUnavailable
	}
	return nil
}
