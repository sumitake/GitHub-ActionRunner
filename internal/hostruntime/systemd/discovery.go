package systemd

import (
	"fmt"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

func parseNetworkDocument(
	document []byte,
	maxBytes int,
) (hostruntime.NetworkSnapshot, error) {
	snapshot, err := hostruntime.ParseNetworkDiscovery(document, maxBytes)
	if err != nil {
		return hostruntime.NetworkSnapshot{}, fmt.Errorf(
			"%w: network document: %w",
			ErrProfileUnavailable,
			err,
		)
	}
	return snapshot, nil
}
