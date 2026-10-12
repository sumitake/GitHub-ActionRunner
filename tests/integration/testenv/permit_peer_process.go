package testenv

import (
	"context"

	"github.com/sumitake/portable-ghar/internal/networkjail"
)

const maximumPermitProcDocumentBytes = int64(64 << 10)

// linuxPermitPeerProcessObserver reads the peer's /proc identity through the
// production observer.
type linuxPermitPeerProcessObserver struct{}

func (linuxPermitPeerProcessObserver) ObservePermitPeerProcess(
	ctx context.Context,
	pid int,
) (permitPeerProcessObservation, error) {
	process, err := networkjail.ObservePermitPeerProcess(ctx, pid)
	if err != nil {
		return permitPeerProcessObservation{}, networkjail.ErrPermitPeerInvalid
	}
	return permitPeerProcessObservation{
		UID:       process.UID,
		StartTime: process.StartTime,
	}, nil
}

var _ permitPeerProcessObserver = linuxPermitPeerProcessObserver{}
