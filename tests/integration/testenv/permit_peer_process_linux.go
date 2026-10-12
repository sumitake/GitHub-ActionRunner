//go:build integration && linux

package testenv

import (
	"bytes"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
)

func newLinuxPermitPeerProcessObserver() linuxPermitPeerProcessObserver {
	return linuxPermitPeerProcessObserver{}
}

// parsePermitProcStatStartTime parses one newline-terminated /proc stat
// document for the cleanup probe.
func parsePermitProcStatStartTime(document []byte) (uint64, error) {
	if len(document) == 0 ||
		len(document) > int(maximumPermitProcDocumentBytes) ||
		document[len(document)-1] != '\n' ||
		bytes.Count(document, []byte{'\n'}) != 1 ||
		bytes.IndexByte(document, 0) >= 0 ||
		bytes.IndexByte(document, '\r') >= 0 {
		return 0, networkjail.ErrPermitPeerInvalid
	}
	startTime, err := hostruntime.ParseLinuxProcStatStartTime(
		document[:len(document)-1],
	)
	if err != nil {
		return 0, networkjail.ErrPermitPeerInvalid
	}
	return startTime, nil
}
