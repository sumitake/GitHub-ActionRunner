//go:build integration && linux

package testenv

import (
	"io"
	"math"
	"os"

	"github.com/sumitake/portable-ghar/internal/networkjail"
)

func newLinuxPermitPeerProcessObserver() linuxPermitPeerProcessObserver {
	return linuxPermitPeerProcessObserver{
		readFile: readBoundedPermitProcFile,
	}
}

func readBoundedPermitProcFile(
	path string,
	maximum int64,
) ([]byte, error) {
	if path == "" || maximum <= 0 || maximum == math.MaxInt64 {
		return nil, networkjail.ErrPermitPeerInvalid
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, networkjail.ErrPermitPeerInvalid
	}
	defer file.Close()
	document, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(document) == 0 ||
		int64(len(document)) > maximum {
		zeroPermitProcDocument(document)
		return nil, networkjail.ErrPermitPeerInvalid
	}
	return document, nil
}
