package testenv

import (
	"bytes"
	"context"
	"strconv"
	"strings"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
	"github.com/sumitake/portable-ghar/internal/networkjail"
)

const maximumPermitProcDocumentBytes = int64(64 << 10)

type boundedPermitProcReader func(string, int64) ([]byte, error)

type linuxPermitPeerProcessObserver struct {
	readFile boundedPermitProcReader
}

func (o linuxPermitPeerProcessObserver) ObservePermitPeerProcess(
	ctx context.Context,
	pid int,
) (permitPeerProcessObservation, error) {
	if ctx == nil || ctx.Err() != nil || pid <= 0 ||
		o.readFile == nil {
		return permitPeerProcessObservation{},
			networkjail.ErrPermitPeerInvalid
	}
	base := "/proc/" + strconv.Itoa(pid)
	first, err := o.observe(ctx, base)
	if err != nil || ctx.Err() != nil {
		return permitPeerProcessObservation{},
			networkjail.ErrPermitPeerInvalid
	}
	second, err := o.observe(ctx, base)
	if err != nil || first != second {
		return permitPeerProcessObservation{},
			networkjail.ErrPermitPeerInvalid
	}
	return second, nil
}

func (o linuxPermitPeerProcessObserver) observe(
	ctx context.Context,
	base string,
) (permitPeerProcessObservation, error) {
	if ctx == nil || ctx.Err() != nil || base == "" {
		return permitPeerProcessObservation{},
			networkjail.ErrPermitPeerInvalid
	}
	status, err := o.readFile(
		base+"/status",
		maximumPermitProcDocumentBytes,
	)
	if err != nil || ctx.Err() != nil {
		return permitPeerProcessObservation{},
			networkjail.ErrPermitPeerInvalid
	}
	uid, ok := parsePermitProcStatusUID(status)
	zeroPermitProcDocument(status)
	if !ok {
		return permitPeerProcessObservation{},
			networkjail.ErrPermitPeerInvalid
	}
	stat, err := o.readFile(
		base+"/stat",
		maximumPermitProcDocumentBytes,
	)
	if err != nil || ctx.Err() != nil {
		zeroPermitProcDocument(stat)
		return permitPeerProcessObservation{},
			networkjail.ErrPermitPeerInvalid
	}
	startTime, err := parsePermitProcStatStartTime(stat)
	zeroPermitProcDocument(stat)
	if err != nil {
		return permitPeerProcessObservation{},
			networkjail.ErrPermitPeerInvalid
	}
	return permitPeerProcessObservation{
		UID:       uid,
		StartTime: startTime,
	}, nil
}

func parsePermitProcStatusUID(document []byte) (uint32, bool) {
	if len(document) == 0 ||
		len(document) > int(maximumPermitProcDocumentBytes) ||
		document[len(document)-1] != '\n' ||
		bytes.IndexByte(document, 0) >= 0 ||
		bytes.IndexByte(document, '\r') >= 0 {
		return 0, false
	}
	var (
		uid   uint64
		found bool
	)
	for _, line := range strings.Split(
		string(document[:len(document)-1]),
		"\n",
	) {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		if found || !strings.HasPrefix(line, "Uid:\t") {
			return 0, false
		}
		fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
		if len(fields) != 4 {
			return 0, false
		}
		for index, field := range fields {
			value, err := strconv.ParseUint(field, 10, 32)
			if err != nil || strconv.FormatUint(value, 10) != field {
				return 0, false
			}
			if index == 0 {
				uid = value
			} else if value != uid {
				return 0, false
			}
		}
		found = true
	}
	return uint32(uid), found
}

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

func zeroPermitProcDocument(document []byte) {
	for index := range document {
		document[index] = 0
	}
}

var _ permitPeerProcessObserver = linuxPermitPeerProcessObserver{}
