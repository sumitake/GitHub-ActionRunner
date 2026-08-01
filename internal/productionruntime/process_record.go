package productionruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"

	"github.com/sumitake/portable-ghar/internal/fleetfence"
)

const (
	MaxProcessRecordBytes = 4 << 10

	processRecordSchemaVersion = uint32(2)
	processRecordDigestDomain  = "portable-ghar-process-record-v2"
)

var ErrInvalidProcessRecord = errors.New(
	"productionruntime: invalid process record",
)

type ProcessRecord struct {
	SchemaVersion          uint32           `json:"schema_version"`
	PID                    uint64           `json:"pid"`
	PGID                   uint64           `json:"pgid"`
	BootID                 string           `json:"boot_id"`
	PIDNamespaceInode      uint64           `json:"pid_namespace_inode"`
	StartTimeTicks         uint64           `json:"start_time_ticks"`
	ExecutableDigest       string           `json:"executable_digest"`
	ExecutableDevice       uint64           `json:"executable_device"`
	ExecutableInode        uint64           `json:"executable_inode"`
	PrivateOverlayRevision string           `json:"private_overlay_revision"`
	ManifestDigest         string           `json:"manifest_digest"`
	ActiveFleet            fleetfence.Fleet `json:"active_fleet"`
	FenceGeneration        uint64           `json:"fence_generation"`
}

func MarshalProcessRecord(record ProcessRecord) ([]byte, string, error) {
	if !validProcessRecord(record) {
		return nil, "", ErrInvalidProcessRecord
	}
	document, err := json.Marshal(record)
	if err != nil ||
		len(document) == 0 ||
		len(document) > MaxProcessRecordBytes {
		return nil, "", ErrInvalidProcessRecord
	}
	return document, digestArtifact(processRecordDigestDomain, document), nil
}

func ParseProcessRecord(
	document []byte,
	maxBytes int,
) (ProcessRecord, string, error) {
	var record ProcessRecord
	if maxBytes <= 0 ||
		maxBytes > MaxProcessRecordBytes ||
		len(document) == 0 ||
		len(document) > maxBytes ||
		len(document) > MaxProcessRecordBytes {
		return record, "", ErrInvalidProcessRecord
	}

	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return ProcessRecord{}, "", ErrInvalidProcessRecord
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ProcessRecord{}, "", ErrInvalidProcessRecord
	}

	canonical, err := json.Marshal(record)
	if err != nil ||
		!bytes.Equal(canonical, document) ||
		!validProcessRecord(record) {
		return ProcessRecord{}, "", ErrInvalidProcessRecord
	}
	return record, digestArtifact(processRecordDigestDomain, document), nil
}

func validProcessRecord(record ProcessRecord) bool {
	return record.SchemaVersion == processRecordSchemaVersion &&
		record.PID > 0 &&
		record.PID <= uint64(math.MaxInt32) &&
		record.PGID > 0 &&
		record.PGID <= uint64(math.MaxInt32) &&
		record.PGID == record.PID &&
		validProcessRecordBootID(record.BootID) &&
		record.PIDNamespaceInode > 0 &&
		record.StartTimeTicks > 0 &&
		lowerHexDigest(record.ExecutableDigest) &&
		record.ExecutableDevice > 0 &&
		record.ExecutableInode > 0 &&
		lowerHexDigest(record.PrivateOverlayRevision) &&
		lowerHexDigest(record.ManifestDigest) &&
		(record.ActiveFleet == fleetfence.FleetPortable ||
			record.ActiveFleet == fleetfence.FleetLegacy) &&
		record.FenceGeneration > 0
}

func validProcessRecordBootID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range []byte(value) {
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return false
			}
		default:
			if (character < '0' || character > '9') &&
				(character < 'a' || character > 'f') {
				return false
			}
		}
	}
	return true
}
