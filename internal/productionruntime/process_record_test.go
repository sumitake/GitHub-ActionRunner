package productionruntime

import (
	"bytes"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/sumitake/portable-ghar/internal/fleetfence"
)

func TestProcessRecordRoundTripAndDigestIdentity(t *testing.T) {
	t.Parallel()

	record := validProcessRecordFixture()
	document, digest, err := MarshalProcessRecord(record)
	if err != nil {
		t.Fatalf("MarshalProcessRecord() error = %v", err)
	}
	if len(document) == 0 || len(document) > MaxProcessRecordBytes {
		t.Fatalf("document length = %d", len(document))
	}
	if bytes.ContainsAny(document, " \n\t\r") {
		t.Fatalf("document is not compact canonical JSON: %q", document)
	}

	parsed, parsedDigest, err := ParseProcessRecord(
		document,
		MaxProcessRecordBytes,
	)
	if err != nil {
		t.Fatalf("ParseProcessRecord() error = %v", err)
	}
	if parsed != record {
		t.Fatalf("parsed record = %#v, want %#v", parsed, record)
	}
	if parsedDigest != digest || !lowerHexDigest(digest) {
		t.Fatalf("parsed digest = %q, want %q", parsedDigest, digest)
	}

	mutated := record
	mutated.StartTimeTicks++
	_, mutatedDigest, err := MarshalProcessRecord(mutated)
	if err != nil {
		t.Fatalf("MarshalProcessRecord(mutated) error = %v", err)
	}
	if mutatedDigest == digest {
		t.Fatal("record mutation did not change digest")
	}
}

func TestProcessRecordRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*ProcessRecord)
	}{
		{"schema-v1", func(record *ProcessRecord) { record.SchemaVersion = 1 }},
		{"schema-future", func(record *ProcessRecord) { record.SchemaVersion = 3 }},
		{"pid-zero", func(record *ProcessRecord) { record.PID = 0 }},
		{"pid-overflow", func(record *ProcessRecord) {
			record.PID = uint64(math.MaxInt32) + 1
		}},
		{"pgid-zero", func(record *ProcessRecord) { record.PGID = 0 }},
		{"pgid-overflow", func(record *ProcessRecord) {
			record.PGID = uint64(math.MaxInt32) + 1
		}},
		{"pgid-not-pid", func(record *ProcessRecord) { record.PGID++ }},
		{"boot-id-empty", func(record *ProcessRecord) { record.BootID = "" }},
		{"boot-id-noncanonical", func(record *ProcessRecord) {
			record.BootID = strings.ToUpper(record.BootID)
		}},
		{"pid-namespace-zero", func(record *ProcessRecord) {
			record.PIDNamespaceInode = 0
		}},
		{"start-zero", func(record *ProcessRecord) {
			record.StartTimeTicks = 0
		}},
		{"executable-digest-uppercase", func(record *ProcessRecord) {
			record.ExecutableDigest = strings.ToUpper(record.ExecutableDigest)
		}},
		{"executable-digest-short", func(record *ProcessRecord) {
			record.ExecutableDigest = "00"
		}},
		{"device-zero", func(record *ProcessRecord) {
			record.ExecutableDevice = 0
		}},
		{"inode-zero", func(record *ProcessRecord) {
			record.ExecutableInode = 0
		}},
		{"overlay-uppercase", func(record *ProcessRecord) {
			record.PrivateOverlayRevision =
				strings.ToUpper(record.PrivateOverlayRevision)
		}},
		{"manifest-short", func(record *ProcessRecord) {
			record.ManifestDigest = "00"
		}},
		{"fleet-none", func(record *ProcessRecord) {
			record.ActiveFleet = fleetfence.FleetNone
		}},
		{"fleet-unknown", func(record *ProcessRecord) {
			record.ActiveFleet = fleetfence.Fleet("unknown")
		}},
		{"generation-zero", func(record *ProcessRecord) {
			record.FenceGeneration = 0
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			record := validProcessRecordFixture()
			test.mutate(&record)
			if _, _, err := MarshalProcessRecord(record); !errors.Is(
				err,
				ErrInvalidProcessRecord,
			) {
				t.Fatalf("MarshalProcessRecord() error = %v", err)
			}
		})
	}
}

func TestProcessRecordParseRejectsNoncanonicalDocuments(t *testing.T) {
	t.Parallel()

	record := validProcessRecordFixture()
	document, _, err := MarshalProcessRecord(record)
	if err != nil {
		t.Fatalf("MarshalProcessRecord() error = %v", err)
	}

	tests := []struct {
		name     string
		document []byte
		maxBytes int
	}{
		{"empty", nil, MaxProcessRecordBytes},
		{
			"oversize",
			bytes.Repeat([]byte{'x'}, MaxProcessRecordBytes+1),
			MaxProcessRecordBytes,
		},
		{"zero-limit", document, 0},
		{
			"unknown-field",
			append(document[:len(document)-1], []byte(`,"unknown":1}`)...),
			MaxProcessRecordBytes,
		},
		{
			"schema-v1",
			bytes.Replace(
				document,
				[]byte(`"schema_version":2`),
				[]byte(`"schema_version":1`),
				1,
			),
			MaxProcessRecordBytes,
		},
		{
			"schema-future",
			bytes.Replace(
				document,
				[]byte(`"schema_version":2`),
				[]byte(`"schema_version":3`),
				1,
			),
			MaxProcessRecordBytes,
		},
		{
			"schema-v2-hybrid-missing-boot-id",
			bytes.Replace(
				document,
				[]byte(`,"boot_id":"`+record.BootID+`"`),
				nil,
				1,
			),
			MaxProcessRecordBytes,
		},
		{
			"trailing-value",
			append(append([]byte(nil), document...), []byte(`{}`)...),
			MaxProcessRecordBytes,
		},
		{
			"trailing-newline",
			append(append([]byte(nil), document...), '\n'),
			MaxProcessRecordBytes,
		},
		{
			"noncanonical-whitespace",
			append([]byte{' '}, document...),
			MaxProcessRecordBytes,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := ParseProcessRecord(
				test.document,
				test.maxBytes,
			); !errors.Is(err, ErrInvalidProcessRecord) {
				t.Fatalf("ParseProcessRecord() error = %v", err)
			}
		})
	}
}

func validProcessRecordFixture() ProcessRecord {
	return ProcessRecord{
		SchemaVersion:          2,
		PID:                    101,
		PGID:                   101,
		BootID:                 syntheticBootID(),
		PIDNamespaceInode:      100,
		StartTimeTicks:         202,
		ExecutableDigest:       strings.Repeat("a", 64),
		ExecutableDevice:       303,
		ExecutableInode:        404,
		PrivateOverlayRevision: strings.Repeat("b", 64),
		ManifestDigest:         strings.Repeat("c", 64),
		ActiveFleet:            fleetfence.FleetPortable,
		FenceGeneration:        505,
	}
}

func syntheticBootID() string {
	return strings.Join(
		[]string{"01234567", "89ab", "cdef", "0123", "456789abcdef"},
		"-",
	)
}
