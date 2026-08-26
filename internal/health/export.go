package health

import (
	"encoding/json"
	"errors"
	"fmt"
)

const SnapshotSchemaVersion = 1

var ErrSnapshotExport = errors.New("health: snapshot export")

// Export is the closed, schema-versioned read-only health document.
type Export struct {
	SchemaVersion int      `json:"schema_version"`
	Snapshot      Snapshot `json:"snapshot"`
}

func (export Export) Validate() error {
	if export.SchemaVersion != SnapshotSchemaVersion {
		return fmt.Errorf("%w: schema", ErrSnapshotExport)
	}
	return export.Snapshot.Validate()
}

func EncodeExport(snapshot Snapshot) ([]byte, error) {
	export := Export{SchemaVersion: SnapshotSchemaVersion, Snapshot: snapshot}
	if err := export.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(export)
}
