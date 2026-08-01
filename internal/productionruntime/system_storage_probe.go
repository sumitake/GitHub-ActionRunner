package productionruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"

	"github.com/sumitake/portable-ghar/internal/hostruntime"
)

const maximumDockerRootOutputBytes = 4096

type systemStorageRole struct {
	path     string
	expected hostruntime.StorageObservationOverlay
}

// SystemStorageProbe binds the six declared storage roles to live filesystem
// identities. Docker's data root is discovered once through one fixed argv;
// callers cannot supply commands or additional roles.
type SystemStorageProbe struct {
	roles []systemStorageRole
}

func NewSystemStorageProbe(
	ctx context.Context,
	overlay hostruntime.PrivateOverlay,
	runner hostruntime.CommandRunner,
) (*SystemStorageProbe, error) {
	if ctx == nil || ctx.Err() != nil || runner == nil {
		return nil, ErrStorageEnvelope
	}
	if _, _, err := hostruntime.MarshalPrivateOverlay(overlay); err != nil {
		return nil, ErrStorageEnvelope
	}
	result, err := runner.Run(
		ctx,
		[]string{
			overlay.Commands.DockerBinary,
			"info",
			"--format",
			"{{json .DockerRootDir}}",
		},
		nil,
		nil,
	)
	if err != nil ||
		result.ExitCode != 0 ||
		result.Signaled ||
		result.Signal != "" ||
		result.StdoutTruncated ||
		result.StderrTruncated ||
		len(result.Stderr) != 0 {
		return nil, ErrStorageEnvelope
	}
	dockerRoot, ok := decodeDockerRoot(result.Stdout)
	if !ok {
		return nil, ErrStorageEnvelope
	}
	paths := [...]string{
		dockerRoot,
		overlay.Paths.StateRoot,
		overlay.Paths.StagingRoot,
		overlay.Paths.RollbackRoot,
		overlay.Paths.ScratchRoot,
		overlay.Paths.LogRoot,
	}
	if len(overlay.Resources.Storage.Observations) != len(paths) {
		return nil, ErrStorageEnvelope
	}
	roles := make([]systemStorageRole, len(paths))
	for index, path := range paths {
		roles[index] = systemStorageRole{
			path:     path,
			expected: overlay.Resources.Storage.Observations[index],
		}
	}
	return &SystemStorageProbe{roles: roles}, nil
}

func (probe *SystemStorageProbe) Snapshot(
	ctx context.Context,
) ([]StorageAvailability, error) {
	if probe == nil || ctx == nil || ctx.Err() != nil ||
		len(probe.roles) == 0 {
		return nil, ErrStorageEnvelope
	}
	snapshot := make([]StorageAvailability, 0, len(probe.roles))
	for _, role := range probe.roles {
		availability, err := probe.observeRole(ctx, role)
		if err != nil {
			return nil, ErrStorageEnvelope
		}
		snapshot = append(snapshot, availability)
	}
	return snapshot, nil
}

func (probe *SystemStorageProbe) Observe(
	ctx context.Context,
	expected hostruntime.LifecycleFilesystemIdentity,
) (StorageAvailability, error) {
	if probe == nil || ctx == nil || ctx.Err() != nil {
		return StorageAvailability{}, ErrStorageEnvelope
	}
	for _, role := range probe.roles {
		if role.expected.Role != expected.Role {
			continue
		}
		availability, err := probe.observeRole(ctx, role)
		if err != nil || availability.Filesystem != expected {
			return StorageAvailability{}, ErrStorageEnvelope
		}
		return availability, nil
	}
	return StorageAvailability{}, ErrStorageEnvelope
}

func (probe *SystemStorageProbe) observeRole(
	ctx context.Context,
	role systemStorageRole,
) (StorageAvailability, error) {
	availability, err := observeStoragePath(ctx, role.path, role.expected.Role)
	if err != nil ||
		availability.Device != role.expected.Device ||
		availability.Filesystem.RootInode != role.expected.Inode {
		return StorageAvailability{}, ErrStorageEnvelope
	}
	return availability, nil
}

func decodeDockerRoot(output []byte) (string, bool) {
	if len(output) == 0 || len(output) > maximumDockerRootOutputBytes {
		return "", false
	}
	document := output
	if document[len(document)-1] == '\n' {
		document = document[:len(document)-1]
	}
	if len(document) == 0 ||
		bytes.IndexByte(document, '\n') >= 0 ||
		bytes.IndexByte(document, '\r') >= 0 {
		return "", false
	}
	var path string
	if json.Unmarshal(document, &path) != nil ||
		!filepath.IsAbs(path) ||
		filepath.Clean(path) != path {
		return "", false
	}
	canonical, err := json.Marshal(path)
	return path, err == nil && bytes.Equal(canonical, document)
}

var _ StorageProbe = (*SystemStorageProbe)(nil)
