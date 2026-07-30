package testenv

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const executionHostIdentityDomain = "portable-ghar-execution-host-identity-v1\x00"

var ErrExecutionHostIdentity = errors.New(
	"testenv: execution host identity invalid",
)

type executionHostIdentityWire struct {
	SchemaVersion                 uint32 `json:"schema_version"`
	OperatingSystem               string `json:"operating_system"`
	Architecture                  string `json:"architecture"`
	EUID                          uint32 `json:"euid"`
	FixtureParentDevice           uint64 `json:"fixture_parent_device"`
	FixtureParentInode            uint64 `json:"fixture_parent_inode"`
	DockerBinaryDevice            uint64 `json:"docker_binary_device"`
	DockerBinaryInode             uint64 `json:"docker_binary_inode"`
	DockerServerObservationDigest string `json:"docker_server_observation_digest"`
}

type executionHostFileIdentity struct {
	Device uint64
	Inode  uint64
	Mode   uint32
	NLink  uint64
}

type executionHostStatSource interface {
	Lstat(string) (executionHostFileIdentity, error)
}

type executionHostObservationConfig struct {
	OperatingSystem       string
	Architecture          string
	EUID                  uint32
	FixtureParentPath     string
	FixtureParentDevice   uint64
	FixtureParentInode    uint64
	DockerBinaryPath      string
	ExpectedTargetDigest  string
	ExpectedControlDigest string
}

func computeExecutionHostIdentity(
	wire executionHostIdentityWire,
) ([]byte, string, error) {
	if wire.SchemaVersion != 1 ||
		wire.OperatingSystem != "linux" ||
		(wire.Architecture != "amd64" && wire.Architecture != "arm64") ||
		wire.FixtureParentDevice == 0 ||
		wire.FixtureParentInode == 0 ||
		wire.DockerBinaryDevice == 0 ||
		wire.DockerBinaryInode == 0 ||
		!isLowerHex(wire.DockerServerObservationDigest, 64) ||
		wire.DockerServerObservationDigest == strings.Repeat("0", 64) {
		return nil, "", ErrExecutionHostIdentity
	}
	document, err := json.Marshal(wire)
	if err != nil {
		return nil, "", ErrExecutionHostIdentity
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(executionHostIdentityDomain))
	_, _ = digest.Write(document)
	return append([]byte(nil), document...),
		hex.EncodeToString(digest.Sum(nil)),
		nil
}

func validFixtureParentIdentity(
	identity executionHostFileIdentity,
	expectedDevice uint64,
	expectedInode uint64,
) bool {
	return expectedDevice != 0 &&
		expectedInode != 0 &&
		identity.Device == expectedDevice &&
		identity.Inode == expectedInode &&
		identity.Mode&unix.S_IFMT == unix.S_IFDIR
}

func validDockerBinaryIdentity(identity executionHostFileIdentity) bool {
	return identity.Device != 0 &&
		identity.Inode != 0 &&
		identity.Mode&unix.S_IFMT == unix.S_IFREG &&
		identity.Mode&0o111 != 0 &&
		identity.Mode&0o022 == 0 &&
		identity.NLink == 1
}

func observeExecutionHostIdentity(
	ctx context.Context,
	config executionHostObservationConfig,
	stats executionHostStatSource,
	session *preflightSession,
) (string, error) {
	if ctx == nil ||
		stats == nil ||
		session == nil ||
		session.surface == nil ||
		config.OperatingSystem != "linux" ||
		(config.Architecture != "amd64" && config.Architecture != "arm64") ||
		!validAbsolutePath(config.FixtureParentPath) ||
		config.FixtureParentPath !=
			filepath.Dir(session.surface.config.FixtureRoot) ||
		!validAbsolutePath(config.DockerBinaryPath) ||
		config.DockerBinaryPath != session.surface.config.DockerPath ||
		!isLowerHex(config.ExpectedTargetDigest, 64) ||
		config.ExpectedTargetDigest == strings.Repeat("0", 64) ||
		!isLowerHex(config.ExpectedControlDigest, 64) ||
		config.ExpectedControlDigest == strings.Repeat("0", 64) ||
		config.ExpectedTargetDigest == config.ExpectedControlDigest {
		return "", ErrExecutionHostIdentity
	}
	parentBefore, err := stats.Lstat(config.FixtureParentPath)
	if err != nil ||
		!validFixtureParentIdentity(
			parentBefore,
			config.FixtureParentDevice,
			config.FixtureParentInode,
		) {
		return "", ErrExecutionHostIdentity
	}
	dockerBefore, err := stats.Lstat(config.DockerBinaryPath)
	if err != nil || !validDockerBinaryIdentity(dockerBefore) {
		return "", ErrExecutionHostIdentity
	}
	server, err := session.Run(ctx, ClosedDockerServerVersion)
	if err != nil {
		return "", ErrExecutionHostIdentity
	}
	parentAfter, err := stats.Lstat(config.FixtureParentPath)
	if err != nil || parentAfter != parentBefore {
		return "", ErrExecutionHostIdentity
	}
	dockerAfter, err := stats.Lstat(config.DockerBinaryPath)
	if err != nil || dockerAfter != dockerBefore {
		return "", ErrExecutionHostIdentity
	}
	_, digest, err := computeExecutionHostIdentity(executionHostIdentityWire{
		SchemaVersion:                 1,
		OperatingSystem:               config.OperatingSystem,
		Architecture:                  config.Architecture,
		EUID:                          config.EUID,
		FixtureParentDevice:           parentBefore.Device,
		FixtureParentInode:            parentBefore.Inode,
		DockerBinaryDevice:            dockerBefore.Device,
		DockerBinaryInode:             dockerBefore.Inode,
		DockerServerObservationDigest: server.Digest,
	})
	if err != nil || digest != config.ExpectedTargetDigest {
		return "", ErrExecutionHostIdentity
	}
	return digest, nil
}
