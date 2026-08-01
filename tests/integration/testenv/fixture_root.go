package testenv

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

const fixtureEmptyDigestDomain = "portable-ghar-fixture-empty-v1\x00"

type fixtureRootObservation struct {
	SchemaVersion  uint32 `json:"schema_version"`
	ParentDevice   uint64 `json:"parent_device"`
	ParentInode    uint64 `json:"parent_inode"`
	ParentOwnerUID uint32 `json:"parent_owner_uid"`
	ParentMode     uint32 `json:"parent_mode"`
	RootDevice     uint64 `json:"root_device"`
	RootInode      uint64 `json:"root_inode"`
	OwnerUID       uint32 `json:"owner_uid"`
	Mode           uint32 `json:"mode"`
}

func computeFixtureEmptyDigest(
	observation fixtureRootObservation,
) (string, error) {
	if observation.SchemaVersion != 1 ||
		observation.ParentDevice == 0 ||
		observation.ParentInode == 0 ||
		observation.ParentOwnerUID != observation.OwnerUID ||
		observation.ParentMode > 0o7777 ||
		observation.ParentMode&0o022 != 0 ||
		observation.RootDevice == 0 ||
		observation.RootInode == 0 ||
		observation.RootDevice != observation.ParentDevice ||
		observation.Mode != 0o700 {
		return "", ErrStaticPreflight
	}
	document, err := json.Marshal(observation)
	if err != nil {
		return "", ErrStaticPreflight
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(fixtureEmptyDigestDomain))
	_, _ = digest.Write(document)
	return hex.EncodeToString(digest.Sum(nil)), nil
}
