package archive

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"path"
)

// Digest is logical content evidence only. It cannot authorize staging.
type Digest struct{ value [sha256.Size]byte }

func (d Digest) Hex() string { return hex.EncodeToString(d.value[:]) }

// Verify checks one exact logical tree. It deliberately makes no claim about
// device/inode identity or hostile concurrent writers.
func Verify(tree fs.FS, manifest Manifest) (Digest, error) {
	if tree == nil {
		return Digest{}, errors.New("archive: filesystem required")
	}
	if err := validateManifest(manifest); err != nil {
		return Digest{}, err
	}
	expected, directories := expectedFiles(manifest)
	seen := make(map[string]struct{}, len(expected))
	err := fs.WalkDir(tree, ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("archive: logical walk failed")
		}
		if name == "." {
			return nil
		}
		if entry.IsDir() {
			if _, ok := directories[name]; !ok {
				return errors.New("archive: unexpected directory")
			}
			return nil
		}
		want, ok := expected[name]
		if !ok {
			return errors.New("archive: unexpected object")
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || uint32(info.Mode().Perm()) != want.Mode || uint64(info.Size()) != want.Size {
			return errors.New("archive: logical file identity differs")
		}
		file, err := tree.Open(name)
		if err != nil {
			return errors.New("archive: logical file open failed")
		}
		hash := sha256.New()
		count, copyErr := io.Copy(hash, io.LimitReader(file, int64(want.Size)+1))
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || count != int64(want.Size) || hex.EncodeToString(hash.Sum(nil)) != want.SHA256 {
			return errors.New("archive: logical file content differs")
		}
		seen[name] = struct{}{}
		return nil
	})
	if err != nil || len(seen) != len(expected) {
		if err != nil {
			return Digest{}, err
		}
		return Digest{}, errors.New("archive: logical tree incomplete")
	}
	digest, err := manifestDigest(manifest)
	if err != nil {
		return Digest{}, err
	}
	return Digest{value: digest}, nil
}

func expectedFiles(manifest Manifest) (map[string]File, map[string]struct{}) {
	files := make(map[string]File)
	directories := make(map[string]struct{})
	for _, seed := range manifest.Seeds {
		for _, file := range seed.Files {
			files[file.Path] = file
			for directory := path.Dir(file.Path); directory != "."; directory = path.Dir(directory) {
				directories[directory] = struct{}{}
				if path.Dir(directory) == directory {
					break
				}
			}
		}
	}
	return files, directories
}
