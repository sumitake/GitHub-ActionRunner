package networkjail

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const maxCABundleBytes = 1 << 20

var (
	lowerHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type CABundleLock struct {
	SchemaVersion  uint64 `json:"schema_version"`
	SourceURL      string `json:"source_url"`
	SourceRevision string `json:"source_revision"`
	SHA256         string `json:"sha256"`
	LicenseSPDX    string `json:"license_spdx"`
	CopiedPath     string `json:"copied_path"`
	ContextPath    string `json:"context_path"`
	SBOMPath       string `json:"sbom_path"`
}

func LoadCABundleLock(reader io.Reader) (CABundleLock, error) {
	if reader == nil {
		return CABundleLock{}, errors.New("networkjail: ca lock reader required")
	}
	decoder := json.NewDecoder(io.LimitReader(reader, 1<<16))
	decoder.DisallowUnknownFields()
	var lock CABundleLock
	if err := decoder.Decode(&lock); err != nil {
		return CABundleLock{}, errors.New("networkjail: ca lock invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return CABundleLock{}, errors.New("networkjail: ca lock trailing data")
	}
	parsed, err := url.Parse(lock.SourceURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return CABundleLock{}, errors.New("networkjail: ca lock source invalid")
	}
	if lock.SchemaVersion != 1 || !validSourceRevision(lock.SourceRevision) ||
		!lowerHex64.MatchString(lock.SHA256) || lock.LicenseSPDX != "MPL-2.0" ||
		lock.CopiedPath != "/etc/ssl/certs/ca-bundle.crt" ||
		lock.ContextPath != "images/trust/build/ca-bundle.pem" ||
		lock.SBOMPath != "images/trust/ca-bundle.spdx.json" {
		return CABundleLock{}, errors.New("networkjail: ca lock fields invalid")
	}
	return lock, nil
}

func validSourceRevision(value string) bool {
	parsed, err := time.Parse("2006-01-02", value)
	return err == nil && parsed.UTC().Format("2006-01-02") == value
}

func (lock CABundleLock) Verify(reader io.Reader) error {
	if reader == nil || !lowerHex64.MatchString(lock.SHA256) {
		return errors.New("networkjail: ca bundle unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxCABundleBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxCABundleBytes {
		zeroBytes(data)
		return errors.New("networkjail: ca bundle unavailable")
	}
	defer zeroBytes(data)
	digest := sha256.Sum256(data)
	returned := hex.EncodeToString(digest[:])
	if !strings.EqualFold(returned, lock.SHA256) {
		return errors.New("networkjail: ca bundle digest mismatch")
	}
	return nil
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
