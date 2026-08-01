// Package linuxcap provides the closed Linux capability self-observation
// contract shared by the immutable network helper, verifier, and their
// production caller.
package linuxcap

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strconv"
	"unicode/utf8"
)

const (
	selfStatusPath = "/proc/self/status"
	maxStatusBytes = 64 << 10
	maskWidth      = 16
)

var errInvalidProfile = errors.New("linuxcap: capability profile invalid")

// Wire is the only capability representation admitted to helper and verifier
// result contracts. Each member is exactly one fixed-width lower-hex mask.
type Wire struct {
	Effective   string `json:"effective"`
	Permitted   string `json:"permitted"`
	Inheritable string `json:"inheritable"`
	Bounding    string `json:"bounding"`
	Ambient     string `json:"ambient"`
}

// ReadSelf reads and closes the immutable capability projection from the
// current process. It never returns raw status content.
func ReadSelf() (Wire, error) {
	file, err := os.Open(selfStatusPath)
	if err != nil {
		return Wire{}, errInvalidProfile
	}
	defer file.Close()
	document, err := io.ReadAll(io.LimitReader(file, maxStatusBytes+1))
	if err != nil {
		zero(document)
		return Wire{}, errInvalidProfile
	}
	wire, parseErr := ParseStatus(document)
	zero(document)
	return wire, parseErr
}

// ParseStatus extracts exactly the five known Linux capability keys. Other
// status fields are ignored; any unknown Cap* key is rejected.
func ParseStatus(document []byte) (Wire, error) {
	if len(document) == 0 ||
		len(document) > maxStatusBytes ||
		!utf8.Valid(document) ||
		document[len(document)-1] != '\n' {
		return Wire{}, errInvalidProfile
	}
	type field struct {
		key   []byte
		value *string
		seen  bool
	}
	var wire Wire
	fields := []field{
		{key: []byte("CapEff:"), value: &wire.Effective},
		{key: []byte("CapPrm:"), value: &wire.Permitted},
		{key: []byte("CapInh:"), value: &wire.Inheritable},
		{key: []byte("CapBnd:"), value: &wire.Bounding},
		{key: []byte("CapAmb:"), value: &wire.Ambient},
	}
	for _, line := range bytes.Split(document[:len(document)-1], []byte{'\n'}) {
		if !bytes.HasPrefix(line, []byte("Cap")) {
			continue
		}
		matched := false
		for index := range fields {
			field := &fields[index]
			prefix := append(append([]byte{}, field.key...), '\t')
			if !bytes.HasPrefix(line, prefix) {
				continue
			}
			if field.seen || len(line) != len(prefix)+maskWidth {
				return Wire{}, errInvalidProfile
			}
			value := string(line[len(prefix):])
			if _, err := parseMask(value); err != nil {
				return Wire{}, errInvalidProfile
			}
			*field.value = value
			field.seen = true
			matched = true
			break
		}
		if !matched {
			return Wire{}, errInvalidProfile
		}
	}
	for _, field := range fields {
		if !field.seen {
			return Wire{}, errInvalidProfile
		}
	}
	return wire, nil
}

// ValidateEmpty accepts only an all-zero canonical five-mask profile.
func ValidateEmpty(wire Wire) error {
	values, err := parseWire(wire)
	if err != nil {
		return err
	}
	for _, value := range values {
		if value != 0 {
			return errInvalidProfile
		}
	}
	return nil
}

// ValidateNetAdmin accepts exactly CAP_NET_ADMIN in effective, permitted, and
// bounding, with inheritable and ambient empty.
func ValidateNetAdmin(wire Wire) error {
	values, err := parseWire(wire)
	if err != nil {
		return err
	}
	netAdmin := uint64(1) << netAdminCapability
	if values[0] != netAdmin ||
		values[1] != netAdmin ||
		values[2] != 0 ||
		values[3] != netAdmin ||
		values[4] != 0 {
		return errInvalidProfile
	}
	return nil
}

func parseWire(wire Wire) ([5]uint64, error) {
	raw := [...]string{
		wire.Effective,
		wire.Permitted,
		wire.Inheritable,
		wire.Bounding,
		wire.Ambient,
	}
	var values [5]uint64
	for index, value := range raw {
		parsed, err := parseMask(value)
		if err != nil {
			return [5]uint64{}, errInvalidProfile
		}
		values[index] = parsed
	}
	return values, nil
}

func parseMask(raw string) (uint64, error) {
	if len(raw) != maskWidth {
		return 0, errInvalidProfile
	}
	for _, value := range []byte(raw) {
		if (value < '0' || value > '9') &&
			(value < 'a' || value > 'f') {
			return 0, errInvalidProfile
		}
	}
	value, err := strconv.ParseUint(raw, 16, 64)
	if err != nil || value&^kernelCapabilityMask() != 0 {
		return 0, errInvalidProfile
	}
	return value, nil
}

func kernelCapabilityMask() uint64 {
	if kernelLastCapability >= 63 {
		return ^uint64(0)
	}
	return (uint64(1) << (kernelLastCapability + 1)) - 1
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
