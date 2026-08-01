package testenv

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

var ErrRawObservation = errors.New("testenv: raw observation invalid")

type rawObservation struct {
	bytes     []byte
	destroyed bool
}

func newRawObservation(
	value []byte,
	maximumBytes int,
) (*rawObservation, error) {
	if len(value) == 0 || maximumBytes <= 0 || len(value) > maximumBytes {
		return nil, ErrRawObservation
	}
	return &rawObservation{bytes: value}, nil
}

func (r *rawObservation) Digest(domain string) (string, error) {
	if r == nil || r.destroyed || !validID(domain) {
		return "", ErrRawObservation
	}
	r.destroyed = true
	defer func() {
		for index := range r.bytes {
			r.bytes[index] = 0
		}
		r.bytes = nil
	}()
	digest := sha256.New()
	_, _ = digest.Write([]byte("portable-ghar-observation-v1\x00"))
	_ = binary.Write(digest, binary.BigEndian, uint16(len(domain)))
	_, _ = digest.Write([]byte(domain))
	_ = binary.Write(digest, binary.BigEndian, uint64(len(r.bytes)))
	_, _ = digest.Write(r.bytes)
	return hex.EncodeToString(digest.Sum(nil)), nil
}
