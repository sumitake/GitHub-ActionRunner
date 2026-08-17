package failoverclient

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	SessionPath      = "/v1/session"
	HeartbeatPath    = "/v1/heartbeat"
	AdminCommandPath = "/v1/admin/command"
	AdminStatusPath  = "/v1/admin/status"
	TimestampHeader  = "x-portable-ghar-timestamp"
	MACHeader        = "x-portable-ghar-mac"
)

var (
	ErrProtocolAuth = errors.New("failoverclient: protocol auth")
	rfc3339MsZ      = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`)
)

func MACInput(method, path, timestamp string, canonicalBody []byte) ([]byte, error) {
	if method != "POST" || !strings.HasPrefix(path, "/v1/") || !rfc3339MsZ.MatchString(timestamp) {
		return nil, fmt.Errorf("%w: mac input", ErrProtocolAuth)
	}
	var builder strings.Builder
	builder.WriteString(method)
	builder.WriteByte('\n')
	builder.WriteString(path)
	builder.WriteByte('\n')
	builder.WriteString(timestamp)
	builder.WriteByte('\n')
	builder.Write(canonicalBody)
	return []byte(builder.String()), nil
}

func SignCanonical(key []byte, method, path, timestamp string, canonicalBody []byte) (string, error) {
	if len(key) < 32 {
		return "", fmt.Errorf("%w: key", ErrProtocolAuth)
	}
	input, err := MACInput(method, path, timestamp, canonicalBody)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(input)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func VerifyCanonical(key []byte, method, path, timestamp string, canonicalBody []byte, presented string) error {
	expected, err := SignCanonical(key, method, path, timestamp, canonicalBody)
	if err != nil {
		return err
	}
	if !constantTimeEqualHex(expected, presented) {
		return fmt.Errorf("%w: mac mismatch", ErrProtocolAuth)
	}
	return nil
}

func AssertTimestampWindow(receipt, request string, window time.Duration) error {
	if window <= 0 || !rfc3339MsZ.MatchString(receipt) || !rfc3339MsZ.MatchString(request) {
		return fmt.Errorf("%w: timestamp window", ErrProtocolAuth)
	}
	receiptTime, err := time.Parse(time.RFC3339Nano, receipt)
	if err != nil {
		return fmt.Errorf("%w: timestamp window", ErrProtocolAuth)
	}
	requestTime, err := time.Parse(time.RFC3339Nano, request)
	if err != nil {
		return fmt.Errorf("%w: timestamp window", ErrProtocolAuth)
	}
	delta := receiptTime.Sub(requestTime)
	if delta < -window || delta > window {
		return fmt.Errorf("%w: timestamp outside window", ErrProtocolAuth)
	}
	return nil
}

func DecodeHex(value string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) == 0 || len(value) != hex.EncodedLen(len(decoded)) || value != strings.ToLower(value) {
		return nil, fmt.Errorf("%w: hex", ErrProtocolAuth)
	}
	return decoded, nil
}

func constantTimeEqualHex(left, right string) bool {
	if len(left) != len(right) || !isLowerHex(left) || !isLowerHex(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func isLowerHex(value string) bool {
	if len(value) == 0 || len(value)%2 != 0 {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' && r < 'a' || r > 'f' {
			return false
		}
	}
	return true
}
