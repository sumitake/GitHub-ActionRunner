package networkjail

import (
	"errors"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
)

func (g DecisionGraph) NormalizeDestination(raw string, port uint16) (DialRequest, error) {
	if !g.portAllowed(port) {
		return DialRequest{}, errors.New("networkjail: destination port denied")
	}
	host, literal, err := normalizeHostOrLiteral(raw)
	if err != nil {
		return DialRequest{}, err
	}
	if literal.IsValid() &&
		!addressAllowed(
			literal,
			g.manifest.IPFamily,
			g.manifest.DynamicDeny,
			g.manifest.DockerHost,
		) {
		return DialRequest{}, errors.New("networkjail: destination address denied")
	}
	return DialRequest{Host: host, Port: port}, nil
}

func (g DecisionGraph) ValidateAnswers(
	request DialRequest,
	answers []netip.Addr,
) ([]netip.Addr, error) {
	if _, err := g.NormalizeDestination(request.Host, request.Port); err != nil {
		return nil, errors.New("networkjail: dial request invalid")
	}
	if literal, err := netip.ParseAddr(request.Host); err == nil {
		literal = normalizeEmbedded(literal)
		if len(answers) != 1 || normalizeEmbedded(answers[0]) != literal {
			return nil, errors.New("networkjail: literal answer mismatch")
		}
		return []netip.Addr{literal}, nil
	}
	if len(answers) == 0 || len(answers) > maxDNSAnswers {
		return nil, errors.New("networkjail: dns answer count invalid")
	}
	result := make([]netip.Addr, len(answers))
	for index, address := range answers {
		if !address.IsValid() || address.Zone() != "" ||
			normalizeEmbedded(address) != address ||
			!addressAllowed(
				address,
				g.manifest.IPFamily,
				g.manifest.DynamicDeny,
				g.manifest.DockerHost,
			) {
			return nil, errors.New("networkjail: dns answer denied")
		}
		result[index] = address
	}
	slices.SortFunc(result, func(left, right netip.Addr) int {
		return left.Compare(right)
	})
	for index := 1; index < len(result); index++ {
		if result[index-1] == result[index] {
			return nil, errors.New("networkjail: dns answer duplicated")
		}
	}
	return result, nil
}

const maxDNSAnswers = 64

func normalizeHostOrLiteral(raw string) (string, netip.Addr, error) {
	if raw == "" || raw != strings.TrimSpace(raw) || containsForbiddenHostRune(raw) ||
		strings.ContainsAny(raw, "@/?#[]%") {
		return "", netip.Addr{}, errors.New("networkjail: destination host invalid")
	}
	if address, err := netip.ParseAddr(raw); err == nil {
		address = normalizeEmbedded(address)
		if !address.IsValid() {
			return "", netip.Addr{}, errors.New("networkjail: destination literal invalid")
		}
		return address.String(), address, nil
	}
	if strings.Contains(raw, ":") {
		return "", netip.Addr{}, errors.New("networkjail: destination literal invalid")
	}
	if mayBeLegacyIPv4(raw) {
		address, ok := parseLegacyIPv4(raw)
		if !ok {
			return "", netip.Addr{}, errors.New("networkjail: destination literal invalid")
		}
		return address.String(), address, nil
	}
	name, err := normalizeName(raw)
	if err != nil {
		return "", netip.Addr{}, err
	}
	if address, err := netip.ParseAddr(name); err == nil || mayBeLegacyIPv4(name) {
		if err == nil {
			address = normalizeEmbedded(address)
			return address.String(), address, nil
		}
		if parsed, ok := parseLegacyIPv4(name); ok {
			return parsed.String(), parsed, nil
		}
		return "", netip.Addr{}, errors.New("networkjail: destination literal invalid")
	}
	return name, netip.Addr{}, nil
}

func normalizeName(raw string) (string, error) {
	if raw == "" || raw != strings.TrimSpace(raw) || containsForbiddenHostRune(raw) ||
		strings.ContainsAny(raw, "@/?#[]:%") {
		return "", errors.New("networkjail: destination name invalid")
	}
	if strings.HasSuffix(raw, "..") {
		return "", errors.New("networkjail: destination name invalid")
	}
	raw = strings.TrimSuffix(raw, ".")
	ascii, err := idna.Lookup.ToASCII(raw)
	if err != nil {
		return "", errors.New("networkjail: destination name invalid")
	}
	ascii = strings.ToLower(ascii)
	if len(ascii) == 0 || len(ascii) > 253 {
		return "", errors.New("networkjail: destination name invalid")
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 ||
			label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("networkjail: destination name invalid")
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') &&
				(char < '0' || char > '9') &&
				char != '-' {
				return "", errors.New("networkjail: destination name invalid")
			}
		}
	}
	return ascii, nil
}

func containsForbiddenHostRune(value string) bool {
	for _, char := range value {
		if char == 0 || unicode.IsControl(char) || unicode.IsSpace(char) {
			return true
		}
	}
	return false
}

func mayBeLegacyIPv4(raw string) bool {
	if raw == "" || raw[0] < '0' || raw[0] > '9' {
		return false
	}
	for _, char := range raw {
		switch {
		case char >= '0' && char <= '9':
		case char >= 'a' && char <= 'f':
		case char >= 'A' && char <= 'F':
		case char == 'x' || char == 'X' || char == '.':
		default:
			return false
		}
	}
	return true
}

func parseLegacyIPv4(raw string) (netip.Addr, bool) {
	parts := strings.Split(raw, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return netip.Addr{}, false
	}
	values := make([]uint64, len(parts))
	for index, part := range parts {
		value, ok := parseLegacyPart(part)
		if !ok {
			return netip.Addr{}, false
		}
		values[index] = value
	}
	var value uint64
	switch len(values) {
	case 1:
		if values[0] > math.MaxUint32 {
			return netip.Addr{}, false
		}
		value = values[0]
	case 2:
		if values[0] > math.MaxUint8 || values[1] > 0xffffff {
			return netip.Addr{}, false
		}
		value = values[0]<<24 | values[1]
	case 3:
		if values[0] > math.MaxUint8 || values[1] > math.MaxUint8 ||
			values[2] > math.MaxUint16 {
			return netip.Addr{}, false
		}
		value = values[0]<<24 | values[1]<<16 | values[2]
	case 4:
		for _, component := range values {
			if component > math.MaxUint8 {
				return netip.Addr{}, false
			}
		}
		value = values[0]<<24 | values[1]<<16 | values[2]<<8 | values[3]
	}
	return netip.AddrFrom4([4]byte{
		byte(value >> 24),
		byte(value >> 16),
		byte(value >> 8),
		byte(value),
	}), true
}

func parseLegacyPart(raw string) (uint64, bool) {
	if raw == "" {
		return 0, false
	}
	base := 10
	digits := raw
	if strings.HasPrefix(raw, "0x") || strings.HasPrefix(raw, "0X") {
		base = 16
		digits = raw[2:]
		if digits == "" {
			return 0, false
		}
	} else if len(raw) > 1 && raw[0] == '0' {
		base = 8
		digits = raw[1:]
	}
	value, err := strconv.ParseUint(digits, base, 64)
	return value, err == nil
}

func normalizeEmbedded(address netip.Addr) netip.Addr {
	if !address.IsValid() {
		return netip.Addr{}
	}
	if address.Is4In6() {
		return address.Unmap()
	}
	if !address.Is6() {
		return address
	}
	bytes16 := address.As16()
	if allZero(bytes16[:12]) {
		return netip.AddrFrom4([4]byte{
			bytes16[12], bytes16[13], bytes16[14], bytes16[15],
		})
	}
	if bytes16[0] == 0x20 && bytes16[1] == 0x02 {
		return netip.AddrFrom4([4]byte{
			bytes16[2], bytes16[3], bytes16[4], bytes16[5],
		})
	}
	if bytes16[0] == 0x20 && bytes16[1] == 0x01 &&
		bytes16[2] == 0 && bytes16[3] == 0 {
		return netip.AddrFrom4([4]byte{
			^bytes16[12], ^bytes16[13], ^bytes16[14], ^bytes16[15],
		})
	}
	return address
}

func allZero(value []byte) bool {
	var combined byte
	for _, current := range value {
		combined |= current
	}
	return combined == 0
}

func addressAllowed(
	address netip.Addr,
	family IPFamily,
	dynamic []netip.Prefix,
	dockerHosts []netip.Addr,
) bool {
	address = normalizeEmbedded(address)
	if !address.IsValid() || address.Zone() != "" {
		return false
	}
	if family == PublicIPv4Only && !address.Is4() {
		return false
	}
	if !address.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range staticDenyPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	for _, prefix := range dynamic {
		if prefix.Contains(address) {
			return false
		}
	}
	for _, host := range dockerHosts {
		if host == address {
			return false
		}
	}
	return true
}

var staticDenyPrefixes = []netip.Prefix{
	v4Prefix(127, 0, 0, 0, 8),
	v6Prefix([16]byte{15: 1}, 128),
	v4Prefix(10, 0, 0, 0, 8),
	v4Prefix(172, 16, 0, 0, 12),
	v4Prefix(192, 168, 0, 0, 16),
	v6Prefix([16]byte{0xfc}, 7),
	v4Prefix(169, 254, 0, 0, 16),
	v6Prefix([16]byte{0xfe, 0x80}, 10),
	v4Prefix(100, 64, 0, 0, 10),
	v4Prefix(0, 0, 0, 0, 8),
	v4Prefix(192, 0, 0, 0, 24),
	v4Prefix(192, 0, 2, 0, 24),
	v4Prefix(198, 51, 100, 0, 24),
	v4Prefix(203, 0, 113, 0, 24),
	v4Prefix(198, 18, 0, 0, 15),
	v4Prefix(240, 0, 0, 0, 4),
	v6Prefix([16]byte{}, 128),
	v6Prefix([16]byte{0x20, 0x01, 0x0d, 0xb8}, 32),
	v4Prefix(224, 0, 0, 0, 4),
	v4Prefix(255, 255, 255, 255, 32),
	v6Prefix([16]byte{0xff}, 8),
}

func v4Prefix(a, b, c, d byte, bits int) netip.Prefix {
	return netip.PrefixFrom(netip.AddrFrom4([4]byte{a, b, c, d}), bits)
}

func v6Prefix(value [16]byte, bits int) netip.Prefix {
	return netip.PrefixFrom(netip.AddrFrom16(value), bits)
}
