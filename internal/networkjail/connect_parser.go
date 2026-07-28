package networkjail

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"strconv"
	"strings"
)

const (
	MaxProxyHeaderBytes      = 16 << 10
	MaxProxyLineBytes        = 4 << 10
	MaxProxyHeaders          = 64
	MaxDialHostBytes         = 253
	MaxDialRequestFrameBytes = dialFrameHeaderBytes + MaxDialHostBytes

	dialFrameHeaderBytes = 14
)

var dialFrameMagic = [8]byte{'P', 'G', 'H', 'A', 'R', 'D', 'L', '1'}

func ParseHTTPConnect(data []byte, graph DecisionGraph) (DialRequest, error) {
	if !graph.protocolEnabled(HTTPConnect) ||
		len(data) == 0 || len(data) > MaxProxyHeaderBytes ||
		!bytes.HasSuffix(data, []byte("\r\n\r\n")) ||
		bytes.Index(data, []byte("\r\n\r\n")) != len(data)-4 ||
		!validCRLF(data) {
		return DialRequest{}, errors.New("networkjail: connect request invalid")
	}
	lines := bytes.Split(data[:len(data)-2], []byte("\r\n"))
	if len(lines) < 3 || len(lines)-2 > MaxProxyHeaders {
		return DialRequest{}, errors.New("networkjail: connect headers invalid")
	}
	for _, line := range lines {
		if len(line) > MaxProxyLineBytes {
			return DialRequest{}, errors.New("networkjail: connect line too large")
		}
	}
	requestParts := strings.Split(string(lines[0]), " ")
	if len(requestParts) != 3 || requestParts[0] != "CONNECT" ||
		requestParts[2] != "HTTP/1.1" {
		return DialRequest{}, errors.New("networkjail: connect request line invalid")
	}
	target, err := parseAuthority(requestParts[1], graph)
	if err != nil {
		return DialRequest{}, err
	}

	seen := make(map[string]struct{}, len(lines)-2)
	var host DialRequest
	var hostSeen bool
	for _, rawLine := range lines[1 : len(lines)-1] {
		if len(rawLine) == 0 || rawLine[0] == ' ' || rawLine[0] == '\t' ||
			bytes.IndexByte(rawLine, 0) >= 0 {
			return DialRequest{}, errors.New("networkjail: connect header invalid")
		}
		name, value, found := strings.Cut(string(rawLine), ":")
		name = strings.ToLower(name)
		value = strings.TrimSpace(value)
		if !found || !validHeaderName(name) || value == "" {
			return DialRequest{}, errors.New("networkjail: connect header invalid")
		}
		if _, duplicate := seen[name]; duplicate {
			return DialRequest{}, errors.New("networkjail: connect header duplicated")
		}
		seen[name] = struct{}{}
		switch name {
		case "host":
			host, err = parseAuthority(value, graph)
			if err != nil {
				return DialRequest{}, err
			}
			hostSeen = true
		case "content-length", "transfer-encoding", "proxy-authorization",
			"connection", "te", "trailer", "upgrade":
			return DialRequest{}, errors.New("networkjail: connect header unsupported")
		}
	}
	if !hostSeen || host != target {
		return DialRequest{}, errors.New("networkjail: connect authority mismatch")
	}
	return target, nil
}

func validCRLF(data []byte) bool {
	for index, value := range data {
		switch value {
		case '\r':
			if index+1 >= len(data) || data[index+1] != '\n' {
				return false
			}
		case '\n':
			if index == 0 || data[index-1] != '\r' {
				return false
			}
		default:
			if value == 0 || value < 0x20 && value != '\t' || value == 0x7f {
				return false
			}
		}
	}
	return true
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, char := range name {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') &&
			char != '-' {
			return false
		}
	}
	return true
}

func parseAuthority(raw string, graph DecisionGraph) (DialRequest, error) {
	if raw == "" || strings.ContainsAny(raw, "@/?# \t\r\n") {
		return DialRequest{}, errors.New("networkjail: authority invalid")
	}
	var host, portText string
	if strings.HasPrefix(raw, "[") {
		closing := strings.IndexByte(raw, ']')
		if closing <= 1 || closing+2 > len(raw) || raw[closing+1] != ':' ||
			strings.Contains(raw[closing+2:], ":") {
			return DialRequest{}, errors.New("networkjail: authority invalid")
		}
		host = raw[1:closing]
		portText = raw[closing+2:]
	} else {
		if strings.Count(raw, ":") != 1 {
			return DialRequest{}, errors.New("networkjail: authority invalid")
		}
		var found bool
		host, portText, found = strings.Cut(raw, ":")
		if !found {
			return DialRequest{}, errors.New("networkjail: authority invalid")
		}
	}
	if portText == "" || len(portText) > 5 {
		return DialRequest{}, errors.New("networkjail: authority port invalid")
	}
	for _, char := range portText {
		if char < '0' || char > '9' {
			return DialRequest{}, errors.New("networkjail: authority port invalid")
		}
	}
	port64, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port64 == 0 {
		return DialRequest{}, errors.New("networkjail: authority port invalid")
	}
	return graph.NormalizeDestination(host, uint16(port64))
}

func ParseSOCKS5Connect(data []byte, graph DecisionGraph) (DialRequest, error) {
	if !graph.protocolEnabled(SOCKS5Connect) || len(data) < 10 ||
		data[0] != 5 || data[1] != 1 || data[2] != 0 ||
		data[3] != 5 || data[4] != 1 || data[5] != 0 {
		return DialRequest{}, errors.New("networkjail: socks request invalid")
	}
	cursor := 7
	var host string
	switch data[6] {
	case 1:
		if len(data) != cursor+4+2 {
			return DialRequest{}, errors.New("networkjail: socks ipv4 invalid")
		}
		host = netipFrom4(data[cursor : cursor+4]).String()
		cursor += 4
	case 3:
		if len(data) <= cursor {
			return DialRequest{}, errors.New("networkjail: socks name invalid")
		}
		length := int(data[cursor])
		cursor++
		if length == 0 || length > MaxDialHostBytes || len(data) != cursor+length+2 {
			return DialRequest{}, errors.New("networkjail: socks name invalid")
		}
		host = string(data[cursor : cursor+length])
		cursor += length
	case 4:
		if len(data) != cursor+16+2 {
			return DialRequest{}, errors.New("networkjail: socks ipv6 invalid")
		}
		host = netipFrom16(data[cursor : cursor+16]).String()
		cursor += 16
	default:
		return DialRequest{}, errors.New("networkjail: socks address type invalid")
	}
	port := binary.BigEndian.Uint16(data[cursor : cursor+2])
	if port == 0 {
		return DialRequest{}, errors.New("networkjail: socks port invalid")
	}
	return graph.NormalizeDestination(host, port)
}

func netipFrom4(value []byte) (address netip.Addr) {
	var encoded [4]byte
	copy(encoded[:], value)
	return netip.AddrFrom4(encoded)
}

func netipFrom16(value []byte) (address netip.Addr) {
	var encoded [16]byte
	copy(encoded[:], value)
	return netip.AddrFrom16(encoded)
}

func EncodeDialRequest(request DialRequest) ([]byte, error) {
	if request.Port == 0 || len(request.Host) == 0 ||
		len(request.Host) > MaxDialHostBytes {
		return nil, errors.New("networkjail: dial request invalid")
	}
	kind := byte(2)
	if address, err := netip.ParseAddr(request.Host); err == nil {
		if normalizeEmbedded(address).String() != request.Host {
			return nil, errors.New("networkjail: dial literal noncanonical")
		}
		kind = 1
	} else {
		name, err := normalizeName(request.Host)
		if err != nil || name != request.Host {
			return nil, errors.New("networkjail: dial name noncanonical")
		}
	}
	frame := make([]byte, dialFrameHeaderBytes+len(request.Host))
	copy(frame[:8], dialFrameMagic[:])
	frame[8] = 1
	frame[9] = kind
	binary.BigEndian.PutUint16(frame[10:12], request.Port)
	binary.BigEndian.PutUint16(frame[12:14], uint16(len(request.Host)))
	copy(frame[14:], request.Host)
	return frame, nil
}

func DecodeDialRequest(frame []byte, graph DecisionGraph) (DialRequest, error) {
	if len(frame) < dialFrameHeaderBytes || len(frame) > MaxDialRequestFrameBytes ||
		!bytes.Equal(frame[:8], dialFrameMagic[:]) || frame[8] != 1 ||
		(frame[9] != 1 && frame[9] != 2) {
		return DialRequest{}, errors.New("networkjail: dial frame invalid")
	}
	hostLength := int(binary.BigEndian.Uint16(frame[12:14]))
	if hostLength == 0 || hostLength > MaxDialHostBytes ||
		len(frame) != dialFrameHeaderBytes+hostLength {
		return DialRequest{}, errors.New("networkjail: dial frame length invalid")
	}
	request, err := graph.NormalizeDestination(
		string(frame[dialFrameHeaderBytes:]),
		binary.BigEndian.Uint16(frame[10:12]),
	)
	if err != nil {
		return DialRequest{}, errors.New("networkjail: dial frame denied")
	}
	_, literalErr := netip.ParseAddr(request.Host)
	if (frame[9] == 1) != (literalErr == nil) {
		return DialRequest{}, errors.New("networkjail: dial frame kind mismatch")
	}
	canonical, err := EncodeDialRequest(request)
	if err != nil || !bytes.Equal(canonical, frame) {
		return DialRequest{}, errors.New("networkjail: dial frame noncanonical")
	}
	return request, nil
}
