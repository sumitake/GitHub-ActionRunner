package networkjail

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestParseHTTPConnectAcceptsOneCanonicalRequest(t *testing.T) {
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile error = %v", err)
	}
	raw := []byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	request, err := ParseHTTPConnect(raw, graph)
	if err != nil {
		t.Fatalf("ParseHTTPConnect error = %v", err)
	}
	if request.Host != "example.com" || request.Port != 443 {
		t.Fatalf("request = %+v", request)
	}
}

func TestParseHTTPConnectRejectsSmugglingAndAmbiguity(t *testing.T) {
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile error = %v", err)
	}
	tests := []struct {
		name string
		raw  string
	}{
		{"wrong method", "GET example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"},
		{"absolute form", "CONNECT https://example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"},
		{"userinfo", "CONNECT user@example.com:443 HTTP/1.1\r\nHost: user@example.com:443\r\n\r\n"},
		{"http 10", "CONNECT example.com:443 HTTP/1.0\r\nHost: example.com:443\r\n\r\n"},
		{"missing host", "CONNECT example.com:443 HTTP/1.1\r\n\r\n"},
		{"duplicate host", "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nHost: example.com:443\r\n\r\n"},
		{"conflicting host", "CONNECT example.com:443 HTTP/1.1\r\nHost: other.example.com:443\r\n\r\n"},
		{"obs fold", "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n folded: value\r\n\r\n"},
		{"content length", "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nContent-Length: 0\r\n\r\n"},
		{"transfer encoding", "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nTransfer-Encoding: chunked\r\n\r\n"},
		{"proxy auth", "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic synthetic\r\n\r\n"},
		{"unsupported port", "CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n\r\n"},
		{"trailing tunnel byte", "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n\x16"},
		{"trailing request", "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nGET / HTTP/1.1\r\n\r\n"},
		{"nul", "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\x00\r\n\r\n"},
		{"bare lf", "CONNECT example.com:443 HTTP/1.1\nHost: example.com:443\n\n"},
		{"path", "CONNECT example.com:443/path HTTP/1.1\r\nHost: example.com:443\r\n\r\n"},
		{"query", "CONNECT example.com:443?x=1 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"},
		{"fragment", "CONNECT example.com:443#x HTTP/1.1\r\nHost: example.com:443\r\n\r\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseHTTPConnect([]byte(tc.raw), graph); err == nil {
				t.Fatal("ParseHTTPConnect accepted invalid request")
			}
		})
	}
}

func TestParseHTTPConnectBoundsInput(t *testing.T) {
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile error = %v", err)
	}
	overlong := bytes.Repeat([]byte{'a'}, MaxProxyHeaderBytes+1)
	if _, err := ParseHTTPConnect(overlong, graph); err == nil {
		t.Fatal("ParseHTTPConnect accepted oversized input")
	}
}

func TestParseSOCKS5Connect(t *testing.T) {
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile error = %v", err)
	}
	host := []byte("example.com")
	raw := []byte{5, 1, 0, 5, 1, 0, 3, byte(len(host))}
	raw = append(raw, host...)
	raw = append(raw, 1, 187)
	request, err := ParseSOCKS5Connect(raw, graph)
	if err != nil {
		t.Fatalf("ParseSOCKS5Connect error = %v", err)
	}
	if request.Host != "example.com" || request.Port != 443 {
		t.Fatalf("request = %+v", request)
	}
	for _, mutate := range []func([]byte) []byte{
		func(in []byte) []byte { in[1] = 2; return in },
		func(in []byte) []byte { in[2] = 2; return in },
		func(in []byte) []byte { in[4] = 2; return in },
		func(in []byte) []byte { in[5] = 1; return in },
		func(in []byte) []byte { return append(in, 0) },
	} {
		candidate := append([]byte(nil), raw...)
		if _, err := ParseSOCKS5Connect(mutate(candidate), graph); err == nil {
			t.Fatal("ParseSOCKS5Connect accepted invalid request")
		}
	}
}

func TestDialRequestFrameIsCanonicalAndBounded(t *testing.T) {
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		t.Fatalf("Compile error = %v", err)
	}
	request, err := graph.NormalizeDestination("example.com", 443)
	if err != nil {
		t.Fatalf("NormalizeDestination error = %v", err)
	}
	frame, err := EncodeDialRequest(request)
	if err != nil {
		t.Fatalf("EncodeDialRequest error = %v", err)
	}
	decoded, err := DecodeDialRequest(frame, graph)
	if err != nil {
		t.Fatalf("DecodeDialRequest error = %v", err)
	}
	if decoded != request {
		t.Fatalf("decoded = %+v, want %+v", decoded, request)
	}
	for _, corrupt := range [][]byte{
		append(append([]byte(nil), frame...), 0),
		append([]byte(nil), frame[:len(frame)-1]...),
		func() []byte { out := append([]byte(nil), frame...); out[0] ^= 0xff; return out }(),
		func() []byte { out := append([]byte(nil), frame...); out[8] = 2; return out }(),
		func() []byte {
			out := append([]byte(nil), frame...)
			binary.BigEndian.PutUint16(out[12:14], uint16(MaxDialHostBytes+1))
			return out
		}(),
	} {
		if _, err := DecodeDialRequest(corrupt, graph); err == nil {
			t.Fatal("DecodeDialRequest accepted corrupt/noncanonical frame")
		}
	}
}

func FuzzParseHTTPConnect(f *testing.F) {
	f.Add([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		f.Fatalf("Compile error = %v", err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxProxyHeaderBytes+1 {
			data = data[:MaxProxyHeaderBytes+1]
		}
		request, err := ParseHTTPConnect(data, graph)
		if err == nil {
			frame, frameErr := EncodeDialRequest(request)
			if frameErr != nil {
				t.Fatalf("accepted request does not encode: %v", frameErr)
			}
			if _, decodeErr := DecodeDialRequest(frame, graph); decodeErr != nil {
				t.Fatalf("accepted request frame does not decode: %v", decodeErr)
			}
		}
	})
}

func FuzzDialRequestFrame(f *testing.F) {
	f.Add([]byte("synthetic"))
	graph, _, err := Compile(validPolicyManifest())
	if err != nil {
		f.Fatalf("Compile error = %v", err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxDialRequestFrameBytes+1 {
			data = data[:MaxDialRequestFrameBytes+1]
		}
		request, err := DecodeDialRequest(data, graph)
		if err == nil {
			canonical, encodeErr := EncodeDialRequest(request)
			if encodeErr != nil {
				t.Fatalf("decoded request does not encode: %v", encodeErr)
			}
			if !bytes.Equal(canonical, data) {
				t.Fatal("DecodeDialRequest accepted noncanonical bytes")
			}
		}
	})
}
