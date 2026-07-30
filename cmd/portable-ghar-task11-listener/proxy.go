package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sumitake/portable-ghar/internal/task11synthetic"
)

var errHTTPSExchange = errors.New("task11 listener HTTPS exchange failed")

type httpsExchangeRuntime struct {
	relayAddress string
	roots        *x509.CertPool
}

func exchangeHTTPS(
	ctx context.Context,
	sentinel task11synthetic.Sentinel,
) (string, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		return "", errHTTPSExchange
	}
	return exchangeHTTPSVia(
		ctx,
		sentinel,
		httpsExchangeRuntime{
			relayAddress: task11synthetic.HTTPSRelayEndpoint,
			roots:        roots,
		},
	)
}

func exchangeHTTPSVia(
	ctx context.Context,
	sentinel task11synthetic.Sentinel,
	runtime httpsExchangeRuntime,
) (string, error) {
	if ctx == nil ||
		runtime.relayAddress == "" ||
		runtime.roots == nil {
		return "", errHTTPSExchange
	}
	target, requestTarget, requestHost, err := parseHTTPSExchangeTarget(
		sentinel,
	)
	if err != nil {
		return "", errHTTPSExchange
	}
	expectedSPKI, err := decodeHTTPSDigest(sentinel.SPKIDigest)
	if err != nil {
		return "", errHTTPSExchange
	}
	expectedCertificate, err := decodeHTTPSDigest(
		sentinel.CertificateDigest,
	)
	if err != nil {
		return "", errHTTPSExchange
	}
	expectedBody, err := decodeHTTPSDigest(sentinel.ResponseBodyDigest)
	if err != nil {
		return "", errHTTPSExchange
	}

	var dialer net.Dialer
	connection, err := dialer.DialContext(
		ctx,
		"tcp4",
		runtime.relayAddress,
	)
	if err != nil {
		return "", errHTTPSExchange
	}
	defer connection.Close()
	if err := bindConnectionDeadline(ctx, connection); err != nil {
		return "", errHTTPSExchange
	}

	connectRequest := "CONNECT " + target + " HTTP/1.1\r\n" +
		"Host: " + target + "\r\n\r\n"
	if err := writeExact(connection, []byte(connectRequest)); err != nil {
		return "", errHTTPSExchange
	}
	const connectResponse = "HTTP/1.1 200 Connection Established\r\n\r\n"
	responseBytes := make([]byte, len(connectResponse))
	if _, err := io.ReadFull(connection, responseBytes); err != nil ||
		string(responseBytes) != connectResponse {
		return "", errHTTPSExchange
	}

	tlsConnection := tls.Client(connection, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		RootCAs:    runtime.roots,
		ServerName: sentinel.Host,
	})
	defer tlsConnection.Close()
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		return "", errHTTPSExchange
	}
	state := tlsConnection.ConnectionState()
	if len(state.PeerCertificates) == 0 ||
		len(state.VerifiedChains) == 0 ||
		(state.NegotiatedProtocol != "" &&
			state.NegotiatedProtocol != "http/1.1") {
		return "", errHTTPSExchange
	}
	leaf := state.PeerCertificates[0]
	observedSPKI := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	observedCertificate := sha256.Sum256(leaf.Raw)
	if subtle.ConstantTimeCompare(
		observedSPKI[:],
		expectedSPKI[:],
	) != 1 ||
		subtle.ConstantTimeCompare(
			observedCertificate[:],
			expectedCertificate[:],
		) != 1 {
		return "", errHTTPSExchange
	}

	getRequest := "GET " + requestTarget + " HTTP/1.1\r\n" +
		"Host: " + requestHost + "\r\n" +
		"Connection: close\r\n\r\n"
	if err := writeExact(tlsConnection, []byte(getRequest)); err != nil {
		return "", errHTTPSExchange
	}
	request := &http.Request{
		Method: http.MethodGet,
		URL: &url.URL{
			Scheme: "https",
			Host:   requestHost,
			Path:   requestTarget,
		},
		Host:       requestHost,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	response, err := http.ReadResponse(
		bufio.NewReaderSize(tlsConnection, 32<<10),
		request,
	)
	if err != nil || response == nil {
		return "", errHTTPSExchange
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK ||
		response.Header.Get("Content-Encoding") != "" ||
		len(response.Trailer) != 0 {
		return "", errHTTPSExchange
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, response.Body); err != nil ||
		len(response.Trailer) != 0 {
		return "", errHTTPSExchange
	}
	observedBodyBytes := hasher.Sum(nil)
	if subtle.ConstantTimeCompare(
		observedBodyBytes,
		expectedBody[:],
	) != 1 {
		return "", errHTTPSExchange
	}
	return hex.EncodeToString(observedBodyBytes), nil
}

func parseHTTPSExchangeTarget(
	sentinel task11synthetic.Sentinel,
) (string, string, string, error) {
	if sentinel.Port == 0 || sentinel.Host == "" {
		return "", "", "", errHTTPSExchange
	}
	parsed, err := url.Parse(sentinel.URL)
	if err != nil ||
		parsed.Scheme != "https" ||
		parsed.User != nil ||
		parsed.Opaque != "" ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" ||
		parsed.RawPath != "" ||
		parsed.Path == "" ||
		!strings.HasPrefix(parsed.Path, "/") ||
		parsed.Hostname() != sentinel.Host ||
		parsed.String() != sentinel.URL {
		return "", "", "", errHTTPSExchange
	}
	port := parsed.Port()
	if port == "" {
		if sentinel.Port != 443 {
			return "", "", "", errHTTPSExchange
		}
	} else if port != strconv.FormatUint(uint64(sentinel.Port), 10) {
		return "", "", "", errHTTPSExchange
	}
	target := net.JoinHostPort(
		sentinel.Host,
		strconv.FormatUint(uint64(sentinel.Port), 10),
	)
	return target, parsed.RequestURI(), parsed.Host, nil
}

func decodeHTTPSDigest(raw string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if len(raw) != sha256.Size*2 || raw != strings.ToLower(raw) {
		return result, errHTTPSExchange
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != sha256.Size {
		return result, errHTTPSExchange
	}
	copy(result[:], decoded)
	return result, nil
}

func bindConnectionDeadline(
	ctx context.Context,
	connection net.Conn,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil
	}
	if !deadline.After(time.Now()) {
		return context.DeadlineExceeded
	}
	return connection.SetDeadline(deadline)
}

func writeExact(writer io.Writer, document []byte) error {
	for len(document) > 0 {
		written, err := writer.Write(document)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(document) {
			return fmt.Errorf("%w: short write", errHTTPSExchange)
		}
		document = document[written:]
	}
	return nil
}
