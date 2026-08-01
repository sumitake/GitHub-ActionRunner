package main

import (
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
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sumitake/portable-ghar/internal/task11synthetic"
)

var errHTTPSExchange = errors.New("task11 listener HTTPS exchange failed")

type httpsExchangeRuntime struct {
	relayAddress string
	roots        *x509.CertPool
	dialContext  func(
		context.Context,
		string,
		string,
	) (net.Conn, error)
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
			dialContext:  dialHTTPSRelay,
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
		runtime.roots == nil ||
		runtime.dialContext == nil ||
		ctx.Err() != nil {
		return "", errHTTPSExchange
	}
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline || !deadline.After(time.Now()) {
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

	connection, err := runtime.dialContext(
		ctx,
		"tcp4",
		runtime.relayAddress,
	)
	if err != nil || connection == nil {
		return "", errHTTPSExchange
	}
	defer connection.Close()
	if err := bindConnectionDeadline(ctx, connection); err != nil {
		return "", errHTTPSExchange
	}
	stopCancellationClose := context.AfterFunc(ctx, func() {
		_ = connection.Close()
	})
	defer stopCancellationClose()

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

	remaining := time.Until(deadline)
	if remaining <= 0 {
		return "", errHTTPSExchange
	}
	var tunnelUsed atomic.Bool
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(
			context.Context,
			string,
			string,
		) (net.Conn, error) {
			return nil, errHTTPSExchange
		},
		DialTLSContext: func(
			dialContext context.Context,
			network string,
			address string,
		) (net.Conn, error) {
			if dialContext == nil ||
				dialContext.Err() != nil ||
				network != "tcp" ||
				address != target ||
				!tunnelUsed.CompareAndSwap(false, true) {
				return nil, errHTTPSExchange
			}
			return tlsConnection, nil
		},
		ForceAttemptHTTP2:      false,
		DisableCompression:     true,
		DisableKeepAlives:      true,
		MaxConnsPerHost:        1,
		ResponseHeaderTimeout:  remaining,
		MaxResponseHeaderBytes: 32 << 10,
		TLSNextProto: map[string]func(
			string,
			*tls.Conn,
		) http.RoundTripper{},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(
			*http.Request,
			[]*http.Request,
		) error {
			return errHTTPSExchange
		},
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		sentinel.URL,
		nil,
	)
	if err != nil ||
		request.URL.RequestURI() != requestTarget {
		return "", errHTTPSExchange
	}
	request.Host = requestHost
	request.Close = true
	request.Header.Set("User-Agent", "")
	var informationalResponse atomic.Bool
	request = request.WithContext(httptrace.WithClientTrace(
		request.Context(),
		&httptrace.ClientTrace{
			Got1xxResponse: func(
				int,
				textproto.MIMEHeader,
			) error {
				informationalResponse.Store(true)
				return errHTTPSExchange
			},
		},
	))
	response, err := client.Do(request)
	if err != nil || response == nil || response.Body == nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return "", errHTTPSExchange
	}
	bodyClosed := false
	defer func() {
		if !bodyClosed {
			_ = response.Body.Close()
		}
	}()
	if informationalResponse.Load() ||
		response.Proto != "HTTP/1.1" ||
		response.ProtoMajor != 1 ||
		response.ProtoMinor != 1 ||
		response.StatusCode != http.StatusOK ||
		len(response.Header.Values("Content-Encoding")) != 0 ||
		len(response.TransferEncoding) != 0 ||
		response.ContentLength < 0 ||
		response.ContentLength >
			int64(task11synthetic.MaximumWireBytes) ||
		len(response.Trailer) != 0 {
		return "", errHTTPSExchange
	}
	hasher := sha256.New()
	bodyBytes, err := io.Copy(
		hasher,
		io.LimitReader(
			response.Body,
			int64(task11synthetic.MaximumWireBytes)+1,
		),
	)
	if err != nil ||
		bodyBytes > int64(task11synthetic.MaximumWireBytes) ||
		response.ContentLength != bodyBytes ||
		len(response.Trailer) != 0 {
		return "", errHTTPSExchange
	}
	if err := response.Body.Close(); err != nil {
		return "", errHTTPSExchange
	}
	bodyClosed = true
	if ctx.Err() != nil {
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

func dialHTTPSRelay(
	ctx context.Context,
	network string,
	address string,
) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, address)
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
	if ctx == nil || connection == nil {
		return errHTTPSExchange
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return context.DeadlineExceeded
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
