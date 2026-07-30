package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sumitake/portable-ghar/internal/task11synthetic"
)

func TestExchangeHTTPSUsesExactLoopbackConnectAndTLSBindings(t *testing.T) {
	t.Parallel()

	body := []byte("portable-ghar-task11-response\n")
	server := httptest.NewUnstartedServer(http.HandlerFunc(
		func(writer http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodGet ||
				request.URL.RequestURI() != "/probe" ||
				request.Host != "example.com" ||
				request.Header.Get("Connection") != "close" {
				t.Errorf("unexpected HTTPS request: %+v", request)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			writer.Header().Set("Content-Type", "application/octet-stream")
			_, _ = writer.Write(body)
		},
	))
	server.StartTLS()
	defer server.Close()

	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	relay := newTestConnectRelay(t, server.Listener.Addr().String())
	defer relay.Close()
	sentinel := sentinelForTLSTest(server.Certificate(), body)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := exchangeHTTPSVia(
		ctx,
		sentinel,
		httpsExchangeRuntime{
			relayAddress: relay.Address(),
			roots:        roots,
		},
	)
	if err != nil || got != sentinel.ResponseBodyDigest {
		t.Fatalf("exchangeHTTPSVia() = %q, %v", got, err)
	}
	relay.Wait(t)
	const wantConnect = "CONNECT example.com:443 HTTP/1.1\r\n" +
		"Host: example.com:443\r\n\r\n"
	if relay.Request() != wantConnect {
		t.Fatalf("CONNECT request = %q, want %q", relay.Request(), wantConnect)
	}
}

func TestExchangeHTTPSRejectsTLSBodyAndStatusSubstitution(t *testing.T) {
	t.Parallel()

	tests := map[string]func(
		*task11synthetic.Sentinel,
		*httptest.Server,
	){
		"SPKI": func(
			sentinel *task11synthetic.Sentinel,
			_ *httptest.Server,
		) {
			sentinel.SPKIDigest = listenerTestDigestA
		},
		"certificate": func(
			sentinel *task11synthetic.Sentinel,
			_ *httptest.Server,
		) {
			sentinel.CertificateDigest = listenerTestDigestA
		},
		"body": func(
			sentinel *task11synthetic.Sentinel,
			_ *httptest.Server,
		) {
			sentinel.ResponseBodyDigest = listenerTestDigestA
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			body := []byte("portable-ghar-task11-response\n")
			server := httptest.NewUnstartedServer(http.HandlerFunc(
				func(writer http.ResponseWriter, _ *http.Request) {
					_, _ = writer.Write(body)
				},
			))
			server.StartTLS()
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			relay := newTestConnectRelay(t, server.Listener.Addr().String())
			defer relay.Close()
			sentinel := sentinelForTLSTest(server.Certificate(), body)
			mutate(&sentinel, server)
			ctx, cancel := context.WithTimeout(
				context.Background(),
				5*time.Second,
			)
			defer cancel()
			if _, err := exchangeHTTPSVia(
				ctx,
				sentinel,
				httpsExchangeRuntime{
					relayAddress: relay.Address(),
					roots:        roots,
				},
			); err == nil {
				t.Fatal("exchangeHTTPSVia accepted substituted evidence")
			}
			relay.Wait(t)
		})
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(
		func(writer http.ResponseWriter, request *http.Request) {
			http.Redirect(writer, request, "/other", http.StatusFound)
		},
	))
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	relay := newTestConnectRelay(t, server.Listener.Addr().String())
	defer relay.Close()
	sentinel := sentinelForTLSTest(server.Certificate(), []byte("unused"))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := exchangeHTTPSVia(
		ctx,
		sentinel,
		httpsExchangeRuntime{
			relayAddress: relay.Address(),
			roots:        roots,
		},
	); err == nil {
		t.Fatal("exchangeHTTPSVia followed or accepted redirect")
	}
	relay.Wait(t)
}

func sentinelForTLSTest(
	certificate *x509.Certificate,
	body []byte,
) task11synthetic.Sentinel {
	certificateSum := sha256.Sum256(certificate.Raw)
	spkiSum := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	bodySum := sha256.Sum256(body)
	return task11synthetic.Sentinel{
		URL:                  "https://example.com/probe",
		Host:                 "example.com",
		Port:                 443,
		HostIdentityDigest:   listenerTestDigestC,
		SPKIDigest:           hex.EncodeToString(spkiSum[:]),
		CertificateDigest:    hex.EncodeToString(certificateSum[:]),
		PolicyEntryDigest:    listenerTestDigestF,
		PolicyEvidenceDigest: listenerTestDigestA,
		ResponseBodyDigest:   hex.EncodeToString(bodySum[:]),
	}
}

type testConnectRelay struct {
	listener net.Listener
	target   string

	mu      sync.Mutex
	request string
	err     error
	done    chan struct{}
}

func newTestConnectRelay(t *testing.T, target string) *testConnectRelay {
	t.Helper()
	listener, err := net.Listen(
		"tcp4",
		net.JoinHostPort(net.IPv4(127, 0, 0, 1).String(), "0"),
	)
	if err != nil {
		t.Fatalf("listen relay: %v", err)
	}
	relay := &testConnectRelay{
		listener: listener,
		target:   target,
		done:     make(chan struct{}),
	}
	go relay.serve()
	return relay
}

func (r *testConnectRelay) Address() string {
	return r.listener.Addr().String()
}

func (r *testConnectRelay) Request() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.request
}

func (r *testConnectRelay) Wait(t *testing.T) {
	t.Helper()
	select {
	case <-r.done:
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not finish")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		t.Fatalf("relay error: %v", r.err)
	}
}

func (r *testConnectRelay) Close() {
	_ = r.listener.Close()
	select {
	case <-r.done:
	default:
	}
}

func (r *testConnectRelay) serve() {
	defer close(r.done)
	client, err := r.listener.Accept()
	if err != nil {
		if !errors.Is(err, net.ErrClosed) {
			r.setError(err)
		}
		return
	}
	defer client.Close()
	_ = r.listener.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReaderSize(client, 16<<10)
	var request strings.Builder
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			r.setError(readErr)
			return
		}
		request.WriteString(line)
		if strings.HasSuffix(request.String(), "\r\n\r\n") {
			break
		}
		if request.Len() > 16<<10 {
			r.setError(errors.New("CONNECT request too large"))
			return
		}
	}
	r.mu.Lock()
	r.request = request.String()
	r.mu.Unlock()
	target, err := net.DialTimeout("tcp", r.target, 5*time.Second)
	if err != nil {
		r.setError(err)
		return
	}
	defer target.Close()
	if _, err := io.WriteString(
		client,
		"HTTP/1.1 200 Connection Established\r\n\r\n",
	); err != nil {
		r.setError(err)
		return
	}
	_ = client.SetDeadline(time.Time{})
	_ = target.SetDeadline(time.Time{})
	copyDone := make(chan error, 1)
	go func() {
		_, copyErr := io.Copy(target, reader)
		copyDone <- copyErr
	}()
	_, reverseErr := io.Copy(client, target)
	_ = client.Close()
	_ = target.Close()
	forwardErr := <-copyDone
	if reverseErr != nil &&
		!errors.Is(reverseErr, net.ErrClosed) &&
		!strings.Contains(reverseErr.Error(), "closed network connection") {
		r.setError(reverseErr)
		return
	}
	if forwardErr != nil &&
		!errors.Is(forwardErr, net.ErrClosed) &&
		!strings.Contains(forwardErr.Error(), "closed network connection") {
		r.setError(forwardErr)
	}
}

func (r *testConnectRelay) setError(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err == nil {
		r.err = err
	}
}
