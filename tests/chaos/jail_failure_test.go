//go:build chaos

package chaos_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sumitake/portable-ghar/internal/networkjail"
)

type chaosResolver struct {
	answers []netip.Addr
	err     error
}

func (resolver chaosResolver) Resolve(
	context.Context,
	string,
) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), resolver.answers...), resolver.err
}

type chaosLiteralDialer struct {
	calls atomic.Uint64
}

func (dialer *chaosLiteralDialer) DialLiteral(
	context.Context,
	netip.Addr,
	uint16,
) (net.Conn, error) {
	dialer.calls.Add(1)
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

type chaosPermitClient struct {
	err   error
	calls atomic.Uint64
}

func (client *chaosPermitClient) Request(
	context.Context,
	networkjail.DialPermitRequest,
) (networkjail.Permit, error) {
	client.calls.Add(1)
	return networkjail.Permit{}, client.err
}

func TestJailPermitFailuresNeverReachKernelDial(t *testing.T) {
	_ = requireChaosHost(t)

	graph := chaosDecisionGraph(t)
	allowedFrame, err := networkjail.EncodeDialRequest(
		networkjail.DialRequest{Host: "example.com", Port: 443},
	)
	if err != nil {
		t.Fatalf("chaos: encode allowed frame: %v", err)
	}
	narrowedFrame, err := networkjail.EncodeDialRequest(
		networkjail.DialRequest{Host: "example.com", Port: 8443},
	)
	if err != nil {
		t.Fatalf("chaos: encode narrowed frame: %v", err)
	}
	public := netip.MustParseAddr("8.8.8.8")
	denied := netip.MustParseAddr("192.0.2.1")

	tests := []struct {
		name     string
		resolver chaosResolver
		permit   error
		frame    []byte
		cancel   bool
	}{
		{
			name:     "permit authority unavailable",
			resolver: chaosResolver{answers: []netip.Addr{public}},
			permit:   networkjail.ErrPermitAuthorityUnavailable,
			frame:    allowedFrame,
		},
		{
			name:     "zero permit after restart",
			resolver: chaosResolver{answers: []netip.Addr{public}},
			frame:    allowedFrame,
		},
		{
			name:     "resolver unavailable",
			resolver: chaosResolver{err: errors.New("synthetic resolver outage")},
			permit:   networkjail.ErrPermitAuthorityUnavailable,
			frame:    allowedFrame,
		},
		{
			name:     "mixed answer after policy narrowing",
			resolver: chaosResolver{answers: []netip.Addr{public, denied}},
			permit:   networkjail.ErrPermitAuthorityUnavailable,
			frame:    allowedFrame,
		},
		{
			name:     "port removed by policy",
			resolver: chaosResolver{answers: []netip.Addr{public}},
			permit:   networkjail.ErrPermitAuthorityUnavailable,
			frame:    narrowedFrame,
		},
		{
			name:     "host pressure cancellation",
			resolver: chaosResolver{answers: []netip.Addr{public}},
			permit:   networkjail.ErrPermitAuthorityUnavailable,
			frame:    allowedFrame,
			cancel:   true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			literals := &chaosLiteralDialer{}
			permits := &chaosPermitClient{err: test.permit}
			dialer, err := networkjail.NewBrokerDialer(
				graph,
				3,
				7,
				test.resolver,
				literals,
				permits,
			)
			if err != nil {
				t.Fatalf("chaos: construct broker dialer: %v", err)
			}
			ctx := context.Background()
			if test.cancel {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			connection, dialErr := dialer.DialFrame(ctx, test.frame)
			if connection != nil {
				_ = connection.Close()
				t.Fatal("chaos: failed authority returned a connection")
			}
			if dialErr == nil {
				t.Fatal("chaos: failed authority returned success")
			}
			if got := literals.calls.Load(); got != 0 {
				t.Fatalf("chaos: kernel dial count = %d, want 0", got)
			}
		})
	}
}

func TestJailRaceNarrowingAndCancellationRemainClosed(t *testing.T) {
	_ = requireChaosHost(t)

	graph := chaosDecisionGraph(t)
	frame, err := networkjail.EncodeDialRequest(
		networkjail.DialRequest{Host: "example.com", Port: 443},
	)
	if err != nil {
		t.Fatalf("chaos: encode frame: %v", err)
	}
	literals := &chaosLiteralDialer{}
	permits := &chaosPermitClient{
		err: networkjail.ErrPermitLedgerConflict,
	}
	dialer, err := networkjail.NewBrokerDialer(
		graph,
		9,
		11,
		chaosResolver{answers: []netip.Addr{
			netip.MustParseAddr("8.8.8.8"),
		}},
		literals,
		permits,
	)
	if err != nil {
		t.Fatalf("chaos: construct broker dialer: %v", err)
	}

	const attempts = 64
	var wait sync.WaitGroup
	wait.Add(attempts)
	for index := 0; index < attempts; index++ {
		go func(cancelBefore bool) {
			defer wait.Done()
			ctx := context.Background()
			if cancelBefore {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			connection, _ := dialer.DialFrame(ctx, frame)
			if connection != nil {
				_ = connection.Close()
			}
		}(index%2 == 0)
	}
	wait.Wait()
	if got := literals.calls.Load(); got != 0 {
		t.Fatalf("chaos: raced kernel dial count = %d, want 0", got)
	}
	if got := permits.calls.Load(); got == 0 || got > attempts {
		t.Fatalf("chaos: permit attempts = %d, want 1..%d", got, attempts)
	}
}

func chaosDecisionGraph(t *testing.T) networkjail.DecisionGraph {
	t.Helper()
	graph, _, err := networkjail.Compile(networkjail.PolicyManifest{
		EgressBackend:       networkjail.RestrictedBrokerV1,
		IPFamily:            networkjail.PublicDualStack,
		BrokerIPv6Posture:   networkjail.DenyViaIP6Tables,
		EnabledProtocols:    []networkjail.ProxyProtocol{networkjail.HTTPConnect},
		AllowedConnectPorts: []uint16{443},
		DoHBootstrap: []networkjail.DoHEndpoint{{
			ServerName: "dns.example.com",
			Bootstrap:  []netip.Addr{netip.MustParseAddr("8.8.8.8")},
			Path:       "/dns-query",
		}},
		DynamicDeny: []netip.Prefix{
			netip.MustParsePrefix("9.9.9.9/32"),
		},
		DockerHost: []netip.Addr{
			netip.MustParseAddr("11.11.11.11"),
		},
		JobOpenCap:                    2,
		JobDialRate:                   3,
		JobDialBurst:                  4,
		DoHOpenCap:                    1,
		DoHDialRate:                   1,
		DoHDialBurst:                  2,
		TailTimeoutSeconds:            5,
		ConntrackEntriesPerActualDial: 2,
		HostReserveEntries:            10,
		PositiveProbes: []networkjail.Probe{{
			Protocol: networkjail.HTTPConnect,
			Host:     "example.com",
			Port:     443,
		}},
		NegativeProbes: []networkjail.Probe{{
			Protocol: networkjail.HTTPConnect,
			Host:     "192.0.2.1",
			Port:     443,
		}},
	})
	if err != nil {
		t.Fatalf("chaos: compile decision graph: %v", err)
	}
	return graph
}
