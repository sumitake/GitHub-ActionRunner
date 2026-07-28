package networkjail

import (
	"net/netip"
)

func publicV4(a, b, c, d byte) netip.Addr {
	return netip.AddrFrom4([4]byte{a, b, c, d})
}

func deniedDocumentationV4() netip.Addr {
	return netip.AddrFrom4([4]byte{192, 0, 2, 1})
}

func validPolicyManifest() PolicyManifest {
	return PolicyManifest{
		EgressBackend:     RestrictedBrokerV1,
		IPFamily:          PublicDualStack,
		BrokerIPv6Posture: DenyViaIP6Tables,
		EnabledProtocols:  []ProxyProtocol{HTTPConnect, SOCKS5Connect},
		AllowedConnectPorts: []uint16{
			443,
			8443,
		},
		DoHBootstrap: []DoHEndpoint{
			{
				ServerName: "dns.example.com",
				Bootstrap:  []netip.Addr{publicV4(8, 8, 8, 8)},
				Path:       "/dns-query",
			},
		},
		DynamicDeny: []netip.Prefix{
			netip.PrefixFrom(publicV4(9, 9, 9, 9), 32),
		},
		DockerHost: []netip.Addr{
			publicV4(11, 11, 11, 11),
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
		PositiveProbes: []Probe{
			{Protocol: HTTPConnect, Host: "example.com", Port: 443},
		},
		NegativeProbes: []Probe{
			{Protocol: HTTPConnect, Host: deniedDocumentationV4().String(), Port: 443},
		},
	}
}
