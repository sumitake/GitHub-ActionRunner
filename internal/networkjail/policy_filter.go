package networkjail

import (
	"bytes"
	"fmt"
	"net/netip"
	"slices"
)

func compileFilterProgram(graph DecisionGraph, ipv4 bool) []byte {
	var buffer bytes.Buffer
	buffer.WriteString("*filter\n")
	buffer.WriteString(":INPUT DROP [0:0]\n")
	buffer.WriteString(":FORWARD DROP [0:0]\n")
	buffer.WriteString(":OUTPUT DROP [0:0]\n")
	buffer.WriteString("-A INPUT -i lo -j ACCEPT\n")
	buffer.WriteString("-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")
	if ipv4 {
		buffer.WriteString("-A INPUT -p icmp --icmp-type 3 -j ACCEPT\n")
		buffer.WriteString("-A INPUT -p icmp --icmp-type 11 -j ACCEPT\n")
	} else {
		for _, kind := range []uint8{1, 2, 3, 4, 134, 135, 136} {
			fmt.Fprintf(
				&buffer,
				"-A INPUT -p ipv6-icmp --icmpv6-type %d -j ACCEPT\n",
				kind,
			)
		}
	}
	buffer.WriteString("-A OUTPUT -o lo -j ACCEPT\n")
	buffer.WriteString("-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")
	if !ipv4 {
		for _, kind := range []uint8{133, 135, 136} {
			fmt.Fprintf(
				&buffer,
				"-A OUTPUT -p ipv6-icmp --icmpv6-type %d -j ACCEPT\n",
				kind,
			)
		}
	}

	for _, prefix := range filterDenyPrefixes(graph, ipv4) {
		fmt.Fprintf(&buffer, "-A OUTPUT -d %s -j DROP\n", prefix)
	}
	for _, address := range filterDoHAddresses(graph, ipv4) {
		fmt.Fprintf(
			&buffer,
			"-A OUTPUT -p tcp -d %s --dport 443 -m conntrack --ctstate NEW -j ACCEPT\n",
			netip.PrefixFrom(address, address.BitLen()),
		)
	}
	for _, port := range graph.manifest.AllowedConnectPorts {
		fmt.Fprintf(
			&buffer,
			"-A OUTPUT -p tcp --dport %d -m conntrack --ctstate NEW -j ACCEPT\n",
			port,
		)
	}
	buffer.WriteString("COMMIT\n")
	return buffer.Bytes()
}

func filterDenyPrefixes(graph DecisionGraph, ipv4 bool) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(staticDenyPrefixes)+
		len(graph.manifest.DynamicDeny)+len(graph.manifest.DockerHost))
	for _, prefix := range staticDenyPrefixes {
		if prefix.Addr().Is4() == ipv4 {
			prefixes = append(prefixes, prefix)
		}
	}
	for _, prefix := range graph.manifest.DynamicDeny {
		if prefix.Addr().Is4() == ipv4 {
			prefixes = append(prefixes, prefix)
		}
	}
	for _, address := range graph.manifest.DockerHost {
		if address.Is4() == ipv4 {
			prefixes = append(
				prefixes,
				netip.PrefixFrom(address, address.BitLen()),
			)
		}
	}
	slices.SortFunc(prefixes, comparePrefix)
	return slices.Compact(prefixes)
}

func filterDoHAddresses(graph DecisionGraph, ipv4 bool) []netip.Addr {
	var addresses []netip.Addr
	for _, endpoint := range graph.manifest.DoHBootstrap {
		for _, address := range endpoint.Bootstrap {
			if address.Is4() == ipv4 {
				addresses = append(addresses, address)
			}
		}
	}
	slices.SortFunc(addresses, func(left, right netip.Addr) int {
		return left.Compare(right)
	})
	return slices.Compact(addresses)
}
