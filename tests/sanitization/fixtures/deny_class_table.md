<!-- Synthetic doc-style deny-class table, mirrors docs/superpowers/specs/2026-07-10-portable-ghar-platform-design.md.
     Used to prove H2's fixture-path qualification: this exact content is a
     FINDING when scanned as a non-fixture path but passes when scanned
     under a fixture-qualified path (tests/, config/examples/, docs/). -->

Blocked egress classes: loopback (`127.0.0.0/8`, `::1`); private/unique-local
(`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`); link-local
(`169.254.0.0/16`, `fe80::/10`), including the metadata address
`169.254.169.254`; shared/CGNAT (`100.64.0.0/10`); reserved/documentation
(`0.0.0.0/8`, `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
`2001:db8::/32`); multicast/broadcast (`224.0.0.0/4`, `255.255.255.255`,
`ff00::/8`).
