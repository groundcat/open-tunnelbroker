package broker

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
)

// buildSolicitation renders a valid neighbor solicitation, the packet an
// upstream router sends when it wants to reach target.
func buildSolicitation(source, target netip.Addr) []byte {
	packet := make([]byte, ipv6HeaderLength+ndpMessageLength)
	packet[0] = 6 << 4
	binary.BigEndian.PutUint16(packet[4:6], ndpMessageLength)
	packet[6] = protocolICMPv6
	packet[7] = ndpHopLimit
	sourceBytes := source.As16()
	copy(packet[8:24], sourceBytes[:])
	// Solicitations are addressed to the target's solicited-node group.
	solicitedNode := solicitedNodeAddress(target)
	solicitedBytes := solicitedNode.As16()
	copy(packet[24:40], solicitedBytes[:])
	message := packet[ipv6HeaderLength:]
	message[0] = icmpv6NeighborSolicitation
	targetBytes := target.As16()
	copy(message[8:24], targetBytes[:])
	binary.BigEndian.PutUint16(message[2:4], icmpv6Checksum(source, solicitedNode, message))
	return packet
}

func solicitedNodeAddress(target netip.Addr) netip.Addr {
	base := netip.MustParseAddr("ff02::1:ff00:0").As16()
	targetBytes := target.As16()
	base[13], base[14], base[15] = targetBytes[13], targetBytes[14], targetBytes[15]
	return netip.AddrFrom16(base)
}

func TestSolicitationRoundTripProducesUsableAdvertisement(t *testing.T) {
	router := netip.MustParseAddr("2001:db8:1200:416::1")
	client := netip.MustParseAddr("2001:db8:1200:416:dead:beef:cafe:1")
	hardware, err := net.ParseMAC("52:54:00:11:22:33")
	if err != nil {
		t.Fatal(err)
	}

	solicitation, err := parseNeighborSolicitation(buildSolicitation(router, client))
	if err != nil {
		t.Fatalf("valid solicitation was rejected: %v", err)
	}
	if solicitation.Source != router || solicitation.Target != client {
		t.Fatalf("solicitation parsed incorrectly: %+v", solicitation)
	}

	advertisement, err := buildNeighborAdvertisement(solicitation.Target, solicitation.Source, hardware)
	if err != nil {
		t.Fatal(err)
	}
	message := advertisement[ipv6HeaderLength:]
	if message[0] != icmpv6NeighborAdvertisement {
		t.Fatalf("wrong ICMPv6 type: %d", message[0])
	}
	// The reply must be verifiable by the router: correct checksum, hop limit
	// 255, solicited flag set, and the proxying host's Ethernet address.
	if got := icmpv6Checksum(solicitation.Target, solicitation.Source, message); got != 0 {
		t.Fatalf("advertisement checksum does not verify: %#04x", got)
	}
	if advertisement[7] != ndpHopLimit {
		t.Fatalf("advertisement hop limit is %d, must be %d", advertisement[7], ndpHopLimit)
	}
	if message[4]&ndpFlagSolicited == 0 {
		t.Fatal("advertisement is not marked solicited")
	}
	// Override must stay clear so a proxy reply can never displace a real
	// neighbor entry.
	if message[4]&0x20 != 0 {
		t.Fatal("proxy advertisement must not set the Override flag")
	}
	if target, _ := netip.AddrFromSlice(message[8:24]); target != client {
		t.Fatalf("advertisement announces the wrong target: %s", target)
	}
	if message[24] != ndpOptionTargetLinkLayer || message[25] != 1 {
		t.Fatal("advertisement is missing its target link-layer address option")
	}
	if got := net.HardwareAddr(message[26:32]).String(); got != hardware.String() {
		t.Fatalf("advertisement carries the wrong Ethernet address: %s", got)
	}
	source, _ := netip.AddrFromSlice(advertisement[8:24])
	destination, _ := netip.AddrFromSlice(advertisement[24:40])
	if source != client || destination != router {
		t.Fatalf("advertisement addressing is wrong: %s -> %s", source, destination)
	}
}

func TestMalformedOrOffLinkSolicitationsAreRejected(t *testing.T) {
	router := netip.MustParseAddr("2001:db8:1200:416::1")
	client := netip.MustParseAddr("2001:db8:1200:416::99")
	valid := buildSolicitation(router, client)

	corrupt := func(mutate func([]byte)) []byte {
		packet := append([]byte(nil), valid...)
		mutate(packet)
		return packet
	}
	cases := map[string][]byte{
		"truncated":           valid[:ipv6HeaderLength+8],
		"empty":               nil,
		"wrong IP version":    corrupt(func(p []byte) { p[0] = 4 << 4 }),
		"not ICMPv6":          corrupt(func(p []byte) { p[6] = 17 }),
		"forwarded hop limit": corrupt(func(p []byte) { p[7] = 64 }),
		"wrong ICMPv6 type":   corrupt(func(p []byte) { p[ipv6HeaderLength] = 128 }),
		"broken checksum":     corrupt(func(p []byte) { p[ipv6HeaderLength+3] ^= 0xff }),
		"multicast target":    buildSolicitation(router, netip.MustParseAddr("ff02::1")),
		"unspecified source":  buildSolicitation(netip.IPv6Unspecified(), client),
		"oversized payload":   corrupt(func(p []byte) { binary.BigEndian.PutUint16(p[4:6], 0xffff) }),
		"undersized payload":  corrupt(func(p []byte) { binary.BigEndian.PutUint16(p[4:6], 8) }),
	}
	for name, packet := range cases {
		if _, err := parseNeighborSolicitation(packet); err == nil {
			t.Errorf("%s solicitation was accepted", name)
		}
	}
	// A hop limit of exactly 255 from a link-local source is the normal case and
	// must still be accepted.
	if _, err := parseNeighborSolicitation(buildSolicitation(netip.MustParseAddr("fe80::1"), client)); err != nil {
		t.Errorf("link-local solicitation was rejected: %v", err)
	}
}

func TestProxySetAnswersDelegatedPrefixButNeverLocalOrForeignAddresses(t *testing.T) {
	upstream := Upstream{ID: 1, V6CIDR: "2001:db8:1200:416::/64", Mode: UpstreamOnLink}
	tunnels := []Tunnel{
		{ID: 1, V6CIDR: "2001:db8:1200:416::/64", Enabled: true},
		{ID: 2, V6CIDR: "2001:db8:9999::/64", Enabled: true}, // outside the upstream
		{ID: 3, V6CIDR: "2001:db8:1200:416::/64", Enabled: false},
	}
	// The provider-assigned host address lives inside the delegated prefix on a
	// single-/64 VPS, so it must be excluded or the host loses reachability.
	host := netip.MustParseAddr("2001:db8:1200:416::10")
	set := ndpProxySetFor(upstream, tunnels, []netip.Addr{host, netip.MustParseAddr("fe80::1")})

	if len(set.Delegated) != 1 || set.Delegated[0] != netip.MustParsePrefix("2001:db8:1200:416::/64") {
		t.Fatalf("unexpected delegated set: %+v", set.Delegated)
	}
	if len(set.Local) != 1 || set.Local[0] != host {
		t.Fatalf("local exclusions must contain only upstream-prefix addresses: %+v", set.Local)
	}
	if !set.shouldAnswer(netip.MustParseAddr("2001:db8:1200:416:aaaa::1")) {
		t.Fatal("a delegated address is not answered")
	}
	if set.shouldAnswer(host) {
		t.Fatal("the host's own address must never be proxied")
	}
	if set.shouldAnswer(netip.MustParseAddr("2001:db8:5555::1")) {
		t.Fatal("an address outside every delegated prefix was answered")
	}
}

func TestProxyingIsDisabledForRoutedUpstreams(t *testing.T) {
	upstream := Upstream{ID: 1, V6CIDR: "2001:db8:1200::/48", Mode: UpstreamRouted}
	tunnels := []Tunnel{{ID: 1, V6CIDR: "2001:db8:1200:100::/56", Enabled: true}}
	if set := ndpProxySetFor(upstream, tunnels, nil); !set.empty() {
		t.Fatalf("routed delegation needs no Neighbor Discovery proxy: %+v", set)
	}
	// A row written before this setting existed must behave as routed.
	if set := ndpProxySetFor(Upstream{ID: 1, V6CIDR: upstream.V6CIDR}, tunnels, nil); !set.empty() {
		t.Fatal("legacy configuration enabled Neighbor Discovery proxying")
	}
}
