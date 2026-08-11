package broker

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sort"
)

// Neighbor Discovery proxying exists for providers that place the delegated
// prefix on-link instead of routing it. The upstream router then resolves every
// address in the prefix with Neighbor Discovery on the upstream segment, while
// the addresses actually live behind WireGuard. Answering that discovery for a
// whole prefix cannot be expressed as a fixed list of kernel proxy entries, so
// the daemon parses solicitations and replies itself.
const (
	ipv6HeaderLength = 40
	protocolICMPv6   = 58

	// Neighbor Discovery packets must carry hop limit 255 so that a response
	// can never be triggered by an off-link sender.
	ndpHopLimit = 255

	icmpv6NeighborSolicitation  = 135
	icmpv6NeighborAdvertisement = 136

	ndpOptionTargetLinkLayer = 2
	ndpMessageLength         = 24
	ndpAdvertisementLength   = ndpMessageLength + 8

	// A proxy advertisement is solicited and announces a router, but must not
	// set Override so that it can never displace a genuine neighbor entry
	// (RFC 4861 section 7.2.8).
	ndpFlagRouter    = 0x80
	ndpFlagSolicited = 0x40

	ethernetAddressLength = 6
	ethernetHeaderLength  = 14
)

var errNotNeighborSolicitation = errors.New("packet is not a valid neighbor solicitation")

type neighborSolicitation struct {
	Source, Destination, Target netip.Addr
}

// parseNeighborSolicitation reads an IPv6 packet beginning at its fixed header
// and returns the solicitation it carries. Every RFC 4861 receive check is
// enforced, including the ICMPv6 checksum and the hop limit, so a malformed or
// off-link packet can never produce an advertisement.
func parseNeighborSolicitation(packet []byte) (neighborSolicitation, error) {
	if len(packet) < ipv6HeaderLength+ndpMessageLength || packet[0]>>4 != 6 {
		return neighborSolicitation{}, errNotNeighborSolicitation
	}
	// Extension headers are rejected rather than walked: a neighbor
	// solicitation is defined to carry none.
	if packet[6] != protocolICMPv6 || packet[7] != ndpHopLimit {
		return neighborSolicitation{}, errNotNeighborSolicitation
	}
	payloadLength := int(binary.BigEndian.Uint16(packet[4:6]))
	if payloadLength < ndpMessageLength || ipv6HeaderLength+payloadLength > len(packet) {
		return neighborSolicitation{}, errNotNeighborSolicitation
	}
	message := packet[ipv6HeaderLength : ipv6HeaderLength+payloadLength]
	if message[0] != icmpv6NeighborSolicitation || message[1] != 0 {
		return neighborSolicitation{}, errNotNeighborSolicitation
	}
	source, sourceOK := netip.AddrFromSlice(packet[8:24])
	destination, destinationOK := netip.AddrFromSlice(packet[24:40])
	target, targetOK := netip.AddrFromSlice(message[8:24])
	if !sourceOK || !destinationOK || !targetOK {
		return neighborSolicitation{}, errNotNeighborSolicitation
	}
	if icmpv6Checksum(source, destination, message) != 0 {
		return neighborSolicitation{}, errNotNeighborSolicitation
	}
	// A multicast or otherwise non-routable target is never a real address
	// behind this host, and an unspecified source marks duplicate address
	// detection, which must be left to the address owner downstream.
	if !target.IsGlobalUnicast() && !target.IsPrivate() {
		return neighborSolicitation{}, errNotNeighborSolicitation
	}
	if !source.IsGlobalUnicast() && !source.IsPrivate() && !source.IsLinkLocalUnicast() {
		return neighborSolicitation{}, errNotNeighborSolicitation
	}
	return neighborSolicitation{Source: source, Destination: destination, Target: target}, nil
}

// buildNeighborAdvertisement renders a solicited proxy advertisement for target,
// addressed to the solicitor. The source address is the proxied target itself,
// matching the kernel's own proxy_ndp behavior, so upstream routers that already
// accept kernel proxying accept these replies unchanged.
func buildNeighborAdvertisement(target, destination netip.Addr, hardware net.HardwareAddr) ([]byte, error) {
	if !target.Is6() || !destination.Is6() {
		return nil, errors.New("neighbor advertisement requires IPv6 addresses")
	}
	if len(hardware) != ethernetAddressLength {
		return nil, errors.New("neighbor discovery proxying requires an Ethernet upstream interface")
	}
	packet := make([]byte, ipv6HeaderLength+ndpAdvertisementLength)
	packet[0] = 6 << 4
	binary.BigEndian.PutUint16(packet[4:6], ndpAdvertisementLength)
	packet[6] = protocolICMPv6
	packet[7] = ndpHopLimit
	targetBytes, destinationBytes := target.As16(), destination.As16()
	copy(packet[8:24], targetBytes[:])
	copy(packet[24:40], destinationBytes[:])

	message := packet[ipv6HeaderLength:]
	message[0] = icmpv6NeighborAdvertisement
	message[4] = ndpFlagRouter | ndpFlagSolicited
	copy(message[8:24], targetBytes[:])
	message[24] = ndpOptionTargetLinkLayer
	message[25] = 1
	copy(message[26:32], hardware)
	binary.BigEndian.PutUint16(message[2:4], icmpv6Checksum(target, destination, message))
	return packet, nil
}

// icmpv6Checksum computes the ICMPv6 checksum over the IPv6 pseudo-header and
// message. Running it across a message that already carries a correct checksum
// yields zero, which is how received packets are verified.
func icmpv6Checksum(source, destination netip.Addr, message []byte) uint16 {
	sourceBytes, destinationBytes := source.As16(), destination.As16()
	var sum uint32
	for _, address := range [][16]byte{sourceBytes, destinationBytes} {
		for i := 0; i < len(address); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(address[i : i+2]))
		}
	}
	sum += uint32(len(message))
	sum += protocolICMPv6
	for i := 0; i+1 < len(message); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(message[i : i+2]))
	}
	if len(message)%2 == 1 {
		sum += uint32(message[len(message)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// ndpProxySet is the set of addresses this host answers Neighbor Discovery for
// on behalf of downstream tunnels.
type ndpProxySet struct {
	// Delegated holds the prefixes routed into WireGuard.
	Delegated []netip.Prefix
	// Local holds addresses configured on this host. They are never proxied,
	// because the kernel already answers for them and a second advertisement
	// would fight with it. The delegated prefix legitimately contains the
	// provider-assigned host address in on-link mode, so this exclusion is
	// what keeps that address working.
	Local []netip.Addr
}

func (s ndpProxySet) empty() bool { return len(s.Delegated) == 0 }

// shouldAnswer reports whether this host proxies Neighbor Discovery for target.
func (s ndpProxySet) shouldAnswer(target netip.Addr) bool {
	if !target.Is6() {
		return false
	}
	for _, local := range s.Local {
		if local == target {
			return false
		}
	}
	for _, prefix := range s.Delegated {
		if prefix.Contains(target) {
			return true
		}
	}
	return false
}

// equal reports whether two sets describe the same proxy behavior, letting the
// reconciler skip needless reconfiguration.
func (s ndpProxySet) equal(other ndpProxySet) bool {
	if len(s.Delegated) != len(other.Delegated) || len(s.Local) != len(other.Local) {
		return false
	}
	for i := range s.Delegated {
		if s.Delegated[i] != other.Delegated[i] {
			return false
		}
	}
	for i := range s.Local {
		if s.Local[i] != other.Local[i] {
			return false
		}
	}
	return true
}

// ndpProxySetFor collects the prefixes to proxy for one upstream's tunnels. It
// returns an empty set unless that upstream is on-link, because a routed prefix
// needs no Neighbor Discovery help at all. Disabled tunnels are excluded so
// that turning a tunnel off also stops attracting its traffic.
func ndpProxySetFor(up Upstream, tunnels []Tunnel, local []netip.Addr) ndpProxySet {
	if upstreamMode(up) != UpstreamOnLink {
		return ndpProxySet{}
	}
	upstream, ok := delegatedPrefix(up)
	if !ok {
		return ndpProxySet{}
	}
	set := ndpProxySet{}
	for _, tunnel := range tunnels {
		if !tunnel.Enabled {
			continue
		}
		prefix, parseErr := netip.ParsePrefix(tunnel.V6CIDR)
		if parseErr != nil || !upstream.Contains(prefix.Addr()) {
			continue
		}
		set.Delegated = append(set.Delegated, prefix.Masked())
	}
	for _, address := range local {
		if address.Is6() && upstream.Contains(address) {
			set.Local = append(set.Local, address)
		}
	}
	set.sort()
	return set
}

func (s *ndpProxySet) sort() {
	sort.Slice(s.Delegated, func(i, j int) bool {
		if s.Delegated[i].Addr() != s.Delegated[j].Addr() {
			return s.Delegated[i].Addr().Less(s.Delegated[j].Addr())
		}
		return s.Delegated[i].Bits() < s.Delegated[j].Bits()
	})
	sort.Slice(s.Local, func(i, j int) bool { return s.Local[i].Less(s.Local[j]) })
}

// merge folds another set into this one, which is how two on-link upstreams
// that share one egress interface end up behind a single listener.
func (s *ndpProxySet) merge(other ndpProxySet) {
	s.Delegated = append(s.Delegated, other.Delegated...)
	s.Local = append(s.Local, other.Local...)
	s.sort()
}

// ndpProxySetsFor maps each egress interface to the addresses this host answers
// Neighbor Discovery for there. Only on-link upstreams contribute, and an
// interface shared by several of them carries the union of their prefixes.
func ndpProxySetsFor(upstreams []Upstream, tunnels map[int64][]Tunnel, local map[string][]netip.Addr) map[string]ndpProxySet {
	sets := make(map[string]ndpProxySet)
	for _, upstream := range upstreams {
		if upstreamMode(upstream) != UpstreamOnLink || upstream.EgressInterface == "" {
			continue
		}
		set := ndpProxySetFor(upstream, tunnels[upstream.ID], local[upstream.EgressInterface])
		if set.empty() {
			continue
		}
		existing := sets[upstream.EgressInterface]
		existing.merge(set)
		sets[upstream.EgressInterface] = existing
	}
	return sets
}
