package broker

import (
	"net/netip"
	"time"
)

const warpInterfaceName = "wg-warp"

const (
	V4ModeInherit = ""
	V4ModeOff     = "off"
	V4ModeNative  = "native"
	V4ModeWarp    = "warp"
)

const (
	InterTunnelIsolated = "isolated"
	InterTunnelGroups   = "groups"
	InterTunnelAny      = "any"
)

// Upstream delegation modes describe how the provider hands an IPv6 prefix to
// this host, which decides whether the prefix can simply be routed downstream.
const (
	// UpstreamRouted is the normal case: the provider routes the whole prefix
	// to this host, so subprefixes only need a route out of the WireGuard
	// interface.
	UpstreamRouted = "routed"
	// UpstreamOnLink is the single-/64 VPS case: the provider treats the
	// prefix as directly attached to the upstream interface and resolves
	// every address in it with Neighbor Discovery. Delegated addresses live
	// behind WireGuard, so the host has to answer that discovery itself.
	UpstreamOnLink = "on-link"
)

func validUpstreamMode(mode string) bool {
	return mode == UpstreamRouted || mode == UpstreamOnLink
}

// Settings holds the preferences that are global to the deployment. Everything
// that describes one provider connection lives on an Upstream instead, because
// a host may terminate several unrelated connections at once.
type Settings struct {
	V4NAT             bool
	V4Warp            bool
	V4Pool            string
	DefaultDNS        string
	InterTunnelPolicy string
}

// Upstream is one provider connection together with the IPv6 prefix delegated
// over it and the WireGuard interface that redistributes that prefix. Upstreams
// are mutually independent: each has its own transport (WireGuard, L2TP, BGP,
// plain Ethernet, ...), its own delegated prefix, its own keys, and its own
// listening port.
type Upstream struct {
	ID                                  int64
	Name                                string
	V6CIDR                              string
	Mode                                string
	PublicV4                            string
	EgressInterface                     string
	InterfaceName                       string
	EndpointHost                        string
	EndpointPort                        int
	ServerAddress                       string
	ServerPrivateKey                    string
	TransportAddress                    string
	MTU, Keepalive                      int
	MinPrefix, MaxPrefix, DefaultPrefix int
	V4Mode                              string
	TunnelCount                         int
	CreatedAt, UpdatedAt                time.Time
}

// upstreamMode reports the configured delegation mode, defaulting to routed so
// that databases predating this setting keep their existing behavior.
func upstreamMode(up Upstream) string {
	if validUpstreamMode(up.Mode) {
		return up.Mode
	}
	return UpstreamRouted
}

// transportPrefix returns the WireGuard transport address when it is configured
// outside the delegated prefix. In on-link mode the entire delegated prefix
// belongs to downstream tunnels, so the tunnel interface itself is numbered
// from a separate ULA or documentation range instead.
func transportPrefix(up Upstream) (netip.Prefix, bool) {
	prefix, err := netip.ParsePrefix(up.TransportAddress)
	if err != nil || !prefix.Addr().Is6() {
		return netip.Prefix{}, false
	}
	return prefix, true
}

// delegatedPrefix returns the prefix this upstream may split into tunnels.
func delegatedPrefix(up Upstream) (netip.Prefix, bool) {
	prefix, err := netip.ParsePrefix(up.V6CIDR)
	if err != nil || !prefix.Addr().Is6() {
		return netip.Prefix{}, false
	}
	return prefix.Masked(), true
}

// serverReservation returns the slice of the delegated prefix that must be kept
// out of tunnel allocations because the host itself answers for it. On-link
// delegation reserves nothing: the whole prefix is handed downstream and the
// host keeps its provider-assigned address on the upstream interface.
func serverReservation(up Upstream) (netip.Prefix, bool) {
	if upstreamMode(up) == UpstreamOnLink {
		return netip.Prefix{}, false
	}
	server, err := netip.ParsePrefix(up.ServerAddress)
	if err != nil {
		return netip.Prefix{}, false
	}
	upstream, ok := delegatedPrefix(up)
	if !ok || !upstream.Contains(server.Addr()) {
		return netip.Prefix{}, false
	}
	if server.Bits() < up.MaxPrefix {
		server = netip.PrefixFrom(server.Addr(), up.MaxPrefix)
	}
	return server.Masked(), true
}

// tunnelInterfaceAddress reports the address this host puts on an upstream's
// WireGuard interface: one inside the delegated prefix when the provider routes
// it, and one from the separate transport range when the whole prefix goes
// downstream instead.
func tunnelInterfaceAddress(up Upstream) string {
	if transport, ok := transportPrefix(up); ok && upstreamMode(up) == UpstreamOnLink {
		return transport.String()
	}
	return up.ServerAddress
}

type Tunnel struct {
	ID                                                                                            int64
	UpstreamID                                                                                    int64
	Label, PublicKey, PresharedKey, PrivateKey, V6CIDR, V4Address, DNSOverride, Status, LastError string
	V4Enabled, Enabled                                                                            bool
	V4Mode                                                                                        string
	QuotaGiB, QuotaUsedBytes                                                                      int64
	QuotaPeriod                                                                                   string
	QuotaDisabled                                                                                 bool
	RoutingGroups                                                                                 []string
	MTUOverride                                                                                   int
	CreatedAt, UpdatedAt                                                                          time.Time
	LastHandshake                                                                                 time.Time
	RXBytes, TXBytes                                                                              int64
}

type RoutingGroup struct {
	ID          int64
	Name        string
	TunnelCount int
	CreatedAt   time.Time
}

func (t Tunnel) HasRoutingGroup(name string) bool {
	for _, group := range t.RoutingGroups {
		if group == name {
			return true
		}
	}
	return false
}

type Health struct {
	Drift         []string
	LastReconcile time.Time
	Error         string
}

type WarpAccount struct {
	PrivateKey    string
	PeerPublicKey string
	IPv4Address   string
	Endpoint      string
	DeviceID      string
	AccountID     string
	AccountType   string
	CreatedAt     time.Time
	LastTrace     string
	LastTestAt    time.Time
}

func (w WarpAccount) Exists() bool {
	return w.PrivateKey != "" && w.PeerPublicKey != "" && w.IPv4Address != "" && w.Endpoint != ""
}

// upstreamsByID indexes upstreams so that a tunnel can be matched with the
// connection it was allocated from.
func upstreamsByID(upstreams []Upstream) map[int64]Upstream {
	byID := make(map[int64]Upstream, len(upstreams))
	for _, upstream := range upstreams {
		byID[upstream.ID] = upstream
	}
	return byID
}

// resolvedV4Mode reports a tunnel's effective IPv4 egress mode given an index of
// the known upstreams. A tunnel whose upstream is missing carries no traffic at
// all — its interface went away with the upstream — so it is reported as off
// rather than inheriting a global default it could never act on.
func resolvedV4Mode(cfg Settings, byID map[int64]Upstream, tunnel Tunnel) string {
	upstream, known := byID[tunnel.UpstreamID]
	if !known {
		return V4ModeOff
	}
	return tunnelV4Mode(cfg, upstream, tunnel)
}

// tunnelsByUpstream groups tunnels by the upstream that delegated their prefix.
// Tunnels whose upstream no longer exists are left out: their kernel state is
// removed with the upstream itself.
func tunnelsByUpstream(upstreams []Upstream, tunnels []Tunnel) map[int64][]Tunnel {
	grouped := make(map[int64][]Tunnel, len(upstreams))
	known := upstreamsByID(upstreams)
	for _, tunnel := range tunnels {
		if _, ok := known[tunnel.UpstreamID]; !ok {
			continue
		}
		grouped[tunnel.UpstreamID] = append(grouped[tunnel.UpstreamID], tunnel)
	}
	return grouped
}

func tunnelIPv4Enabled(cfg Settings, up Upstream, tunnel Tunnel) bool {
	return tunnelV4Mode(cfg, up, tunnel) != V4ModeOff && tunnel.V4Address != ""
}

func globalV4Mode(cfg Settings) string {
	if cfg.V4Warp {
		return V4ModeWarp
	}
	if cfg.V4NAT {
		return V4ModeNative
	}
	return V4ModeOff
}

// upstreamV4Mode reports the IPv4 egress mode an upstream's tunnels inherit,
// which is the global default unless the upstream overrides it. An upstream
// without IPv4 connectivity of its own can therefore switch all of its tunnels
// off without touching the rest of the deployment.
func upstreamV4Mode(cfg Settings, up Upstream) string {
	if up.V4Mode != V4ModeInherit {
		return up.V4Mode
	}
	return globalV4Mode(cfg)
}

// tunnelV4Mode resolves the three-level default: a tunnel overrides its
// upstream, which overrides the global setting.
func tunnelV4Mode(cfg Settings, up Upstream, tunnel Tunnel) string {
	if tunnel.V4Mode != V4ModeInherit {
		return tunnel.V4Mode
	}
	return upstreamV4Mode(cfg, up)
}

func validTunnelV4Mode(mode string) bool {
	return mode == V4ModeInherit || mode == V4ModeOff || mode == V4ModeNative || mode == V4ModeWarp
}

// tunnelAllowedIPs lists the sources a peer may send from, which are also the
// destinations routed to it. The delegated prefix always belongs to the peer.
// When the peer is numbered from the transport range, that single address is
// added too, because its own tunnel-interface traffic originates there.
func tunnelAllowedIPs(cfg Settings, up Upstream, tunnel Tunnel) []netip.Prefix {
	allowed := make([]netip.Prefix, 0, 3)
	if delegated, err := netip.ParsePrefix(tunnel.V6CIDR); err == nil {
		allowed = append(allowed, delegated.Masked())
	}
	if transport, ok := clientTransportAddress(up, tunnel); ok {
		allowed = append(allowed, netip.PrefixFrom(transport, 128))
	}
	if tunnelIPv4Enabled(cfg, up, tunnel) {
		if address, err := netip.ParseAddr(tunnel.V4Address); err == nil {
			allowed = append(allowed, netip.PrefixFrom(address, 32))
		}
	}
	return allowed
}

// clientTransportAddress derives this tunnel's address inside its upstream's
// WireGuard transport range. It is used when the tunnel cannot take an address
// from its own delegated prefix because that prefix goes to the client's LAN in
// full. The value is derived from the tunnel ID so that it is stable and needs
// no separate allocation or manual step.
func clientTransportAddress(up Upstream, tunnel Tunnel) (netip.Addr, bool) {
	transport, ok := transportPrefix(up)
	if !ok || upstreamMode(up) != UpstreamOnLink || tunnel.ID <= 0 {
		return netip.Addr{}, false
	}
	candidate := offsetAddr(transport.Masked().Addr(), uint64(tunnel.ID)+1)
	// The server holds one address in this range; step past it rather than
	// duplicating it.
	if candidate == transport.Addr() {
		candidate = offsetAddr(candidate, 1)
	}
	if !transport.Contains(candidate) {
		return netip.Addr{}, false
	}
	return candidate, true
}

func offsetAddr(base netip.Addr, offset uint64) netip.Addr {
	value := base.As16()
	carry := offset
	for i := 15; i >= 0 && carry > 0; i-- {
		sum := uint64(value[i]) + carry&0xff
		value[i] = byte(sum)
		carry = carry>>8 + sum>>8
	}
	return netip.AddrFrom16(value)
}
