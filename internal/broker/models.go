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

// Upstream delegation modes describe how the provider hands the IPv6 prefix to
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

// upstreamMode reports the configured delegation mode, defaulting to routed so
// that databases predating this setting keep their existing behavior.
func upstreamMode(cfg Settings) string {
	if validUpstreamMode(cfg.UpstreamMode) {
		return cfg.UpstreamMode
	}
	return UpstreamRouted
}

// transportPrefix returns the WireGuard transport address when it is configured
// outside the delegated prefix. In on-link mode the entire delegated prefix
// belongs to downstream tunnels, so the tunnel interface itself is numbered
// from a separate ULA or documentation range instead.
func transportPrefix(cfg Settings) (netip.Prefix, bool) {
	prefix, err := netip.ParsePrefix(cfg.TransportAddress)
	if err != nil || !prefix.Addr().Is6() {
		return netip.Prefix{}, false
	}
	return prefix, true
}

// serverReservation returns the slice of the delegated prefix that must be kept
// out of tunnel allocations because the host itself answers for it. On-link
// delegation reserves nothing: the whole prefix is handed downstream and the
// host keeps its provider-assigned address on the upstream interface.
func serverReservation(cfg Settings) (netip.Prefix, bool) {
	if upstreamMode(cfg) == UpstreamOnLink {
		return netip.Prefix{}, false
	}
	server, err := netip.ParsePrefix(cfg.ServerAddress)
	if err != nil {
		return netip.Prefix{}, false
	}
	upstream, err := netip.ParsePrefix(cfg.UpstreamV6)
	if err != nil || !upstream.Contains(server.Addr()) {
		return netip.Prefix{}, false
	}
	if server.Bits() < cfg.MaxPrefix {
		server = netip.PrefixFrom(server.Addr(), cfg.MaxPrefix)
	}
	return server.Masked(), true
}

type Settings struct {
	UpstreamV6        string
	UpstreamV4        string
	V4NAT             bool
	V4Warp            bool
	V4Pool            string
	DefaultDNS        string
	EndpointHost      string
	EndpointPort      int
	InterfaceName     string
	ServerAddress     string
	ServerPrivateKey  string
	MTU               int
	Keepalive         int
	MinPrefix         int
	MaxPrefix         int
	DefaultPrefix     int
	UpstreamInterface string
	InterTunnelPolicy string
	UpstreamMode      string
	TransportAddress  string
}

type Tunnel struct {
	ID                                                                                            int64
	InterfaceID                                                                                   int64
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

func tunnelIPv4Enabled(cfg Settings, tunnel Tunnel) bool {
	return tunnelV4Mode(cfg, tunnel) != V4ModeOff && tunnel.V4Address != ""
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

func tunnelV4Mode(cfg Settings, tunnel Tunnel) string {
	if tunnel.V4Mode != V4ModeInherit {
		return tunnel.V4Mode
	}
	return globalV4Mode(cfg)
}

func validTunnelV4Mode(mode string) bool {
	return mode == V4ModeInherit || mode == V4ModeOff || mode == V4ModeNative || mode == V4ModeWarp
}

// tunnelAllowedIPs lists the sources a peer may send from, which are also the
// destinations routed to it. The delegated prefix always belongs to the peer.
// When the peer is numbered from the transport range, that single address is
// added too, because its own tunnel-interface traffic originates there.
func tunnelAllowedIPs(cfg Settings, tunnel Tunnel) []netip.Prefix {
	allowed := make([]netip.Prefix, 0, 3)
	if delegated, err := netip.ParsePrefix(tunnel.V6CIDR); err == nil {
		allowed = append(allowed, delegated.Masked())
	}
	if transport, ok := clientTransportAddress(cfg, tunnel); ok {
		allowed = append(allowed, netip.PrefixFrom(transport, 128))
	}
	if tunnelIPv4Enabled(cfg, tunnel) {
		if address, err := netip.ParseAddr(tunnel.V4Address); err == nil {
			allowed = append(allowed, netip.PrefixFrom(address, 32))
		}
	}
	return allowed
}
