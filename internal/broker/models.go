package broker

import "time"

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
	RoutingGroup                                                                                  string
	MTUOverride                                                                                   int
	CreatedAt, UpdatedAt                                                                          time.Time
	LastHandshake                                                                                 time.Time
	RXBytes, TXBytes                                                                              int64
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
