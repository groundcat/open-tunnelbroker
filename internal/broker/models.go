package broker

import "time"

const warpInterfaceName = "wg-warp"

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
}

type Tunnel struct {
	ID                                                                                            int64
	InterfaceID                                                                                   int64
	Label, PublicKey, PresharedKey, PrivateKey, V6CIDR, V4Address, DNSOverride, Status, LastError string
	V4Enabled, Enabled                                                                            bool
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
	return (cfg.V4NAT || cfg.V4Warp) && tunnel.V4Address != ""
}
