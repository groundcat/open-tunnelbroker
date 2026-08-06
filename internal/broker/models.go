package broker

import "time"

type Settings struct {
	UpstreamV6        string
	UpstreamV4        string
	V4NAT             bool
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
