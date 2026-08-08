package broker

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

func buildNFTScript(cfg Settings, tunnels []Tunnel) (string, error) {
	if cfg.UpstreamInterface == "" {
		return "", errors.New("upstream interface is required")
	}
	script := fmt.Sprintf("delete table inet open_tunnelbroker\nadd table inet open_tunnelbroker\nadd chain inet open_tunnelbroker forward { type filter hook forward priority 0; policy drop; }\nadd rule inet open_tunnelbroker forward iifname %q oifname %q accept\nadd rule inet open_tunnelbroker forward iifname %q oifname %q ct state established,related accept\n", cfg.InterfaceName, cfg.UpstreamInterface, cfg.UpstreamInterface, cfg.InterfaceName)

	interTunnel, err := interTunnelRules(cfg, tunnels)
	if err != nil {
		return "", err
	}
	script += interTunnel

	warpEnabled := false
	for _, tunnel := range tunnels {
		warpEnabled = warpEnabled || tunnelV4Mode(cfg, tunnel) == V4ModeWarp
	}
	if warpEnabled {
		script += fmt.Sprintf("add rule inet open_tunnelbroker forward iifname %q oifname %q accept\nadd rule inet open_tunnelbroker forward iifname %q oifname %q ct state established,related accept\n", cfg.InterfaceName, warpInterfaceName, warpInterfaceName, cfg.InterfaceName)
	}
	var natRules string
	for _, tunnel := range tunnels {
		if !tunnelIPv4Enabled(cfg, tunnel) {
			continue
		}
		egress := cfg.UpstreamInterface
		if tunnelV4Mode(cfg, tunnel) == V4ModeWarp {
			egress = warpInterfaceName
		}
		natRules += fmt.Sprintf("add rule inet open_tunnelbroker postrouting ip saddr %s/32 oifname %q masquerade\n", tunnel.V4Address, egress)
	}
	if natRules != "" {
		script += "add chain inet open_tunnelbroker postrouting { type nat hook postrouting priority 100; policy accept; }\n" + natRules
	}
	return script, nil
}

func interTunnelRules(cfg Settings, tunnels []Tunnel) (string, error) {
	switch cfg.InterTunnelPolicy {
	case "", InterTunnelIsolated:
		return "", nil
	case InterTunnelAny:
		return fmt.Sprintf("add rule inet open_tunnelbroker forward iifname %q oifname %q accept\n", cfg.InterfaceName, cfg.InterfaceName), nil
	case InterTunnelGroups:
		return routingGroupRules(cfg, tunnels)
	default:
		return "", errors.New("invalid inter-tunnel routing policy")
	}
}

func routingGroupRules(cfg Settings, tunnels []Tunnel) (string, error) {
	groups := make(map[string][]Tunnel)
	for _, tunnel := range tunnels {
		if tunnel.Enabled && tunnel.RoutingGroup != "" {
			groups[tunnel.RoutingGroup] = append(groups[tunnel.RoutingGroup], tunnel)
		}
	}
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)

	var script strings.Builder
	for index, name := range names {
		members := groups[name]
		if len(members) < 2 {
			continue
		}
		v6Elements := make([]string, 0, len(members))
		v4Elements := make([]string, 0, len(members))
		for _, tunnel := range members {
			prefix, err := netip.ParsePrefix(tunnel.V6CIDR)
			if err != nil || !prefix.Addr().Is6() {
				return "", fmt.Errorf("tunnel %d has invalid IPv6 allocation", tunnel.ID)
			}
			v6Elements = append(v6Elements, prefix.Masked().String())
			if tunnelIPv4Enabled(cfg, tunnel) {
				address, addressErr := netip.ParseAddr(tunnel.V4Address)
				if addressErr != nil || !address.Is4() {
					return "", fmt.Errorf("tunnel %d has invalid IPv4 allocation", tunnel.ID)
				}
				v4Elements = append(v4Elements, address.String())
			}
		}

		v6Set := fmt.Sprintf("tunnel_group_%d_v6", index)
		fmt.Fprintf(&script, "add set inet open_tunnelbroker %s { type ipv6_addr; flags interval; }\n", v6Set)
		fmt.Fprintf(&script, "add element inet open_tunnelbroker %s { %s }\n", v6Set, strings.Join(v6Elements, ", "))
		fmt.Fprintf(&script, "add rule inet open_tunnelbroker forward iifname %q oifname %q ip6 saddr @%s ip6 daddr @%s accept\n", cfg.InterfaceName, cfg.InterfaceName, v6Set, v6Set)
		if len(v4Elements) >= 2 {
			v4Set := fmt.Sprintf("tunnel_group_%d_v4", index)
			fmt.Fprintf(&script, "add set inet open_tunnelbroker %s { type ipv4_addr; }\n", v4Set)
			fmt.Fprintf(&script, "add element inet open_tunnelbroker %s { %s }\n", v4Set, strings.Join(v4Elements, ", "))
			fmt.Fprintf(&script, "add rule inet open_tunnelbroker forward iifname %q oifname %q ip saddr @%s ip daddr @%s accept\n", cfg.InterfaceName, cfg.InterfaceName, v4Set, v4Set)
		}
	}
	return script.String(), nil
}
