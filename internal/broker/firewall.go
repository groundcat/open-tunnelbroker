package broker

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// buildNFTScript renders the application's entire nftables table. Every upstream
// contributes its own forwarding pair, so a tunnel may reach the Internet only
// through the provider that delegated its prefix.
func buildNFTScript(cfg Settings, upstreams []Upstream, tunnels []Tunnel) (string, error) {
	if len(upstreams) == 0 {
		return "delete table inet open_tunnelbroker\nadd table inet open_tunnelbroker\n", nil
	}
	for _, upstream := range upstreams {
		if upstream.EgressInterface == "" {
			return "", fmt.Errorf("upstream %q has no egress interface", upstream.Name)
		}
		if upstream.InterfaceName == "" {
			return "", fmt.Errorf("upstream %q has no WireGuard interface", upstream.Name)
		}
	}
	var script strings.Builder
	script.WriteString("delete table inet open_tunnelbroker\nadd table inet open_tunnelbroker\nadd chain inet open_tunnelbroker forward { type filter hook forward priority 0; policy drop; }\n")
	for _, upstream := range upstreams {
		fmt.Fprintf(&script, "add rule inet open_tunnelbroker forward iifname %q oifname %q accept\nadd rule inet open_tunnelbroker forward iifname %q oifname %q ct state established,related accept\n", upstream.InterfaceName, upstream.EgressInterface, upstream.EgressInterface, upstream.InterfaceName)
	}

	interTunnel, err := interTunnelRules(cfg, upstreams, tunnels)
	if err != nil {
		return "", err
	}
	script.WriteString(interTunnel)

	byID := upstreamsByID(upstreams)
	warpEnabled := false
	for _, tunnel := range tunnels {
		warpEnabled = warpEnabled || resolvedV4Mode(cfg, byID, tunnel) == V4ModeWarp
	}
	if warpEnabled {
		for _, name := range warpTunnelInterfaces(cfg, upstreams, tunnels) {
			fmt.Fprintf(&script, "add rule inet open_tunnelbroker forward iifname %q oifname %q accept\nadd rule inet open_tunnelbroker forward iifname %q oifname %q ct state established,related accept\n", name, warpInterfaceName, warpInterfaceName, name)
		}
	}
	var natRules strings.Builder
	for _, tunnel := range tunnels {
		upstream, ok := byID[tunnel.UpstreamID]
		if !ok || !tunnelIPv4Enabled(cfg, upstream, tunnel) {
			continue
		}
		egress := upstream.EgressInterface
		if tunnelV4Mode(cfg, upstream, tunnel) == V4ModeWarp {
			egress = warpInterfaceName
		}
		fmt.Fprintf(&natRules, "add rule inet open_tunnelbroker postrouting ip saddr %s/32 oifname %q masquerade\n", tunnel.V4Address, egress)
	}
	if natRules.Len() > 0 {
		script.WriteString("add chain inet open_tunnelbroker postrouting { type nat hook postrouting priority 100; policy accept; }\n")
		script.WriteString(natRules.String())
	}
	return script.String(), nil
}

// warpTunnelInterfaces lists the WireGuard interfaces holding at least one
// WARP-routed tunnel, so only those gain a forwarding pair to wg-warp.
func warpTunnelInterfaces(cfg Settings, upstreams []Upstream, tunnels []Tunnel) []string {
	byID := upstreamsByID(upstreams)
	seen := make(map[string]bool)
	for _, tunnel := range tunnels {
		upstream, ok := byID[tunnel.UpstreamID]
		if ok && tunnelV4Mode(cfg, upstream, tunnel) == V4ModeWarp {
			seen[upstream.InterfaceName] = true
		}
	}
	return sortedKeys(seen)
}

func sortedKeys(set map[string]bool) []string {
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// interTunnelRules renders the policy governing tunnel-to-tunnel traffic. The
// policy spans upstreams: two tunnels may be reachable to each other even when
// their prefixes come from unrelated providers, because the rules match on the
// addresses rather than on which interface delivered them. Traffic leaving one
// WireGuard interface for another is never masqueraded, so the original source
// address is preserved in both directions.
func interTunnelRules(cfg Settings, upstreams []Upstream, tunnels []Tunnel) (string, error) {
	switch cfg.InterTunnelPolicy {
	case "", InterTunnelIsolated:
		return "", nil
	case InterTunnelAny:
		var script strings.Builder
		for _, ingress := range tunnelInterfaces(upstreams) {
			for _, egress := range tunnelInterfaces(upstreams) {
				fmt.Fprintf(&script, "add rule inet open_tunnelbroker forward iifname %q oifname %q accept\n", ingress, egress)
			}
		}
		return script.String(), nil
	case InterTunnelGroups:
		return routingGroupRules(cfg, upstreams, tunnels)
	default:
		return "", errors.New("invalid inter-tunnel routing policy")
	}
}

// tunnelInterfaces lists every WireGuard interface this application manages,
// deduplicated and ordered so that generated rules are stable.
func tunnelInterfaces(upstreams []Upstream) []string {
	seen := make(map[string]bool, len(upstreams))
	for _, upstream := range upstreams {
		if upstream.InterfaceName != "" {
			seen[upstream.InterfaceName] = true
		}
	}
	return sortedKeys(seen)
}

func routingGroupRules(cfg Settings, upstreams []Upstream, tunnels []Tunnel) (string, error) {
	byID := upstreamsByID(upstreams)
	groups := make(map[string][]Tunnel)
	for _, tunnel := range tunnels {
		if !tunnel.Enabled {
			continue
		}
		if _, ok := byID[tunnel.UpstreamID]; !ok {
			continue
		}
		for _, group := range tunnel.RoutingGroups {
			groups[group] = append(groups[group], tunnel)
		}
	}
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)

	interfaces := tunnelInterfaces(upstreams)
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
			if tunnelIPv4Enabled(cfg, byID[tunnel.UpstreamID], tunnel) {
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
		v4Set := ""
		if len(v4Elements) >= 2 {
			v4Set = fmt.Sprintf("tunnel_group_%d_v4", index)
			fmt.Fprintf(&script, "add set inet open_tunnelbroker %s { type ipv4_addr; }\n", v4Set)
			fmt.Fprintf(&script, "add element inet open_tunnelbroker %s { %s }\n", v4Set, strings.Join(v4Elements, ", "))
		}
		// A group can span upstreams, so every interface pair is permitted for
		// the group's own addresses. Set membership on both source and
		// destination is what actually authorizes the traffic.
		for _, ingress := range interfaces {
			for _, egress := range interfaces {
				fmt.Fprintf(&script, "add rule inet open_tunnelbroker forward iifname %q oifname %q ip6 saddr @%s ip6 daddr @%s accept\n", ingress, egress, v6Set, v6Set)
				if v4Set != "" {
					fmt.Fprintf(&script, "add rule inet open_tunnelbroker forward iifname %q oifname %q ip saddr @%s ip daddr @%s accept\n", ingress, egress, v4Set, v4Set)
				}
			}
		}
	}
	return script.String(), nil
}
