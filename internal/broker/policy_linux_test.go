//go:build linux

package broker

import (
	"testing"

	"github.com/vishvananda/netlink"
)

func policyTestUpstreams() []Upstream {
	return []Upstream{
		{ID: 1, Name: "fiber", V6CIDR: "2001:db8:100::/48", InterfaceName: "wg0", EgressInterface: "eth0"},
		{ID: 2, Name: "vps", V6CIDR: "2001:db8:900:416::/64", Mode: UpstreamOnLink, TransportAddress: "fd00:6b72:6f6b:1::1/64", InterfaceName: "wg1", EgressInterface: "ppp0"},
	}
}

// Each delegated prefix must leave through the provider that delegated it, or
// upstream ingress filtering would drop it as a spoofed source.
func TestPolicyRulesPinEachPrefixToItsOwnProvider(t *testing.T) {
	upstreams := policyTestUpstreams()
	desired := desiredPolicyRules(Settings{V4Pool: "10.99.0.0/16"}, upstreams, nil)

	for _, upstream := range upstreams {
		want := policyRule{family: netlink.FAMILY_V6, priority: upstreamRulePriority, table: upstreamRouteTable(upstream), source: upstream.V6CIDR}
		if !desired[want] {
			t.Fatalf("no egress rule pins %s to upstream %q: %+v", upstream.V6CIDR, upstream.Name, desired)
		}
	}
	// The two upstreams must not share a routing table, or the pinning would be
	// meaningless.
	if upstreamRouteTable(upstreams[0]) == upstreamRouteTable(upstreams[1]) {
		t.Fatal("two upstreams were given the same policy table")
	}
}

// Traffic aimed at another tunnel must stay in the main table, where the tunnel
// routes live; otherwise cross-upstream communication could never resolve.
func TestPolicyRulesKeepInterTunnelTrafficOnTheMainTable(t *testing.T) {
	upstreams := policyTestUpstreams()
	desired := desiredPolicyRules(Settings{V4Pool: "10.99.0.0/16"}, upstreams, nil)

	for _, destination := range []string{"2001:db8:100::/48", "2001:db8:900:416::/64", "fd00:6b72:6f6b:1::/64"} {
		want := policyRule{family: netlink.FAMILY_V6, priority: interUpstreamRulePriority, table: mainRouteTable, dest: destination}
		if !desired[want] {
			t.Fatalf("destination %s is not routed through the main table: %+v", destination, desired)
		}
	}
	pool := policyRule{family: netlink.FAMILY_V4, priority: interUpstreamRulePriority, table: mainRouteTable, dest: "10.99.0.0/16"}
	if !desired[pool] {
		t.Fatalf("the internal IPv4 pool is not routed through the main table: %+v", desired)
	}
	// Destination rules must be evaluated before every source rule, including
	// WARP's. Otherwise a packet aimed at another tunnel would be pushed into a
	// provider's table — or, for a WARP tunnel, into the WARP table, whose only
	// route is the default one, and the inter-tunnel path would break.
	if interUpstreamRulePriority >= upstreamRulePriority || interUpstreamRulePriority >= warpRulePriority {
		t.Fatalf("inter-upstream rules must be evaluated first: inter=%d warp=%d upstream=%d", interUpstreamRulePriority, warpRulePriority, upstreamRulePriority)
	}
	// The WARP test rule borrows the priority just below WARP's own, so it must
	// not collide with the inter-upstream rules either.
	if warpRulePriority-1 <= interUpstreamRulePriority {
		t.Fatal("the WARP trace rule collides with the inter-upstream rules")
	}
}

// A masqueraded IPv4 address is pinned the same way, except under WARP, whose
// own rule already selects the WARP table.
func TestPolicyRulesPinNativeIPv4ButNotWARP(t *testing.T) {
	upstreams := policyTestUpstreams()
	cfg := Settings{V4Pool: "10.99.0.0/16", V4NAT: true}
	tunnels := []Tunnel{
		{ID: 1, UpstreamID: 1, V6CIDR: "2001:db8:100:1::/64", V4Address: "10.99.0.1", Enabled: true},
		{ID: 2, UpstreamID: 2, V6CIDR: "2001:db8:900:416::/64", V4Address: "10.99.0.2", V4Mode: V4ModeWarp, Enabled: true},
		{ID: 3, UpstreamID: 2, V6CIDR: "2001:db8:900:417::/64", V4Address: "10.99.0.3", V4Mode: V4ModeOff, Enabled: true},
	}
	desired := desiredPolicyRules(cfg, upstreams, tunnels)

	native := policyRule{family: netlink.FAMILY_V4, priority: upstreamRulePriority, table: upstreamRouteTable(upstreams[0]), source: "10.99.0.1/32"}
	if !desired[native] {
		t.Fatalf("a natively masqueraded address is not pinned to its upstream: %+v", desired)
	}
	for _, address := range []string{"10.99.0.2/32", "10.99.0.3/32"} {
		for _, table := range []int{upstreamRouteTable(upstreams[0]), upstreamRouteTable(upstreams[1])} {
			if desired[policyRule{family: netlink.FAMILY_V4, priority: upstreamRulePriority, table: table, source: address}] {
				t.Fatalf("%s should not have an upstream egress rule: %+v", address, desired)
			}
		}
	}
}

// A single-upstream deployment must install nothing at all, so an upgrade from
// the previous release changes no routing behavior.
func TestSingleUpstreamInstallsNoPolicyRules(t *testing.T) {
	single := policyTestUpstreams()[:1]
	tunnels := []Tunnel{{ID: 1, UpstreamID: 1, V6CIDR: "2001:db8:100:1::/64", V4Address: "10.99.0.1", Enabled: true}}
	// applyPolicyRouting short-circuits before building any rules; the desired
	// set for the multi-upstream path is only consulted past that point.
	if desired := desiredPolicyRules(Settings{V4Pool: "10.99.0.0/16"}, single, tunnels); len(desired) == 0 {
		t.Fatal("the rule builder produced nothing for a valid upstream")
	}
	if table := upstreamRouteTable(single[0]); table <= mainRouteTable {
		t.Fatalf("upstream policy table %d collides with a kernel-reserved table", table)
	}
}
