package broker

import (
	"strings"
	"testing"
)

func routingTestUpstreams() []Upstream {
	return []Upstream{{ID: 1, Name: "primary", V6CIDR: "2001:db8::/32", InterfaceName: "wg0", EgressInterface: "eth0"}}
}

func routingTestTunnels() []Tunnel {
	return []Tunnel{
		{ID: 1, UpstreamID: 1, V6CIDR: "2001:db8:1::/64", V4Address: "10.99.0.1", V4Enabled: true, RoutingGroups: []string{"alpha", "beta"}, Enabled: true},
		{ID: 2, UpstreamID: 1, V6CIDR: "2001:db8:2::/64", V4Address: "10.99.0.2", V4Enabled: true, RoutingGroups: []string{"alpha"}, Enabled: true},
		{ID: 3, UpstreamID: 1, V6CIDR: "2001:db8:3::/64", V4Address: "10.99.0.3", V4Enabled: true, RoutingGroups: []string{"beta"}, Enabled: true},
		{ID: 4, UpstreamID: 1, V6CIDR: "2001:db8:4::/64", V4Address: "10.99.0.4", V4Enabled: true, Enabled: true},
	}
}

func TestInterTunnelRoutingIsIsolatedByDefault(t *testing.T) {
	rules, err := interTunnelRules(Settings{InterTunnelPolicy: InterTunnelIsolated}, routingTestUpstreams(), routingTestTunnels())
	if err != nil || rules != "" {
		t.Fatalf("isolated policy generated forwarding rules: %q, %v", rules, err)
	}
	rules, err = interTunnelRules(Settings{}, routingTestUpstreams(), routingTestTunnels())
	if err != nil || rules != "" {
		t.Fatalf("legacy empty policy was not isolated: %q, %v", rules, err)
	}
}

func TestAnyTunnelPolicyAllowsWireGuardHairpinForwarding(t *testing.T) {
	rules, err := interTunnelRules(Settings{InterTunnelPolicy: InterTunnelAny}, routingTestUpstreams(), routingTestTunnels())
	if err != nil || rules != "add rule inet open_tunnelbroker forward iifname \"wg0\" oifname \"wg0\" accept\n" {
		t.Fatalf("unexpected any-tunnel policy: %q, %v", rules, err)
	}
}

// Tunnels on unrelated providers must still be able to reach each other when the
// policy allows it, which needs a rule for every ordered interface pair.
func TestAnyTunnelPolicySpansUpstreams(t *testing.T) {
	upstreams := []Upstream{
		{ID: 1, Name: "primary", V6CIDR: "2001:db8::/32", InterfaceName: "wg0", EgressInterface: "eth0"},
		{ID: 2, Name: "secondary", V6CIDR: "2001:db9::/32", InterfaceName: "wg1", EgressInterface: "ppp0"},
	}
	rules, err := interTunnelRules(Settings{InterTunnelPolicy: InterTunnelAny}, upstreams, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		`iifname "wg0" oifname "wg1" accept`,
		`iifname "wg1" oifname "wg0" accept`,
		`iifname "wg0" oifname "wg0" accept`,
		`iifname "wg1" oifname "wg1" accept`,
	} {
		if !strings.Contains(rules, expected) {
			t.Fatalf("cross-upstream policy missing %q:\n%s", expected, rules)
		}
	}
}

func TestGroupPolicyMatchesBothSourceAndDestination(t *testing.T) {
	cfg := Settings{InterTunnelPolicy: InterTunnelGroups, V4NAT: true}
	rules, err := interTunnelRules(cfg, routingTestUpstreams(), routingTestTunnels())
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"2001:db8:1::/64, 2001:db8:2::/64",
		"10.99.0.1, 10.99.0.2",
		"ip6 saddr @tunnel_group_0_v6 ip6 daddr @tunnel_group_0_v6 accept",
		"ip saddr @tunnel_group_0_v4 ip daddr @tunnel_group_0_v4 accept",
		"2001:db8:1::/64, 2001:db8:3::/64",
		"ip6 saddr @tunnel_group_1_v6 ip6 daddr @tunnel_group_1_v6 accept",
	} {
		if !strings.Contains(rules, expected) {
			t.Fatalf("group policy missing %q:\n%s", expected, rules)
		}
	}
	for _, forbidden := range []string{"2001:db8:4::/64", "10.99.0.4", "ct state established"} {
		if strings.Contains(rules, forbidden) {
			t.Fatalf("group policy unexpectedly contains %q:\n%s", forbidden, rules)
		}
	}
}

// A managed group is a deployment-wide relationship, so two members allocated
// from different providers must be permitted to talk in both directions.
func TestGroupPolicySpansUpstreams(t *testing.T) {
	upstreams := []Upstream{
		{ID: 1, Name: "primary", V6CIDR: "2001:db8::/32", InterfaceName: "wg0", EgressInterface: "eth0"},
		{ID: 2, Name: "secondary", V6CIDR: "2001:db9::/32", InterfaceName: "wg1", EgressInterface: "ppp0"},
	}
	tunnels := []Tunnel{
		{ID: 1, UpstreamID: 1, V6CIDR: "2001:db8:1::/64", RoutingGroups: []string{"shared"}, Enabled: true},
		{ID: 2, UpstreamID: 2, V6CIDR: "2001:db9:1::/64", RoutingGroups: []string{"shared"}, Enabled: true},
	}
	rules, err := interTunnelRules(Settings{InterTunnelPolicy: InterTunnelGroups}, upstreams, tunnels)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rules, "2001:db8:1::/64, 2001:db9:1::/64") {
		t.Fatalf("group set does not span upstreams:\n%s", rules)
	}
	for _, expected := range []string{
		`iifname "wg0" oifname "wg1" ip6 saddr @tunnel_group_0_v6 ip6 daddr @tunnel_group_0_v6 accept`,
		`iifname "wg1" oifname "wg0" ip6 saddr @tunnel_group_0_v6 ip6 daddr @tunnel_group_0_v6 accept`,
	} {
		if !strings.Contains(rules, expected) {
			t.Fatalf("cross-upstream group rule missing %q:\n%s", expected, rules)
		}
	}
}

func TestGroupPolicyExcludesDisabledMembers(t *testing.T) {
	tunnels := routingTestTunnels()
	tunnels[1].Enabled = false
	tunnels[2].Enabled = false
	rules, err := interTunnelRules(Settings{InterTunnelPolicy: InterTunnelGroups, V4NAT: true}, routingTestUpstreams(), tunnels)
	if err != nil || rules != "" {
		t.Fatalf("single active group member received a rule: %q, %v", rules, err)
	}
}

func TestInterTunnelTrafficIsNeverMasqueraded(t *testing.T) {
	cfg := Settings{InterTunnelPolicy: InterTunnelAny, V4NAT: true}
	script, err := buildNFTScript(cfg, routingTestUpstreams(), routingTestTunnels())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(script, `oifname "wg0" masquerade`) {
		t.Fatalf("inter-tunnel traffic was NATed:\n%s", script)
	}
	if !strings.Contains(script, `iifname "wg0" oifname "wg0" accept`) || !strings.Contains(script, `oifname "eth0" masquerade`) {
		t.Fatalf("forwarding or upstream NAT rule missing:\n%s", script)
	}
}

// Each upstream forwards only between its own pair of interfaces, and each
// tunnel is masqueraded out of the provider that delegated its prefix.
func TestEachUpstreamGetsItsOwnForwardingAndNATPath(t *testing.T) {
	upstreams := []Upstream{
		{ID: 1, Name: "primary", V6CIDR: "2001:db8::/32", InterfaceName: "wg0", EgressInterface: "eth0"},
		{ID: 2, Name: "secondary", V6CIDR: "2001:db9::/32", InterfaceName: "wg1", EgressInterface: "ppp0"},
	}
	tunnels := []Tunnel{
		{ID: 1, UpstreamID: 1, V6CIDR: "2001:db8:1::/64", V4Address: "10.99.0.1", V4Enabled: true, Enabled: true},
		{ID: 2, UpstreamID: 2, V6CIDR: "2001:db9:1::/64", V4Address: "10.99.0.2", V4Enabled: true, Enabled: true},
	}
	script, err := buildNFTScript(Settings{V4NAT: true, InterTunnelPolicy: InterTunnelIsolated}, upstreams, tunnels)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		`forward iifname "wg0" oifname "eth0" accept`,
		`forward iifname "eth0" oifname "wg0" ct state established,related accept`,
		`forward iifname "wg1" oifname "ppp0" accept`,
		`forward iifname "ppp0" oifname "wg1" ct state established,related accept`,
		`ip saddr 10.99.0.1/32 oifname "eth0" masquerade`,
		`ip saddr 10.99.0.2/32 oifname "ppp0" masquerade`,
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("multi-upstream script missing %q:\n%s", expected, script)
		}
	}
	// Isolation must still hold: no interface may forward into another
	// upstream's WireGuard device.
	for _, forbidden := range []string{`iifname "wg0" oifname "wg1"`, `iifname "wg0" oifname "ppp0"`, `iifname "wg1" oifname "eth0"`} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("upstreams were cross-connected with %q:\n%s", forbidden, script)
		}
	}
}

// An upstream that overrides its IPv4 mode governs the tunnels it delegated,
// without disturbing the other providers.
func TestUpstreamIPv4ModeSelectsTheEgressPath(t *testing.T) {
	upstreams := []Upstream{
		{ID: 1, Name: "native", V6CIDR: "2001:db8::/32", InterfaceName: "wg0", EgressInterface: "eth0", V4Mode: V4ModeNative},
		{ID: 2, Name: "no-ipv4", V6CIDR: "2001:db9::/32", InterfaceName: "wg1", EgressInterface: "ppp0", V4Mode: V4ModeOff},
		{ID: 3, Name: "warped", V6CIDR: "2001:dba::/32", InterfaceName: "wg2", EgressInterface: "eth1", V4Mode: V4ModeWarp},
	}
	tunnels := []Tunnel{
		{ID: 1, UpstreamID: 1, V6CIDR: "2001:db8:1::/64", V4Address: "10.99.0.1", Enabled: true},
		{ID: 2, UpstreamID: 2, V6CIDR: "2001:db9:1::/64", V4Address: "10.99.0.2", Enabled: true},
		{ID: 3, UpstreamID: 3, V6CIDR: "2001:dba:1::/64", V4Address: "10.99.0.3", Enabled: true},
	}
	script, err := buildNFTScript(Settings{InterTunnelPolicy: InterTunnelIsolated}, upstreams, tunnels)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, `ip saddr 10.99.0.1/32 oifname "eth0" masquerade`) {
		t.Fatalf("native upstream lost its NAT rule:\n%s", script)
	}
	if strings.Contains(script, "10.99.0.2") {
		t.Fatalf("an upstream with IPv4 disabled still produced a NAT rule:\n%s", script)
	}
	if !strings.Contains(script, `ip saddr 10.99.0.3/32 oifname "wg-warp" masquerade`) {
		t.Fatalf("WARP upstream did not egress through WARP:\n%s", script)
	}
	// Only the WARP-carrying interface is bridged to wg-warp.
	if !strings.Contains(script, `iifname "wg2" oifname "wg-warp" accept`) || strings.Contains(script, `iifname "wg0" oifname "wg-warp"`) {
		t.Fatalf("WARP forwarding pairs are wrong:\n%s", script)
	}
}

// A tunnel whose upstream is gone has no interface to carry its traffic, so it
// must not produce a NAT rule, a forwarding rule, or a group membership. Its
// effective IPv4 mode is off rather than the global default it can never use.
func TestTunnelWithoutAnUpstreamIsInert(t *testing.T) {
	cfg := Settings{V4NAT: true, InterTunnelPolicy: InterTunnelGroups}
	upstreams := routingTestUpstreams()
	tunnels := []Tunnel{
		{ID: 1, UpstreamID: 1, V6CIDR: "2001:db8:1::/64", V4Address: "10.99.0.1", RoutingGroups: []string{"shared"}, Enabled: true},
		{ID: 2, UpstreamID: 1, V6CIDR: "2001:db8:2::/64", V4Address: "10.99.0.2", RoutingGroups: []string{"shared"}, Enabled: true},
		{ID: 3, UpstreamID: 404, V6CIDR: "2001:dead::/64", V4Address: "10.99.0.9", V4Mode: V4ModeWarp, RoutingGroups: []string{"shared"}, Enabled: true},
	}
	orphan := tunnels[2]
	if mode := resolvedV4Mode(cfg, upstreamsByID(upstreams), orphan); mode != V4ModeOff {
		t.Fatalf("an orphaned tunnel resolved to %q instead of off", mode)
	}
	script, err := buildNFTScript(cfg, upstreams, tunnels)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"10.99.0.9", "2001:dead::/64", warpInterfaceName} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("an orphaned tunnel reached the ruleset via %q:\n%s", forbidden, script)
		}
	}
	// The healthy members of the same group are unaffected.
	if !strings.Contains(script, "2001:db8:1::/64, 2001:db8:2::/64") {
		t.Fatalf("the orphan removed its group's healthy members:\n%s", script)
	}
}

func TestInvalidInterTunnelPolicyIsRejected(t *testing.T) {
	if _, err := interTunnelRules(Settings{InterTunnelPolicy: "invalid"}, routingTestUpstreams(), nil); err == nil {
		t.Fatal("invalid policy was accepted")
	}
}
