package broker

import (
	"strings"
	"testing"
)

func routingTestTunnels() []Tunnel {
	return []Tunnel{
		{ID: 1, V6CIDR: "2001:db8:1::/64", V4Address: "10.99.0.1", V4Enabled: true, RoutingGroup: "alpha", Enabled: true},
		{ID: 2, V6CIDR: "2001:db8:2::/64", V4Address: "10.99.0.2", V4Enabled: true, RoutingGroup: "alpha", Enabled: true},
		{ID: 3, V6CIDR: "2001:db8:3::/64", V4Address: "10.99.0.3", V4Enabled: true, RoutingGroup: "beta", Enabled: true},
		{ID: 4, V6CIDR: "2001:db8:4::/64", V4Address: "10.99.0.4", V4Enabled: true, Enabled: true},
	}
}

func TestInterTunnelRoutingIsIsolatedByDefault(t *testing.T) {
	rules, err := interTunnelRules(Settings{InterfaceName: "wg0", InterTunnelPolicy: InterTunnelIsolated}, routingTestTunnels())
	if err != nil || rules != "" {
		t.Fatalf("isolated policy generated forwarding rules: %q, %v", rules, err)
	}
	rules, err = interTunnelRules(Settings{InterfaceName: "wg0"}, routingTestTunnels())
	if err != nil || rules != "" {
		t.Fatalf("legacy empty policy was not isolated: %q, %v", rules, err)
	}
}

func TestAnyTunnelPolicyAllowsWireGuardHairpinForwarding(t *testing.T) {
	rules, err := interTunnelRules(Settings{InterfaceName: "wg0", InterTunnelPolicy: InterTunnelAny}, routingTestTunnels())
	if err != nil || rules != "add rule inet open_tunnelbroker forward iifname \"wg0\" oifname \"wg0\" accept\n" {
		t.Fatalf("unexpected any-tunnel policy: %q, %v", rules, err)
	}
}

func TestGroupPolicyMatchesBothSourceAndDestination(t *testing.T) {
	cfg := Settings{InterfaceName: "wg0", InterTunnelPolicy: InterTunnelGroups, V4NAT: true}
	rules, err := interTunnelRules(cfg, routingTestTunnels())
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"2001:db8:1::/64, 2001:db8:2::/64",
		"10.99.0.1, 10.99.0.2",
		"ip6 saddr @tunnel_group_0_v6 ip6 daddr @tunnel_group_0_v6 accept",
		"ip saddr @tunnel_group_0_v4 ip daddr @tunnel_group_0_v4 accept",
	} {
		if !strings.Contains(rules, expected) {
			t.Fatalf("group policy missing %q:\n%s", expected, rules)
		}
	}
	for _, forbidden := range []string{"2001:db8:3::/64", "2001:db8:4::/64", "10.99.0.3", "ct state established"} {
		if strings.Contains(rules, forbidden) {
			t.Fatalf("group policy unexpectedly contains %q:\n%s", forbidden, rules)
		}
	}
}

func TestGroupPolicyExcludesDisabledMembers(t *testing.T) {
	tunnels := routingTestTunnels()
	tunnels[1].Enabled = false
	rules, err := interTunnelRules(Settings{InterfaceName: "wg0", InterTunnelPolicy: InterTunnelGroups, V4NAT: true}, tunnels)
	if err != nil || rules != "" {
		t.Fatalf("single active group member received a rule: %q, %v", rules, err)
	}
}

func TestInterTunnelTrafficIsNeverMasqueraded(t *testing.T) {
	cfg := Settings{InterfaceName: "wg0", UpstreamInterface: "eth0", InterTunnelPolicy: InterTunnelAny, V4NAT: true}
	script, err := buildNFTScript(cfg, routingTestTunnels())
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

func TestInvalidInterTunnelPolicyIsRejected(t *testing.T) {
	if _, err := interTunnelRules(Settings{InterfaceName: "wg0", InterTunnelPolicy: "invalid"}, nil); err == nil {
		t.Fatal("invalid policy was accepted")
	}
}
