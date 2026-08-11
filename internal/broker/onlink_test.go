package broker

import (
	"io"
	"log"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// onLinkUpstream models the single-/64 VPS case: the provider assigns one /64
// that it treats as directly attached to the server's Ethernet interface.
func onLinkUpstream() UpstreamInput {
	return UpstreamInput{Name: "vps", V6CIDR: "2001:db8:1200:416::/64", Mode: UpstreamOnLink, EndpointHost: "vps.example.test", EndpointPort: 51820, InterfaceName: "wg-test", MTU: 1420, Keepalive: 25, EgressInterface: "eth0"}
}

func onLinkApp(t *testing.T) (*App, *fakeKernel, Upstream) {
	t.Helper()
	app, err := New(filepath.Join(t.TempDir(), "broker.db"), true, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.Close() })
	kernel := &fakeKernel{}
	app.kernel = kernel
	if err = app.SaveSettings(Settings{V4Pool: "10.99.0.0/16", DefaultDNS: "2606:4700:4700::1111"}); err != nil {
		t.Fatal(err)
	}
	upstream, err := app.CreateUpstream(onLinkUpstream(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	return app, kernel, upstream
}

func TestSingleSlash64NeedsNoManualPrefixConfiguration(t *testing.T) {
	_, _, upstream := onLinkApp(t)

	// A /64 cannot be subdivided for SLAAC, so the only offered allocation size
	// is the whole prefix, with no admin arithmetic required.
	if upstream.MinPrefix != 64 || upstream.MaxPrefix != 64 || upstream.DefaultPrefix != 64 {
		t.Fatalf("prefix limits were not normalized to the single /64: %+v", upstream)
	}
	// A transport address outside the prefix is filled in automatically, because
	// the prefix itself has no room for an infrastructure address.
	transport, ok := transportPrefix(upstream)
	if !ok {
		t.Fatalf("no WireGuard transport address was configured: %+v", upstream)
	}
	delegated := netip.MustParsePrefix(upstream.V6CIDR)
	if delegated.Contains(transport.Addr()) {
		t.Fatalf("transport address %s must not consume delegated space", transport)
	}
	if upstream.ServerAddress != "" {
		t.Fatalf("on-link delegation must reserve no address inside the prefix: %q", upstream.ServerAddress)
	}
}

func TestEntireSlash64IsDelegatedToOneTunnel(t *testing.T) {
	app, kernel, upstream := onLinkApp(t)
	tunnel, err := app.CreateTunnel(CreateTunnelInput{UpstreamID: upstream.ID, Label: "home", GenerateKeys: true}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	cfg := mustSettings(t, app)
	// The whole upstream /64 goes to the tunnel: no split, no reserved subnet.
	if tunnel.V6CIDR != upstream.V6CIDR {
		t.Fatalf("tunnel received %s instead of the entire upstream %s", tunnel.V6CIDR, upstream.V6CIDR)
	}
	if tunnel.Status != "applied" || len(kernel.applied) != 1 {
		t.Fatalf("tunnel was not applied: %+v", tunnel)
	}

	// AllowedIPs must carry the delegated /64 plus the peer's transport address,
	// otherwise its own tunnel-sourced packets would be dropped.
	allowed := tunnelAllowedIPs(cfg, upstream, tunnel)
	client, ok := clientTransportAddress(upstream, tunnel)
	if !ok {
		t.Fatal("no client transport address was derived")
	}
	want := map[string]bool{upstream.V6CIDR: false, netip.PrefixFrom(client, 128).String(): false}
	for _, prefix := range allowed {
		if _, expected := want[prefix.String()]; !expected {
			t.Fatalf("unexpected AllowedIP %s", prefix)
		}
		want[prefix.String()] = true
	}
	for prefix, found := range want {
		if !found {
			t.Fatalf("AllowedIPs is missing %s", prefix)
		}
	}

	// The pool is now full, which is correct: one /64 delegates exactly once.
	if _, err = app.CreateTunnel(CreateTunnelInput{UpstreamID: upstream.ID, Label: "second", GenerateKeys: true}, "admin"); err == nil {
		t.Fatal("a second tunnel was allocated from an exhausted single /64")
	}
}

func TestOnLinkClientConfigKeepsTheWholePrefixFreeForSLAAC(t *testing.T) {
	app, _, upstream := onLinkApp(t)
	tunnel, err := app.CreateTunnel(CreateTunnelInput{UpstreamID: upstream.ID, Label: "home", GenerateKeys: true}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	config := app.ClientConfig(tunnel, upstream, mustSettings(t, app))
	client, _ := clientTransportAddress(upstream, tunnel)
	transport, _ := transportPrefix(upstream)

	// The tunnel interface takes a transport address. Putting the delegated /64
	// on the tunnel instead would leave nothing for the LAN to advertise.
	if !strings.Contains(config, "Address = "+client.String()+"/"+strconv.Itoa(transport.Bits())) {
		t.Fatalf("client interface is not numbered from the transport range:\n%s", config)
	}
	if strings.Contains(config, "Address = "+upstream.V6CIDR) {
		t.Fatalf("delegated prefix was placed on the tunnel interface:\n%s", config)
	}
	// The admin still needs to know which prefix to advertise on the LAN.
	if !strings.Contains(config, upstream.V6CIDR) {
		t.Fatalf("client config does not state the routed prefix:\n%s", config)
	}
	if !strings.Contains(config, "AllowedIPs = ::/0") {
		t.Fatalf("client config does not route IPv6 through the tunnel:\n%s", config)
	}
}

func TestRoutedDelegationKeepsItsExistingAddressing(t *testing.T) {
	app, _ := testApp(t)
	upstream := mustUpstream(t, app)
	tunnel, err := app.CreateTunnel(CreateTunnelInput{Label: "routed", Prefix: 56, GenerateKeys: true}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	cfg := mustSettings(t, app)
	// A routed upstream must be untouched by the on-link work: the tunnel is
	// still numbered from its own delegated prefix.
	if _, ok := clientTransportAddress(upstream, tunnel); ok {
		t.Fatal("routed delegation must not use a transport address")
	}
	allocation := netip.MustParsePrefix(tunnel.V6CIDR)
	config := app.ClientConfig(tunnel, upstream, cfg)
	if !strings.Contains(config, "Address = "+firstUsable(allocation).String()+"/56") {
		t.Fatalf("routed client addressing changed:\n%s", config)
	}
	if len(tunnelAllowedIPs(cfg, upstream, tunnel)) != 1 {
		t.Fatalf("routed AllowedIPs gained an entry: %+v", tunnelAllowedIPs(cfg, upstream, tunnel))
	}
	// The server's own /64 stays reserved when the provider routes the prefix.
	if reserved, ok := serverReservation(upstream); !ok || reserved.String() != "2001:db8:1200::/64" {
		t.Fatalf("server reservation was lost: %s, %v", reserved, ok)
	}
}

func TestOnLinkSettingsRejectContradictoryAddressing(t *testing.T) {
	app, _, upstream := onLinkApp(t)

	// A transport address inside the delegated prefix would collide with the
	// space handed downstream.
	invalid := onLinkUpstream()
	invalid.ID = upstream.ID
	invalid.TransportAddress = "2001:db8:1200:416::1/64"
	if _, err := app.UpdateUpstream(invalid, "admin"); err == nil {
		t.Fatal("a transport address inside the delegated prefix was accepted")
	}
	// Routed mode with no transport address must still be allowed, since it
	// numbers the tunnel from the prefix itself.
	routed := onLinkUpstream()
	routed.ID = upstream.ID
	routed.Mode = UpstreamRouted
	routed.TransportAddress = ""
	routed.ServerAddress = "2001:db8:1200:416::1/64"
	if _, err := app.UpdateUpstream(routed, "admin"); err != nil {
		t.Fatalf("routed delegation was rejected: %v", err)
	}
	if got := mustUpstream(t, app); got.Mode != UpstreamRouted {
		t.Fatalf("delegation mode was not persisted: %+v", got)
	}
}

func TestSwitchingToOnLinkNeverSilentlyDropsTheServerAddress(t *testing.T) {
	app, _ := testApp(t)
	upstream := mustUpstream(t, app)
	if _, err := app.CreateTunnel(CreateTunnelInput{Label: "existing", Prefix: 56, GenerateKeys: true}, "admin"); err != nil {
		t.Fatal(err)
	}
	onLink := testUpstream()
	onLink.ID = upstream.ID
	onLink.Mode = UpstreamOnLink

	// The reserved server address and full delegation contradict each other. The
	// switch must be refused with an actionable message rather than quietly
	// renumbering a running deployment.
	_, err := app.UpdateUpstream(onLink, "admin")
	if err == nil {
		t.Fatal("switching to on-link silently discarded the reserved server address")
	}
	if !strings.Contains(err.Error(), "server address") {
		t.Fatalf("error does not say what to fix: %v", err)
	}
	if unchanged := mustUpstream(t, app); unchanged.Mode != UpstreamRouted || unchanged.ServerAddress != upstream.ServerAddress {
		t.Fatalf("a rejected switch still modified the upstream: %+v", unchanged)
	}

	// Clearing it, as the message instructs, completes the switch.
	onLink.ServerAddress = ""
	if _, err = app.UpdateUpstream(onLink, "admin"); err != nil {
		t.Fatalf("switch was refused after clearing the server address: %v", err)
	}
	after := mustUpstream(t, app)
	if after.Mode != UpstreamOnLink || after.TransportAddress == "" {
		t.Fatalf("switch did not configure on-link delegation: %+v", after)
	}
}

func TestProxySetIsBuiltPerUpstream(t *testing.T) {
	routed := Upstream{ID: 1, V6CIDR: "2001:db8:1200::/48", Mode: UpstreamRouted, EgressInterface: "eth0", InterfaceName: "wg0"}
	if set := ndpProxySetFor(routed, []Tunnel{{ID: 1, UpstreamID: 1, V6CIDR: "2001:db8:1200:100::/56", Enabled: true}}, nil); !set.empty() {
		t.Fatalf("routed delegation needs no Neighbor Discovery proxy: %+v", set)
	}
	onLink := Upstream{ID: 2, V6CIDR: "2001:db8:1200:416::/64", Mode: UpstreamOnLink, EgressInterface: "eth1", InterfaceName: "wg1"}
	set := ndpProxySetFor(onLink, []Tunnel{{ID: 2, UpstreamID: 2, V6CIDR: "2001:db8:1200:416::/64", Enabled: true}}, nil)
	if len(set.Delegated) != 1 || set.Delegated[0].String() != "2001:db8:1200:416::/64" {
		t.Fatalf("on-link delegation was not proxied: %+v", set)
	}
}

// Two on-link providers must each get their own listener, and two on-link
// prefixes arriving on one interface must share a single merged one.
func TestNeighborDiscoveryProxyIsScopedPerEgressInterface(t *testing.T) {
	upstreams := []Upstream{
		{ID: 1, Name: "a", V6CIDR: "2001:db8:1::/64", Mode: UpstreamOnLink, EgressInterface: "eth0", InterfaceName: "wg0"},
		{ID: 2, Name: "b", V6CIDR: "2001:db8:2::/64", Mode: UpstreamOnLink, EgressInterface: "eth1", InterfaceName: "wg1"},
		{ID: 3, Name: "c", V6CIDR: "2001:db8:3::/64", Mode: UpstreamOnLink, EgressInterface: "eth0", InterfaceName: "wg2"},
		{ID: 4, Name: "d", V6CIDR: "2001:db8:4::/64", Mode: UpstreamRouted, EgressInterface: "eth2", InterfaceName: "wg3"},
	}
	tunnels := map[int64][]Tunnel{
		1: {{ID: 1, UpstreamID: 1, V6CIDR: "2001:db8:1::/64", Enabled: true}},
		2: {{ID: 2, UpstreamID: 2, V6CIDR: "2001:db8:2::/64", Enabled: true}},
		3: {{ID: 3, UpstreamID: 3, V6CIDR: "2001:db8:3::/64", Enabled: true}},
		4: {{ID: 4, UpstreamID: 4, V6CIDR: "2001:db8:4::/64", Enabled: true}},
	}
	host := netip.MustParseAddr("2001:db8:1::10")
	sets := ndpProxySetsFor(upstreams, tunnels, map[string][]netip.Addr{"eth0": {host}})

	if len(sets) != 2 {
		t.Fatalf("expected one proxy per on-link egress interface: %+v", sets)
	}
	// eth0 carries two independent on-link prefixes, so its listener answers for
	// both while still excluding the host's own address.
	shared := sets["eth0"]
	if len(shared.Delegated) != 2 || !shared.shouldAnswer(netip.MustParseAddr("2001:db8:1::99")) || !shared.shouldAnswer(netip.MustParseAddr("2001:db8:3::99")) {
		t.Fatalf("shared egress interface does not answer for both prefixes: %+v", shared)
	}
	if shared.shouldAnswer(host) {
		t.Fatal("the host's own address must never be proxied")
	}
	if sets["eth1"].shouldAnswer(netip.MustParseAddr("2001:db8:1::99")) {
		t.Fatal("one provider's listener answered for another provider's prefix")
	}
	// A routed upstream contributes nothing at all.
	if _, ok := sets["eth2"]; ok {
		t.Fatalf("a routed upstream started a Neighbor Discovery proxy: %+v", sets)
	}
}

func TestProxySetEqualityDetectsMembershipChanges(t *testing.T) {
	upstream := Upstream{ID: 1, V6CIDR: "2001:db8:1200:416::/64", Mode: UpstreamOnLink}
	first := ndpProxySetFor(upstream, []Tunnel{{ID: 1, V6CIDR: "2001:db8:1200:416::/64", Enabled: true}}, nil)
	same := ndpProxySetFor(upstream, []Tunnel{{ID: 1, V6CIDR: "2001:db8:1200:416::/64", Enabled: true}}, nil)
	if !first.equal(same) {
		t.Fatal("identical proxy sets compared unequal")
	}
	if first.equal(ndpProxySetFor(upstream, nil, nil)) {
		t.Fatal("an emptied proxy set compared equal")
	}
}

// Two on-link upstreams must number their tunnels from different transport
// ranges, or peers on separate providers would collide on one address.
func TestOnLinkUpstreamsGetDistinctTransportRanges(t *testing.T) {
	app, _, first := onLinkApp(t)
	second := onLinkUpstream()
	second.Name = "vps-2"
	second.V6CIDR = "2001:db8:1200:417::/64"
	second.InterfaceName = "wg-test2"
	second.EndpointPort = 51821
	second.EgressInterface = "eth1"
	other, err := app.CreateUpstream(second, "admin")
	if err != nil {
		t.Fatal(err)
	}
	firstRange, ok := transportPrefix(first)
	if !ok {
		t.Fatalf("first upstream has no transport range: %+v", first)
	}
	otherRange, ok := transportPrefix(other)
	if !ok {
		t.Fatalf("second upstream has no transport range: %+v", other)
	}
	if overlaps(firstRange.Masked(), otherRange.Masked()) {
		t.Fatalf("transport ranges overlap: %s and %s", firstRange, otherRange)
	}
	// A third upstream reusing an existing range must be refused outright.
	third := second
	third.Name = "vps-3"
	third.V6CIDR = "2001:db8:1200:418::/64"
	third.InterfaceName = "wg-test3"
	third.EndpointPort = 51822
	third.TransportAddress = firstRange.String()
	if _, err = app.CreateUpstream(third, "admin"); err == nil || !strings.Contains(err.Error(), "transport range") {
		t.Fatalf("an overlapping transport range was accepted: %v", err)
	}
}
