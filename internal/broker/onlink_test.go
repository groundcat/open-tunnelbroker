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

// onLinkApp models the single-/64 VPS case: the provider assigns one /64 that it
// treats as directly attached to the server's Ethernet interface.
func onLinkApp(t *testing.T) (*App, *fakeKernel) {
	t.Helper()
	app, err := New(filepath.Join(t.TempDir(), "broker.db"), true, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.Close() })
	kernel := &fakeKernel{}
	app.kernel = kernel
	err = app.SaveSettings(Settings{
		UpstreamV6:        "2001:db8:1200:416::/64",
		UpstreamMode:      UpstreamOnLink,
		V4Pool:            "10.99.0.0/16",
		DefaultDNS:        "2606:4700:4700::1111",
		EndpointHost:      "vps.example.test",
		EndpointPort:      51820,
		InterfaceName:     "wg-test",
		MTU:               1420,
		Keepalive:         25,
		UpstreamInterface: "eth0",
	})
	if err != nil {
		t.Fatal(err)
	}
	return app, kernel
}

func TestSingleSlash64NeedsNoManualPrefixConfiguration(t *testing.T) {
	app, _ := onLinkApp(t)
	cfg := mustSettings(t, app)

	// A /64 cannot be subdivided for SLAAC, so the only offered allocation size
	// is the whole prefix, with no admin arithmetic required.
	if cfg.MinPrefix != 64 || cfg.MaxPrefix != 64 || cfg.DefaultPrefix != 64 {
		t.Fatalf("prefix limits were not normalized to the single /64: %+v", cfg)
	}
	// A transport address outside the prefix is filled in automatically, because
	// the prefix itself has no room for an infrastructure address.
	transport, ok := transportPrefix(cfg)
	if !ok {
		t.Fatalf("no WireGuard transport address was configured: %+v", cfg)
	}
	upstream := netip.MustParsePrefix(cfg.UpstreamV6)
	if upstream.Contains(transport.Addr()) {
		t.Fatalf("transport address %s must not consume delegated space", transport)
	}
	if cfg.ServerAddress != "" {
		t.Fatalf("on-link delegation must reserve no address inside the prefix: %q", cfg.ServerAddress)
	}
}

func TestEntireSlash64IsDelegatedToOneTunnel(t *testing.T) {
	app, kernel := onLinkApp(t)
	tunnel, err := app.CreateTunnel(CreateTunnelInput{Label: "home", GenerateKeys: true}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	cfg := mustSettings(t, app)
	// The whole upstream /64 goes to the tunnel: no split, no reserved subnet.
	if tunnel.V6CIDR != cfg.UpstreamV6 {
		t.Fatalf("tunnel received %s instead of the entire upstream %s", tunnel.V6CIDR, cfg.UpstreamV6)
	}
	if tunnel.Status != "applied" || len(kernel.applied) != 1 {
		t.Fatalf("tunnel was not applied: %+v", tunnel)
	}

	// AllowedIPs must carry the delegated /64 plus the peer's transport address,
	// otherwise its own tunnel-sourced packets would be dropped.
	allowed := tunnelAllowedIPs(cfg, tunnel)
	client, ok := clientTransportAddress(cfg, tunnel)
	if !ok {
		t.Fatal("no client transport address was derived")
	}
	want := map[string]bool{cfg.UpstreamV6: false, netip.PrefixFrom(client, 128).String(): false}
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
	if _, err = app.CreateTunnel(CreateTunnelInput{Label: "second", GenerateKeys: true}, "admin"); err == nil {
		t.Fatal("a second tunnel was allocated from an exhausted single /64")
	}
}

func TestOnLinkClientConfigKeepsTheWholePrefixFreeForSLAAC(t *testing.T) {
	app, _ := onLinkApp(t)
	tunnel, err := app.CreateTunnel(CreateTunnelInput{Label: "home", GenerateKeys: true}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	cfg := mustSettings(t, app)
	config := app.ClientConfig(tunnel, cfg)
	client, _ := clientTransportAddress(cfg, tunnel)
	transport, _ := transportPrefix(cfg)

	// The tunnel interface takes a transport address. Putting the delegated /64
	// on the tunnel instead would leave nothing for the LAN to advertise.
	if !strings.Contains(config, "Address = "+client.String()+"/"+strconv.Itoa(transport.Bits())) {
		t.Fatalf("client interface is not numbered from the transport range:\n%s", config)
	}
	if strings.Contains(config, "Address = "+cfg.UpstreamV6) {
		t.Fatalf("delegated prefix was placed on the tunnel interface:\n%s", config)
	}
	// The admin still needs to know which prefix to advertise on the LAN.
	if !strings.Contains(config, cfg.UpstreamV6) {
		t.Fatalf("client config does not state the routed prefix:\n%s", config)
	}
	if !strings.Contains(config, "AllowedIPs = ::/0") {
		t.Fatalf("client config does not route IPv6 through the tunnel:\n%s", config)
	}
}

func TestRoutedDelegationKeepsItsExistingAddressing(t *testing.T) {
	app, _ := testApp(t)
	tunnel, err := app.CreateTunnel(CreateTunnelInput{Label: "routed", Prefix: 56, GenerateKeys: true}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	cfg := mustSettings(t, app)
	// A routed upstream must be untouched by the on-link work: the tunnel is
	// still numbered from its own delegated prefix.
	if _, ok := clientTransportAddress(cfg, tunnel); ok {
		t.Fatal("routed delegation must not use a transport address")
	}
	allocation := netip.MustParsePrefix(tunnel.V6CIDR)
	config := app.ClientConfig(tunnel, cfg)
	if !strings.Contains(config, "Address = "+firstUsable(allocation).String()+"/56") {
		t.Fatalf("routed client addressing changed:\n%s", config)
	}
	if len(tunnelAllowedIPs(cfg, tunnel)) != 1 {
		t.Fatalf("routed AllowedIPs gained an entry: %+v", tunnelAllowedIPs(cfg, tunnel))
	}
	// The server's own /64 stays reserved when the provider routes the prefix.
	if reserved, ok := serverReservation(cfg); !ok || reserved.String() != "2001:db8:1200::/64" {
		t.Fatalf("server reservation was lost: %s, %v", reserved, ok)
	}
}

func TestOnLinkSettingsRejectContradictoryAddressing(t *testing.T) {
	app, _ := onLinkApp(t)
	cfg := mustSettings(t, app)

	// A transport address inside the delegated prefix would collide with the
	// space handed downstream.
	invalid := cfg
	invalid.TransportAddress = "2001:db8:1200:416::1/64"
	if err := app.SaveSettings(invalid); err == nil {
		t.Fatal("a transport address inside the delegated prefix was accepted")
	}
	// Routed mode with no transport address must still be allowed, since it
	// numbers the tunnel from the prefix itself.
	routed := cfg
	routed.UpstreamMode = UpstreamRouted
	routed.TransportAddress = ""
	routed.ServerAddress = "2001:db8:1200:416::1/64"
	if err := app.SaveSettings(routed); err != nil {
		t.Fatalf("routed delegation was rejected: %v", err)
	}
	if got := mustSettings(t, app); got.UpstreamMode != UpstreamRouted {
		t.Fatalf("delegation mode was not persisted: %+v", got)
	}
}

func TestSwitchingToOnLinkNeverSilentlyDropsTheServerAddress(t *testing.T) {
	app, _ := testApp(t)
	if _, err := app.CreateTunnel(CreateTunnelInput{Label: "existing", Prefix: 56, GenerateKeys: true}, "admin"); err != nil {
		t.Fatal(err)
	}
	cfg := mustSettings(t, app)
	cfg.UpstreamMode = UpstreamOnLink

	// The reserved server address and full delegation contradict each other. The
	// switch must be refused with an actionable message rather than quietly
	// renumbering a running deployment.
	err := app.SaveSettings(cfg)
	if err == nil {
		t.Fatal("switching to on-link silently discarded the reserved server address")
	}
	if !strings.Contains(err.Error(), "server address") {
		t.Fatalf("error does not say what to fix: %v", err)
	}
	if unchanged := mustSettings(t, app); unchanged.UpstreamMode != UpstreamRouted || unchanged.ServerAddress != cfg.ServerAddress {
		t.Fatalf("a rejected switch still modified settings: %+v", unchanged)
	}

	// Clearing it, as the message instructs, completes the switch.
	cfg.ServerAddress = ""
	if err = app.SaveSettings(cfg); err != nil {
		t.Fatalf("switch was refused after clearing the server address: %v", err)
	}
	after := mustSettings(t, app)
	if after.UpstreamMode != UpstreamOnLink || after.TransportAddress == "" {
		t.Fatalf("switch did not configure on-link delegation: %+v", after)
	}
}

func TestDelegationMigrationDefaultsExistingDeploymentsToRouted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "migration.db")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	// Recreate a database written before delegation modes existed.
	for _, statement := range []string{
		`ALTER TABLE settings DROP COLUMN upstream_mode`,
		`ALTER TABLE settings DROP COLUMN transport_address`,
	} {
		if _, err = store.db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = store.db.Exec(`UPDATE settings SET upstream_v6='2001:db8:1200::/48',server_address='2001:db8:1200::1/64' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	cfg, err := store.Settings()
	if err != nil {
		t.Fatal(err)
	}
	// An upgrade must not change how an existing prefix is delegated, and must
	// not start proxying Neighbor Discovery on a routed upstream.
	if cfg.UpstreamMode != UpstreamRouted || cfg.TransportAddress != "" {
		t.Fatalf("migration changed delegation behavior: %+v", cfg)
	}
	if cfg.ServerAddress != "2001:db8:1200::1/64" {
		t.Fatalf("migration disturbed the server address: %+v", cfg)
	}
	if set := ndpProxySetFor(cfg, []Tunnel{{ID: 1, V6CIDR: "2001:db8:1200:100::/56", Enabled: true}}, nil); !set.empty() {
		t.Fatal("migration enabled Neighbor Discovery proxying on a routed upstream")
	}
}

func TestSettingsResetPreservesOnLinkDelegation(t *testing.T) {
	app, _ := onLinkApp(t)
	if err := app.ResetGeneralSettings("admin"); err != nil {
		t.Fatal(err)
	}
	cfg := mustSettings(t, app)
	// Delegation describes how the provider hands over the prefix, so a reset
	// of general preferences must not silently break a working /64 deployment.
	if cfg.UpstreamMode != UpstreamOnLink || cfg.TransportAddress == "" {
		t.Fatalf("reset discarded the delegation configuration: %+v", cfg)
	}
	if cfg.MinPrefix != 64 || cfg.MaxPrefix != 64 || cfg.DefaultPrefix != 64 {
		t.Fatalf("reset restored prefix sizes a single /64 cannot satisfy: %+v", cfg)
	}
}
