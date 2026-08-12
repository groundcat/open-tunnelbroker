package broker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeKernel struct {
	applyErr          error
	removeUpstreamErr error
	applied           []Tunnel
	appliedUpstream   []Upstream
	traffic           map[int64][2]int64
	applyN            int
	removedUpstream   []string
	closed            bool
}

func (f *fakeKernel) Apply(_ context.Context, _ Settings, _ WarpAccount, upstreams []Upstream, tunnels []Tunnel) ([]Tunnel, error) {
	f.applyN++
	for i := range tunnels {
		if counters, ok := f.traffic[tunnels[i].ID]; ok {
			tunnels[i].RXBytes = counters[0]
			tunnels[i].TXBytes = counters[1]
		}
	}
	f.applied = append([]Tunnel(nil), tunnels...)
	f.appliedUpstream = append([]Upstream(nil), upstreams...)
	return tunnels, f.applyErr
}
func (f *fakeKernel) Inspect(_ Settings, _ WarpAccount, _ []Upstream, _ []Tunnel) ([]string, error) {
	return nil, nil
}
func (f *fakeKernel) Remove(_ Upstream, _ Tunnel) error { return nil }
func (f *fakeKernel) RemoveUpstream(u Upstream) error {
	if f.removeUpstreamErr != nil {
		return f.removeUpstreamErr
	}
	f.removedUpstream = append(f.removedUpstream, u.InterfaceName)
	return nil
}
func (f *fakeKernel) Close() error { f.closed = true; return nil }
func (f *fakeKernel) TestWarp(_ context.Context, _ Settings, _ WarpAccount) (string, error) {
	return "fl=1\nip=203.0.113.8\nwarp=on\n", nil
}

// testUpstream is the routed /48 that most tests allocate from.
func testUpstream() UpstreamInput {
	return UpstreamInput{Name: "primary", V6CIDR: "2001:db8:1200::/48", Mode: UpstreamRouted, EndpointHost: "broker.example.test", EndpointPort: 51820, InterfaceName: "wg-test", ServerAddress: "2001:db8:1200::1/64", MTU: 1420, Keepalive: 25, MinPrefix: 56, MaxPrefix: 64, DefaultPrefix: 56, EgressInterface: "eth0"}
}

func testApp(t *testing.T) (*App, *fakeKernel) {
	t.Helper()
	a, err := New(filepath.Join(t.TempDir(), "broker.db"), true, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	f := &fakeKernel{}
	a.kernel = f
	if err = a.SaveSettings(Settings{V4Pool: "10.99.0.0/16", DefaultDNS: "2606:4700:4700::1111"}); err != nil {
		t.Fatal(err)
	}
	if _, err = a.CreateUpstream(testUpstream(), "admin"); err != nil {
		t.Fatal(err)
	}
	return a, f
}

// mustUpstream returns the single configured upstream, which is what most tests
// allocate from.
func mustUpstream(t *testing.T, a *App) Upstream {
	t.Helper()
	upstreams, err := a.store.Upstreams()
	if err != nil || len(upstreams) == 0 {
		t.Fatalf("no upstream configured: %+v, %v", upstreams, err)
	}
	return upstreams[0]
}

// mustUpstreams returns every configured connection, for tests that need to
// pick a specific one out of several.
func mustUpstreams(t *testing.T, a *App) []Upstream {
	t.Helper()
	upstreams, err := a.store.Upstreams()
	if err != nil {
		t.Fatalf("reading upstreams failed: %v", err)
	}
	return upstreams
}

func TestCreateTunnelPersistsThenApplies(t *testing.T) {
	a, kernel := testApp(t)
	tunnel, err := a.CreateTunnel(CreateTunnelInput{Label: "one", Prefix: 56, GenerateKeys: true}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	allocation := netip.MustParsePrefix(tunnel.V6CIDR)
	if allocation.Bits() != 56 || !netip.MustParsePrefix("2001:db8:1200::/48").Contains(allocation.Addr()) || overlaps(allocation, netip.MustParsePrefix("2001:db8:1200::/64")) || tunnel.Status != "applied" {
		t.Fatalf("unexpected tunnel: %+v", tunnel)
	}
	if len(kernel.applied) != 1 || kernel.applied[0].ID != tunnel.ID {
		t.Fatal("kernel did not receive persisted tunnel")
	}
	if tunnel.QuotaGiB != 100 || tunnel.QuotaPeriod != quotaMonth(time.Now()) {
		t.Fatalf("unexpected default monthly quota: %+v", tunnel)
	}
	expectedAddress := "Address = " + firstUsable(allocation).String() + "/56"
	if cfg := a.ClientConfig(tunnel, mustUpstream(t, a), mustSettings(t, a)); !containsAll(cfg, expectedAddress, "Endpoint = broker.example.test:51820") {
		t.Fatalf("bad client config: %s", cfg)
	}
	if tunnel.UpstreamID != mustUpstream(t, a).ID {
		t.Fatalf("tunnel was not attached to its upstream: %+v", tunnel)
	}
}

func TestMonthlyQuotaCountsBothDirectionsAndDisablesAtLimit(t *testing.T) {
	a, _ := testApp(t)
	tunnel, err := a.CreateTunnel(CreateTunnelInput{Label: "quota", QuotaGiB: 1, GenerateKeys: true}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	hit, err := a.store.UpdateTelemetry(Tunnel{ID: tunnel.ID, RXBytes: 600 << 20, TXBytes: 424 << 20}, now)
	if err != nil || !hit {
		t.Fatalf("quota limit was not reported: hit=%v err=%v", hit, err)
	}
	stored, err := a.store.Tunnel(tunnel.ID)
	if err != nil || stored.Enabled || !stored.QuotaDisabled || stored.QuotaUsedBytes != 1<<30 || stored.Status != "quota-exceeded" {
		t.Fatalf("tunnel was not disabled at quota: %+v, %v", stored, err)
	}

	if err = a.SetTunnelQuota(tunnel.ID, 2, "admin"); err != nil {
		t.Fatal(err)
	}
	stored, err = a.store.Tunnel(tunnel.ID)
	if err != nil || !stored.Enabled || stored.QuotaDisabled || stored.QuotaGiB != 2 {
		t.Fatalf("raising quota did not restore tunnel: %+v, %v", stored, err)
	}
}

func TestReconcileImmediatelyRemovesQuotaExceededPeer(t *testing.T) {
	a, kernel := testApp(t)
	tunnel, err := a.CreateTunnel(CreateTunnelInput{Label: "enforced", QuotaGiB: 1, GenerateKeys: true}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	kernel.traffic = map[int64][2]int64{tunnel.ID: {700 << 20, 324 << 20}}
	before := kernel.applyN
	if err = a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	stored, err := a.store.Tunnel(tunnel.ID)
	if err != nil || stored.Enabled || !stored.QuotaDisabled {
		t.Fatalf("quota was not enforced during reconciliation: %+v, %v", stored, err)
	}
	if kernel.applyN != before+2 || len(kernel.applied) != 1 || kernel.applied[0].Enabled {
		t.Fatalf("disabled peer was not immediately reapplied: calls=%d applied=%+v", kernel.applyN-before, kernel.applied)
	}
}

func TestMonthlyQuotaResetRestoresOnlyQuotaDisabledTunnels(t *testing.T) {
	a, _ := testApp(t)
	quotaTunnel, err := a.CreateTunnel(CreateTunnelInput{Label: "quota", QuotaGiB: 1, GenerateKeys: true}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	manualTunnel, err := a.CreateTunnel(CreateTunnelInput{Label: "manual", GenerateKeys: true}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err = a.store.UpdateTelemetry(Tunnel{ID: quotaTunnel.ID, RXBytes: 1 << 30}, now); err != nil {
		t.Fatal(err)
	}
	if err = a.store.SetEnabled(manualTunnel.ID, false, "admin"); err != nil {
		t.Fatal(err)
	}
	nextMonth := time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC)
	if err = a.store.ResetMonthlyQuotas(nextMonth); err != nil {
		t.Fatal(err)
	}
	quotaTunnel, _ = a.store.Tunnel(quotaTunnel.ID)
	manualTunnel, _ = a.store.Tunnel(manualTunnel.ID)
	if !quotaTunnel.Enabled || quotaTunnel.QuotaDisabled || quotaTunnel.QuotaUsedBytes != 0 || quotaTunnel.QuotaPeriod != quotaMonth(nextMonth) {
		t.Fatalf("quota-disabled tunnel was not reset: %+v", quotaTunnel)
	}
	if manualTunnel.Enabled {
		t.Fatalf("manually disabled tunnel was re-enabled: %+v", manualTunnel)
	}
}

func TestMonthlyQuotaHandlesWireGuardCounterReset(t *testing.T) {
	a, _ := testApp(t)
	tunnel, err := a.CreateTunnel(CreateTunnelInput{Label: "counters", GenerateKeys: true}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err = a.store.UpdateTelemetry(Tunnel{ID: tunnel.ID, RXBytes: 100, TXBytes: 200}, now); err != nil {
		t.Fatal(err)
	}
	if _, err = a.store.UpdateTelemetry(Tunnel{ID: tunnel.ID, RXBytes: 10, TXBytes: 20}, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	tunnel, err = a.store.Tunnel(tunnel.ID)
	if err != nil || tunnel.QuotaUsedBytes != 330 {
		t.Fatalf("counter reset delta was counted incorrectly: %+v, %v", tunnel, err)
	}
}

func TestTunnelCreateAndEditFormsExposeMonthlyQuota(t *testing.T) {
	a, _ := testApp(t)
	managed := []RoutingGroup{{ID: 1, Name: "internal"}, {ID: 2, Name: "production"}}
	for _, group := range managed {
		if err := a.CreateRoutingGroup(group.Name, "admin"); err != nil {
			t.Fatal(err)
		}
	}
	// The form's defaults are supplied by the handler, so the page is fetched
	// rather than rendered from a hand-built view.
	body := get(t, a.newTunnel, "/tunnels/new").Body.String()
	if !containsAll(body, `name="quota_gib"`, `value="100"`, `name="routing_groups"`, `multiple`, "Monthly upload + download quota") {
		t.Fatalf("new tunnel quota field is missing: %s", body)
	}

	detailRecorder := httptest.NewRecorder()
	a.render(detailRecorder, "detail", view{Title: "Tunnel", Tunnel: Tunnel{ID: 1, V6CIDR: "2001:db8::/64", QuotaGiB: 250, QuotaPeriod: "2026-08", RoutingGroups: []string{"internal"}}, Upstream: mustUpstream(t, a), RoutingGroups: managed, EffectiveV4Mode: V4ModeOff})
	if body := detailRecorder.Body.String(); !containsAll(body, `name="quota_gib"`, `value="250"`, `name="routing_groups"`, `value="internal" selected`, "Monthly traffic:", "2026-08") {
		t.Fatalf("edit tunnel quota field is missing: %s", body)
	}
}

func TestRoutingPageAppliesGlobalPolicy(t *testing.T) {
	a, _ := testApp(t)
	groupsRecorder := httptest.NewRecorder()
	a.render(groupsRecorder, "groups", view{Title: "Groups", RoutingGroups: []RoutingGroup{{ID: 1, Name: "internal", TunnelCount: 2}}})
	if body := groupsRecorder.Body.String(); !containsAll(body, "Create routing group", "Managed groups", "internal", "2", `action" value="delete`) {
		t.Fatalf("group management page is incomplete: %s", body)
	}
	getRecorder := httptest.NewRecorder()
	a.render(getRecorder, "routing", view{Title: "Routing", Settings: mustSettings(t, a)})
	if body := getRecorder.Body.String(); !containsAll(body, "Inter-tunnel routing policy", "Isolated", "Shared managed group", "Any tunnel", "Routing-group assignments") {
		t.Fatalf("routing policy form is incomplete: %s", body)
	}

	form := url.Values{"csrf": {"token"}, "inter_tunnel_policy": {InterTunnelAny}}
	request := httptest.NewRequest(http.MethodPost, "/routing", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("X-OTB-User", "admin")
	request.Header.Set("X-OTB-CSRF", "token")
	recorder := httptest.NewRecorder()
	a.routing(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("routing update returned %d", recorder.Code)
	}
	if cfg := mustSettings(t, a); cfg.InterTunnelPolicy != InterTunnelAny {
		t.Fatalf("routing policy was not persisted: %+v", cfg)
	}
}

func TestApplyFailureLeavesAllocationInError(t *testing.T) {
	a, kernel := testApp(t)
	kernel.applyErr = errors.New("synthetic apply failure")
	tunnel, err := a.CreateTunnel(CreateTunnelInput{Label: "one", GenerateKeys: true}, "admin")
	if err == nil {
		t.Fatal("expected apply error")
	}
	stored, storeErr := a.store.Tunnel(tunnel.ID)
	if storeErr != nil || stored.Status != "error" || stored.V6CIDR == "" {
		t.Fatalf("allocation was not retained as error: %+v, %v", stored, storeErr)
	}
}

func TestClientConfigFormatsIPv6EndpointAndSingleAddress(t *testing.T) {
	a, _ := testApp(t)
	upstream := mustUpstream(t, a)
	upstream.EndpointHost = "2001:db8::10"
	tunnel := Tunnel{V6CIDR: "2001:db8:1200::9/128", PresharedKey: "test"}
	generated := a.ClientConfig(tunnel, upstream, mustSettings(t, a))
	if !containsAll(generated, "Address = 2001:db8:1200::9/128", "Endpoint = [2001:db8::10]:51820") {
		t.Fatalf("bad client config: %s", generated)
	}
}

func TestClientConfigGlobalNATToggleControlsIPv4(t *testing.T) {
	a, _ := testApp(t)
	cfg := mustSettings(t, a)
	upstream := mustUpstream(t, a)
	tunnel := Tunnel{V6CIDR: "2001:db8:1200:100::/56", V4Enabled: true, V4Address: "10.99.0.2"}

	cfg.V4NAT = false
	v6Only := a.ClientConfig(tunnel, upstream, cfg)
	if strings.Contains(v6Only, "10.99.0.2") || strings.Contains(v6Only, "0.0.0.0/0") || !strings.Contains(v6Only, "AllowedIPs = ::/0") {
		t.Fatalf("IPv4 leaked into config while global NAT was disabled: %s", v6Only)
	}

	cfg.V4NAT = true
	dualStack := a.ClientConfig(tunnel, upstream, cfg)
	if !containsAll(dualStack, "10.99.0.2/32", "AllowedIPs = 0.0.0.0/0, ::/0") {
		t.Fatalf("IPv4 missing while NAT was enabled: %s", dualStack)
	}
}

func TestTunnelQRCodeIsSensitivePNG(t *testing.T) {
	a, _ := testApp(t)
	tunnel := Tunnel{ID: 7, Label: "QR test", PrivateKey: "private-key", PresharedKey: "preshared-key", V6CIDR: "2001:db8:1200:100::/56"}
	recorder := httptest.NewRecorder()
	a.tunnelQRCode(recorder, tunnel)
	result := recorder.Result()
	defer result.Body.Close()
	if result.StatusCode != http.StatusOK || result.Header.Get("Content-Type") != "image/png" || result.Header.Get("Cache-Control") != "no-store, private" {
		t.Fatalf("unexpected QR response: status=%d headers=%v", result.StatusCode, result.Header)
	}
	if !bytes.HasPrefix(recorder.Body.Bytes(), []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatal("QR response is not a PNG")
	}
}

func TestTunnelQRCodeRequiresServerGeneratedPrivateKey(t *testing.T) {
	a, _ := testApp(t)
	recorder := httptest.NewRecorder()
	a.tunnelQRCode(recorder, Tunnel{ID: 8, V6CIDR: "2001:db8:1200:200::/56"})
	if recorder.Code != http.StatusConflict {
		t.Fatalf("expected conflict, got %d", recorder.Code)
	}
}

func TestEnablingGlobalIPv4BackfillsExistingTunnels(t *testing.T) {
	a, _ := testApp(t)
	first, err := a.CreateTunnel(CreateTunnelInput{Label: "first", GenerateKeys: true}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if first.V4Address != "" {
		t.Fatal("IPv4 was allocated while global egress was disabled")
	}
	cfg := mustSettings(t, a)
	cfg.V4NAT = true
	if err = a.SaveSettings(cfg); err != nil {
		t.Fatal(err)
	}
	first, err = a.store.Tunnel(first.ID)
	if err != nil || first.V4Address != "10.99.0.1" || !first.V4Enabled {
		t.Fatalf("existing tunnel was not backfilled: %+v, %v", first, err)
	}
	second, err := a.CreateTunnel(CreateTunnelInput{Label: "second", GenerateKeys: true}, "admin")
	if err != nil || second.V4Address != "10.99.0.2" || !second.V4Enabled {
		t.Fatalf("new tunnel did not inherit global IPv4: %+v, %v", second, err)
	}
}

func TestTunnelIPv4ModeOverridesGlobalDefault(t *testing.T) {
	a, _ := testApp(t)
	cfg := mustSettings(t, a)
	upstream := mustUpstream(t, a)

	native, err := a.CreateTunnel(CreateTunnelInput{Label: "native", V4Mode: V4ModeNative, GenerateKeys: true}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if native.V4Mode != V4ModeNative || native.V4Address != "10.99.0.1" || !tunnelIPv4Enabled(cfg, upstream, native) {
		t.Fatalf("native override was not applied: %+v", native)
	}
	if current := mustSettings(t, a); current.V4NAT || current.V4Warp {
		t.Fatalf("tunnel override changed global mode: %+v", current)
	}
	if generated := a.ClientConfig(native, upstream, cfg); !containsAll(generated, "10.99.0.1/32", "AllowedIPs = 0.0.0.0/0, ::/0") {
		t.Fatalf("override missing from client config: %s", generated)
	}

	cfg.V4NAT = true
	if err = a.SaveSettings(cfg); err != nil {
		t.Fatal(err)
	}
	disabled, err := a.CreateTunnel(CreateTunnelInput{Label: "disabled", V4Mode: V4ModeOff, GenerateKeys: true}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if disabled.V4Address != "" || tunnelIPv4Enabled(cfg, upstream, disabled) {
		t.Fatalf("disabled override inherited global native mode: %+v", disabled)
	}
}

// The three-level default must resolve tunnel over upstream over global, so an
// upstream without IPv4 connectivity can opt all of its tunnels out.
func TestUpstreamIPv4ModeOverridesGlobalAndYieldsToTunnel(t *testing.T) {
	a, _ := testApp(t)
	cfg := mustSettings(t, a)
	cfg.V4NAT = true
	if err := a.SaveSettings(cfg); err != nil {
		t.Fatal(err)
	}
	cfg = mustSettings(t, a)

	input := testUpstream()
	input.Name = "v6-only"
	input.V6CIDR = "2001:db8:1300::/48"
	input.ServerAddress = "2001:db8:1300::1/64"
	input.InterfaceName = "wg-v6only"
	input.EndpointPort = 51821
	input.EgressInterface = "ppp0"
	input.V4Mode = V4ModeOff
	v6Only, err := a.CreateUpstream(input, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if upstreamV4Mode(cfg, v6Only) != V4ModeOff {
		t.Fatalf("upstream override did not beat the global default: %+v", v6Only)
	}

	inherited, err := a.CreateTunnel(CreateTunnelInput{UpstreamID: v6Only.ID, Label: "inherits-off", GenerateKeys: true}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if inherited.V4Address != "" || tunnelIPv4Enabled(cfg, v6Only, inherited) {
		t.Fatalf("tunnel inherited IPv4 from the global default instead of its upstream: %+v", inherited)
	}
	// A tunnel may still override its upstream in the other direction.
	overridden, err := a.CreateTunnel(CreateTunnelInput{UpstreamID: v6Only.ID, Label: "opts-in", V4Mode: V4ModeNative, GenerateKeys: true}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if overridden.V4Address == "" || !tunnelIPv4Enabled(cfg, v6Only, overridden) {
		t.Fatalf("tunnel override did not beat its upstream: %+v", overridden)
	}
	// Tunnels on the original upstream keep following the global default.
	primary, err := a.CreateTunnel(CreateTunnelInput{UpstreamID: mustUpstream(t, a).ID, Label: "global", GenerateKeys: true}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if primary.V4Address == "" {
		t.Fatalf("an unrelated upstream lost its global IPv4 default: %+v", primary)
	}
}

func TestTunnelRoutingGroupsPersistAndCanBeEdited(t *testing.T) {
	a, _ := testApp(t)
	if err := a.CreateRoutingGroup("production", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := a.CreateRoutingGroup("internal services", "admin"); err != nil {
		t.Fatal(err)
	}
	tunnel, err := a.CreateTunnel(CreateTunnelInput{Label: "grouped", RoutingGroups: []string{"production", "internal services"}, GenerateKeys: true}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !tunnel.HasRoutingGroup("production") || !tunnel.HasRoutingGroup("internal services") || len(tunnel.RoutingGroups) != 2 {
		t.Fatalf("routing groups were not created: %+v", tunnel)
	}
	groups, err := a.store.RoutingGroups()
	if err != nil || len(groups) != 2 || groups[0].TunnelCount != 1 || groups[1].TunnelCount != 1 {
		t.Fatalf("managed group counts are incorrect: %+v, %v", groups, err)
	}
	if err = a.DeleteRoutingGroup(groups[0].ID, "admin"); err != nil {
		t.Fatal(err)
	}
	tunnel, err = a.store.Tunnel(tunnel.ID)
	if err != nil || tunnel.HasRoutingGroup(groups[0].Name) || len(tunnel.RoutingGroups) != 1 {
		t.Fatalf("deleted group membership was retained: %+v, %v", tunnel, err)
	}
	remaining, err := a.store.RoutingGroups()
	if err != nil || len(remaining) != 1 {
		t.Fatalf("unexpected remaining groups: %+v, %v", remaining, err)
	}
	if err = a.RenameRoutingGroup(remaining[0].ID, "customer-facing", "admin"); err != nil {
		t.Fatal(err)
	}
	tunnel, err = a.store.Tunnel(tunnel.ID)
	if err != nil || !tunnel.HasRoutingGroup("customer-facing") || tunnel.HasRoutingGroup("production") {
		t.Fatalf("renamed group did not preserve membership: %+v, %v", tunnel, err)
	}
	if err = a.SetTunnelRoutingGroups(tunnel.ID, []string{"customer-facing"}, "admin"); err != nil {
		t.Fatal(err)
	}
	tunnel, err = a.store.Tunnel(tunnel.ID)
	if err != nil || len(tunnel.RoutingGroups) != 1 || tunnel.RoutingGroups[0] != "customer-facing" {
		t.Fatalf("routing groups were not updated: %+v, %v", tunnel, err)
	}
	if err = a.SetTunnelRoutingGroups(tunnel.ID, []string{"bad\ngroup"}, "admin"); err == nil {
		t.Fatal("control character in routing group was accepted")
	}
	if err = a.SetTunnelRoutingGroups(tunnel.ID, []string{strings.Repeat("x", 65)}, "admin"); err == nil {
		t.Fatal("oversized routing group was accepted")
	}
	if err = a.SetTunnelRoutingGroups(tunnel.ID, []string{"unknown"}, "admin"); err == nil {
		t.Fatal("unknown routing group was accepted")
	}
	if err = a.CreateRoutingGroup("customer-facing", "admin"); err == nil {
		t.Fatal("duplicate routing group was accepted")
	}
}

func TestInterTunnelPolicyDefaultsToIsolationAndResetsSafely(t *testing.T) {
	a, _ := testApp(t)
	cfg := mustSettings(t, a)
	if cfg.InterTunnelPolicy != InterTunnelIsolated {
		t.Fatalf("unsafe default routing policy: %q", cfg.InterTunnelPolicy)
	}
	cfg.InterTunnelPolicy = "invalid"
	if err := a.SaveSettings(cfg); err == nil {
		t.Fatal("invalid inter-tunnel policy was accepted")
	}
	cfg.InterTunnelPolicy = InterTunnelAny
	if err := a.SaveSettings(cfg); err != nil {
		t.Fatal(err)
	}
	if err := a.ResetGeneralSettings("admin"); err != nil {
		t.Fatal(err)
	}
	if reset := mustSettings(t, a); reset.InterTunnelPolicy != InterTunnelIsolated {
		t.Fatalf("settings reset did not restore isolation: %+v", reset)
	}
}

func TestRoutingMigrationAddsSafeDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "migration.db")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.db.Exec(`ALTER TABLE settings DROP COLUMN inter_tunnel_policy`); err != nil {
		t.Fatal(err)
	}
	legacy := Tunnel{UpstreamID: 1, Label: "legacy", PublicKey: "legacy-key", PresharedKey: "legacy-psk", V6CIDR: "2001:db8::/64", QuotaGiB: 100, QuotaPeriod: "2026-08", Enabled: true}
	if err = store.InsertTunnel(&legacy, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err = store.db.Exec(`ALTER TABLE tunnels ADD COLUMN routing_group TEXT NOT NULL DEFAULT ''`); err != nil {
		t.Fatal(err)
	}
	if _, err = store.db.Exec(`UPDATE tunnels SET routing_group='legacy-group' WHERE id=?`, legacy.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = store.db.Exec(`DROP TABLE tunnel_routing_groups`); err != nil {
		t.Fatal(err)
	}
	if _, err = store.db.Exec(`DROP TABLE routing_groups`); err != nil {
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
	if err != nil || cfg.InterTunnelPolicy != InterTunnelIsolated {
		t.Fatalf("routing policy migration is unsafe: %+v, %v", cfg, err)
	}
	if _, err = store.Tunnels(); err != nil {
		t.Fatalf("routing group migration is incomplete: %v", err)
	}
	legacy, err = store.Tunnel(legacy.ID)
	if err != nil || !legacy.HasRoutingGroup("legacy-group") {
		t.Fatalf("legacy routing membership was not migrated: %+v, %v", legacy, err)
	}
	groups, err := store.RoutingGroups()
	if err != nil || len(groups) != 1 || groups[0].Name != "legacy-group" || groups[0].TunnelCount != 1 {
		t.Fatalf("legacy managed group was not migrated: %+v, %v", groups, err)
	}
	var legacyValue string
	if err = store.db.QueryRow(`SELECT routing_group FROM tunnels WHERE id=?`, legacy.ID).Scan(&legacyValue); err != nil || legacyValue != "" {
		t.Fatalf("legacy migration marker was not cleared: %q, %v", legacyValue, err)
	}
}

func TestExistingTunnelIPv4ModeCanBeEdited(t *testing.T) {
	a, _ := testApp(t)
	tunnel, err := a.CreateTunnel(CreateTunnelInput{Label: "editable", GenerateKeys: true}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = a.SetTunnelV4Mode(tunnel.ID, V4ModeNative, "admin"); err != nil {
		t.Fatal(err)
	}
	tunnel, err = a.store.Tunnel(tunnel.ID)
	if err != nil || tunnel.V4Mode != V4ModeNative || tunnel.V4Address != "10.99.0.1" {
		t.Fatalf("mode edit was not persisted and allocated: %+v, %v", tunnel, err)
	}
	if err = a.SetTunnelV4Mode(tunnel.ID, V4ModeOff, "admin"); err != nil {
		t.Fatal(err)
	}
	tunnel, err = a.store.Tunnel(tunnel.ID)
	if err != nil || tunnel.V4Mode != V4ModeOff || tunnelIPv4Enabled(mustSettings(t, a), mustUpstream(t, a), tunnel) {
		t.Fatalf("disabled mode edit was not applied: %+v, %v", tunnel, err)
	}
	if err = a.SetTunnelV4Mode(tunnel.ID, "invalid", "admin"); err == nil {
		t.Fatal("invalid tunnel IPv4 mode was accepted")
	}
}

func TestResetGeneralSettingsPreservesDeploymentIdentity(t *testing.T) {
	a, _ := testApp(t)
	before := mustUpstream(t, a)
	cfg := mustSettings(t, a)
	cfg.V4NAT = true
	cfg.V4Pool = "10.88.0.0/16"
	cfg.DefaultDNS = "2001:db8::53"
	cfg.InterTunnelPolicy = InterTunnelAny
	if err := a.SaveSettings(cfg); err != nil {
		t.Fatal(err)
	}
	if err := a.ResetGeneralSettings("admin"); err != nil {
		t.Fatal(err)
	}
	reset := mustSettings(t, a)
	if reset.V4NAT || reset.V4Warp || reset.V4Pool != "10.99.0.0/16" || reset.DefaultDNS != "2606:4700:4700::1111" || reset.InterTunnelPolicy != InterTunnelIsolated {
		t.Fatalf("general defaults not restored: %+v", reset)
	}
	// Upstreams describe the deployment, not a preference, so a reset of the
	// global settings must leave every provider connection untouched.
	after := mustUpstream(t, a)
	if after != before {
		t.Fatalf("upstream configuration changed: before=%+v after=%+v", before, after)
	}
}

// A tunnel must be allocated from the upstream that was asked for, and prefixes
// from two upstreams must be able to coexist without colliding.
func TestTunnelsAreAllocatedFromTheSelectedUpstream(t *testing.T) {
	a, kernel := testApp(t)
	primary := mustUpstream(t, a)

	second := testUpstream()
	second.Name = "secondary"
	second.V6CIDR = "2001:db8:9900::/48"
	second.ServerAddress = "2001:db8:9900::1/64"
	second.InterfaceName = "wg-second"
	second.EndpointPort = 51821
	second.EgressInterface = "ppp0"
	secondary, err := a.CreateUpstream(second, "admin")
	if err != nil {
		t.Fatal(err)
	}

	first, err := a.CreateTunnel(CreateTunnelInput{UpstreamID: primary.ID, Label: "on-primary", GenerateKeys: true}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	other, err := a.CreateTunnel(CreateTunnelInput{UpstreamID: secondary.ID, Label: "on-secondary", GenerateKeys: true}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !netip.MustParsePrefix(primary.V6CIDR).Contains(netip.MustParsePrefix(first.V6CIDR).Addr()) {
		t.Fatalf("tunnel was not allocated from its upstream: %s not in %s", first.V6CIDR, primary.V6CIDR)
	}
	if !netip.MustParsePrefix(secondary.V6CIDR).Contains(netip.MustParsePrefix(other.V6CIDR).Addr()) {
		t.Fatalf("tunnel was not allocated from its upstream: %s not in %s", other.V6CIDR, secondary.V6CIDR)
	}
	if first.UpstreamID != primary.ID || other.UpstreamID != secondary.ID {
		t.Fatalf("upstream attachment is wrong: %+v %+v", first, other)
	}
	// Both connections must reach the kernel together, since each owns its own
	// interface and peer table.
	if len(kernel.appliedUpstream) != 2 {
		t.Fatalf("kernel did not receive both upstreams: %+v", kernel.appliedUpstream)
	}
	// Free space is per upstream, so filling one must not affect the other.
	usedPrimary, err := a.store.UsedPrefixes(primary.ID)
	if err != nil || len(usedPrimary) != 1 || usedPrimary[0].String() != first.V6CIDR {
		t.Fatalf("per-upstream allocations leaked: %+v, %v", usedPrimary, err)
	}
}

// With more than one upstream the choice is required, because allocating from
// an arbitrary provider would hand out the wrong address space.
func TestTunnelCreationRequiresAnUpstreamChoiceWhenSeveralExist(t *testing.T) {
	a, _ := testApp(t)
	if _, err := a.CreateTunnel(CreateTunnelInput{Label: "implicit", GenerateKeys: true}, "admin"); err != nil {
		t.Fatalf("a single-upstream deployment should not require a choice: %v", err)
	}
	second := testUpstream()
	second.Name = "secondary"
	second.V6CIDR = "2001:db8:9900::/48"
	second.ServerAddress = "2001:db8:9900::1/64"
	second.InterfaceName = "wg-second"
	second.EndpointPort = 51821
	if _, err := a.CreateUpstream(second, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateTunnel(CreateTunnelInput{Label: "ambiguous", GenerateKeys: true}, "admin"); err == nil {
		t.Fatal("an ambiguous allocation was accepted")
	}
	if _, err := a.CreateTunnel(CreateTunnelInput{UpstreamID: 9999, Label: "missing", GenerateKeys: true}, "admin"); err == nil {
		t.Fatal("a tunnel was allocated from a nonexistent upstream")
	}
}

// Two connections that would fight in the kernel or hand out overlapping space
// must be refused at configuration time rather than diagnosed as drift later.
func TestUpstreamsMustNotCollide(t *testing.T) {
	a, _ := testApp(t)
	base := testUpstream()

	duplicateName := base
	duplicateName.V6CIDR = "2001:db8:9900::/48"
	duplicateName.ServerAddress = "2001:db8:9900::1/64"
	duplicateName.InterfaceName = "wg-other"
	duplicateName.EndpointPort = 51821
	if _, err := a.CreateUpstream(duplicateName, "admin"); err == nil || !strings.Contains(err.Error(), "name") {
		t.Fatalf("a duplicate upstream name was accepted: %v", err)
	}

	duplicateInterface := duplicateName
	duplicateInterface.Name = "second"
	duplicateInterface.InterfaceName = base.InterfaceName
	if _, err := a.CreateUpstream(duplicateInterface, "admin"); err == nil || !strings.Contains(err.Error(), "interface") {
		t.Fatalf("a duplicate WireGuard interface was accepted: %v", err)
	}

	overlapping := duplicateName
	overlapping.Name = "overlapping"
	overlapping.V6CIDR = "2001:db8:1200:8000::/52"
	overlapping.ServerAddress = ""
	if _, err := a.CreateUpstream(overlapping, "admin"); err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Fatalf("an overlapping delegated prefix was accepted: %v", err)
	}

	sameEndpoint := duplicateName
	sameEndpoint.Name = "same-endpoint"
	sameEndpoint.EndpointPort = base.EndpointPort
	if _, err := a.CreateUpstream(sameEndpoint, "admin"); err == nil || !strings.Contains(err.Error(), "listens on") {
		t.Fatalf("a duplicate listening endpoint was accepted: %v", err)
	}

	reserved := duplicateName
	reserved.Name = "reserved"
	reserved.InterfaceName = warpInterfaceName
	if _, err := a.CreateUpstream(reserved, "admin"); err == nil {
		t.Fatal("the WARP interface name was accepted as an upstream interface")
	}
}

// Egressing one upstream through another's tunnel device would install a
// forwarding pair between two managed WireGuard interfaces, letting every
// client of one reach every client of the other while the routing policy still
// reads as isolated.
func TestUpstreamCannotEgressThroughAnotherUpstreamsTunnel(t *testing.T) {
	a, _ := testApp(t)
	primary := mustUpstream(t, a)

	chained := testUpstream()
	chained.Name = "chained"
	chained.V6CIDR = "2001:db8:9900::/48"
	chained.ServerAddress = "2001:db8:9900::1/64"
	chained.InterfaceName = "wg-chained"
	chained.EndpointPort = 51821
	chained.EgressInterface = primary.InterfaceName
	if _, err := a.CreateUpstream(chained, "admin"); err == nil || !strings.Contains(err.Error(), "belongs to upstream") {
		t.Fatalf("an upstream egressing through another's tunnel was accepted: %v", err)
	}

	// The reverse arrangement is the same problem seen from the other side.
	reversed := chained
	reversed.EgressInterface = "ppp0"
	reversed.InterfaceName = primary.EgressInterface
	if _, err := a.CreateUpstream(reversed, "admin"); err == nil {
		t.Fatalf("a WireGuard interface that is another upstream's egress was accepted: %v", err)
	}

	// Chaining through a separate interface remains allowed: an upstream may
	// legitimately ride over a WireGuard tunnel this application does not own.
	external := chained
	external.EgressInterface = "wg-provider"
	if _, err := a.CreateUpstream(external, "admin"); err != nil {
		t.Fatalf("an upstream over an unmanaged tunnel interface was refused: %v", err)
	}
}

// Deleting an upstream must remove its kernel state before its row, because the
// row is what a later reconciliation uses to find that interface again.
func TestUpstreamDeletionKeepsTheRowWhenTeardownFails(t *testing.T) {
	a, kernel := testApp(t)
	upstream := mustUpstream(t, a)
	kernel.removeUpstreamErr = errors.New("synthetic netlink failure")

	if err := a.DeleteUpstream(upstream.ID, "admin"); err == nil {
		t.Fatal("a failed teardown was reported as a successful deletion")
	}
	remaining, err := a.store.Upstreams()
	if err != nil || len(remaining) != 1 {
		t.Fatalf("the upstream row was dropped despite a failed teardown, leaking its interface: %+v, %v", remaining, err)
	}
	// Once the kernel cooperates, the deletion completes normally.
	kernel.removeUpstreamErr = nil
	if err = a.DeleteUpstream(upstream.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if remaining, err = a.store.Upstreams(); err != nil || len(remaining) != 0 {
		t.Fatalf("retrying the deletion did not remove the upstream: %+v, %v", remaining, err)
	}
}

// Deleting an upstream must not silently strand the tunnels allocated from it,
// and must remove its kernel interface once it is genuinely unused.
func TestUpstreamDeletionProtectsExistingTunnels(t *testing.T) {
	a, kernel := testApp(t)
	upstream := mustUpstream(t, a)
	tunnel, err := a.CreateTunnel(CreateTunnelInput{Label: "held", GenerateKeys: true}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = a.DeleteUpstream(upstream.ID, "admin"); err == nil {
		t.Fatal("an upstream with tunnels was deleted")
	}
	if err = a.DeleteTunnel(tunnel.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if err = a.DeleteUpstream(upstream.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if len(kernel.removedUpstream) != 1 || kernel.removedUpstream[0] != upstream.InterfaceName {
		t.Fatalf("the upstream interface was not torn down: %+v", kernel.removedUpstream)
	}
	remaining, err := a.store.Upstreams()
	if err != nil || len(remaining) != 0 {
		t.Fatalf("upstream was not deleted: %+v, %v", remaining, err)
	}
	// Removing the last upstream must still reach the kernel with an empty
	// desired state, or its forwarding and NAT rules would stay installed with
	// nothing left to authorize them.
	if len(kernel.appliedUpstream) != 0 || len(kernel.applied) != 0 {
		t.Fatalf("the empty desired state was not applied: upstreams=%+v tunnels=%+v", kernel.appliedUpstream, kernel.applied)
	}
}

// Editing an upstream must never orphan an allocation that clients already use.
func TestUpstreamEditCannotOrphanAllocations(t *testing.T) {
	a, _ := testApp(t)
	upstream := mustUpstream(t, a)
	if _, err := a.CreateTunnel(CreateTunnelInput{Label: "existing", GenerateKeys: true}, "admin"); err != nil {
		t.Fatal(err)
	}
	moved := testUpstream()
	moved.ID = upstream.ID
	moved.V6CIDR = "2001:db8:4400::/48"
	moved.ServerAddress = "2001:db8:4400::1/64"
	if _, err := a.UpdateUpstream(moved, "admin"); err == nil || !strings.Contains(err.Error(), "outside the new delegated prefix") {
		t.Fatalf("renumbering an upstream under a live tunnel was accepted: %v", err)
	}
	// A harmless edit on the same prefix must still be applied.
	renamed := testUpstream()
	renamed.ID = upstream.ID
	renamed.Name = "renamed"
	if _, err := a.UpdateUpstream(renamed, "admin"); err != nil {
		t.Fatalf("a safe upstream edit was refused: %v", err)
	}
	if got := mustUpstream(t, a); got.Name != "renamed" || got.ServerPrivateKey != upstream.ServerPrivateKey {
		t.Fatalf("edit did not preserve upstream identity: %+v", got)
	}
}

// TestLegacySingleUpstreamIsMigratedIntoAnUpstreamRow recreates a database
// written before multiple upstreams existed and checks that an upgrade keeps the
// running deployment exactly as it was: same prefix, same keys, same interface,
// with every existing tunnel still attached to it.
func TestLegacySingleUpstreamIsMigratedIntoAnUpstreamRow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	// Rebuild the pre-upstream settings schema, including the delegation
	// columns, and drop the new table entirely.
	for _, statement := range legacySettingsSchema(true) {
		if _, err = store.db.Exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	if _, err = store.db.Exec(`INSERT INTO tunnels(upstream_id,label,public_key,allocated_v6_cidr,quota_gib,quota_period,enabled,created_at,updated_at) VALUES(0,'legacy','legacy-key','2001:db8:1200:100::/56',100,'2026-08',1,'2026-08-01T00:00:00Z','2026-08-01T00:00:00Z')`); err != nil {
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
	upstreams, err := store.Upstreams()
	if err != nil || len(upstreams) != 1 {
		t.Fatalf("legacy upstream was not migrated: %+v, %v", upstreams, err)
	}
	migrated := upstreams[0]
	if migrated.V6CIDR != "2001:db8:1200::/48" || migrated.ServerAddress != "2001:db8:1200::1/64" || migrated.ServerPrivateKey != "legacy-private-key" {
		t.Fatalf("migration changed the delegated addressing or key: %+v", migrated)
	}
	if migrated.InterfaceName != "wg-legacy" || migrated.EgressInterface != "ppp0" || migrated.EndpointHost != "legacy.example.test" || migrated.EndpointPort != 51999 {
		t.Fatalf("migration changed the deployment's interfaces or endpoint: %+v", migrated)
	}
	if migrated.Mode != UpstreamRouted || migrated.MinPrefix != 48 || migrated.MaxPrefix != 64 || migrated.DefaultPrefix != 56 {
		t.Fatalf("migration changed delegation behavior: %+v", migrated)
	}
	if migrated.TunnelCount != 1 {
		t.Fatalf("existing tunnels were not attached to the migrated upstream: %+v", migrated)
	}
	tunnels, err := store.TunnelsForUpstream(migrated.ID)
	if err != nil || len(tunnels) != 1 || tunnels[0].V6CIDR != "2001:db8:1200:100::/56" {
		t.Fatalf("existing allocation was disturbed: %+v, %v", tunnels, err)
	}
	// A second open must be idempotent rather than duplicating the upstream.
	if err = store.migrateLegacyUpstream(); err != nil {
		t.Fatal(err)
	}
	if again, _ := store.Upstreams(); len(again) != 1 {
		t.Fatalf("migration ran twice: %+v", again)
	}
}

// legacySettingsSchema rebuilds the pre-upstream settings columns. onLink adds
// the delegation columns, which only exist in databases written after on-link
// support landed; a database older than that must migrate just as safely.
func legacySettingsSchema(onLink bool) []string {
	statements := []string{
		`DROP TABLE upstreams`,
		`ALTER TABLE settings ADD COLUMN upstream_v6 TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE settings ADD COLUMN upstream_v4 TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE settings ADD COLUMN endpoint_host TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE settings ADD COLUMN endpoint_port INTEGER NOT NULL DEFAULT 51820`,
		`ALTER TABLE settings ADD COLUMN interface_name TEXT NOT NULL DEFAULT 'wg0'`,
		`ALTER TABLE settings ADD COLUMN server_address TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE settings ADD COLUMN server_private_key TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE settings ADD COLUMN mtu INTEGER NOT NULL DEFAULT 1420`,
		`ALTER TABLE settings ADD COLUMN keepalive INTEGER NOT NULL DEFAULT 25`,
		`ALTER TABLE settings ADD COLUMN min_prefix INTEGER NOT NULL DEFAULT 48`,
		`ALTER TABLE settings ADD COLUMN max_prefix INTEGER NOT NULL DEFAULT 64`,
		`ALTER TABLE settings ADD COLUMN default_prefix INTEGER NOT NULL DEFAULT 56`,
		`ALTER TABLE settings ADD COLUMN upstream_interface TEXT NOT NULL DEFAULT 'ppp0'`,
	}
	if onLink {
		statements = append(statements,
			`ALTER TABLE settings ADD COLUMN upstream_mode TEXT NOT NULL DEFAULT 'routed'`,
			`ALTER TABLE settings ADD COLUMN transport_address TEXT NOT NULL DEFAULT ''`)
	}
	return append(statements, `UPDATE settings SET upstream_v6='2001:db8:1200::/48',server_address='2001:db8:1200::1/64',server_private_key='legacy-private-key',endpoint_host='legacy.example.test',endpoint_port=51999,interface_name='wg-legacy',upstream_interface='ppp0',min_prefix=48,max_prefix=64,default_prefix=56 WHERE id=1`)
}

// A database written before delegation modes existed has no upstream_mode or
// transport_address column at all. Reading them unconditionally would fail and
// silently leave the deployment with no upstream, orphaning every tunnel.
func TestUpstreamMigrationHandlesDatabasesPredatingDelegationModes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ancient.db")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range legacySettingsSchema(false) {
		if _, err = store.db.Exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	if _, err = store.db.Exec(`INSERT INTO tunnels(upstream_id,label,public_key,allocated_v6_cidr,quota_gib,quota_period,enabled,created_at,updated_at) VALUES(0,'ancient','ancient-key','2001:db8:1200:700::/56',100,'2026-08',1,'2026-08-01T00:00:00Z','2026-08-01T00:00:00Z')`); err != nil {
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
	upstreams, err := store.Upstreams()
	if err != nil || len(upstreams) != 1 {
		t.Fatalf("a database predating delegation modes lost its upstream: %+v, %v", upstreams, err)
	}
	migrated := upstreams[0]
	// Such a database can only have been routed, and must not acquire a
	// transport address it never had.
	if migrated.Mode != UpstreamRouted || migrated.TransportAddress != "" {
		t.Fatalf("migration invented a delegation configuration: %+v", migrated)
	}
	if migrated.V6CIDR != "2001:db8:1200::/48" || migrated.ServerPrivateKey != "legacy-private-key" || migrated.InterfaceName != "wg-legacy" {
		t.Fatalf("migration disturbed the deployment: %+v", migrated)
	}
	if migrated.TunnelCount != 1 {
		t.Fatalf("the existing tunnel was orphaned: %+v", migrated)
	}
}

func mustSettings(t *testing.T, a *App) Settings {
	t.Helper()
	cfg, err := a.store.Settings()
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
func containsAll(s string, values ...string) bool {
	for _, value := range values {
		if !strings.Contains(s, value) {
			return false
		}
	}
	return true
}
