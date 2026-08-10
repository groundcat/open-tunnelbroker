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
	applyErr error
	applied  []Tunnel
	traffic  map[int64][2]int64
	applyN   int
	closed   bool
}

func (f *fakeKernel) Apply(_ context.Context, _ Settings, _ WarpAccount, tunnels []Tunnel) ([]Tunnel, error) {
	f.applyN++
	for i := range tunnels {
		if counters, ok := f.traffic[tunnels[i].ID]; ok {
			tunnels[i].RXBytes = counters[0]
			tunnels[i].TXBytes = counters[1]
		}
	}
	f.applied = append([]Tunnel(nil), tunnels...)
	return tunnels, f.applyErr
}
func (f *fakeKernel) Inspect(_ Settings, _ WarpAccount, _ []Tunnel) ([]string, error) {
	return nil, nil
}
func (f *fakeKernel) Remove(_ Settings, _ Tunnel) error { return nil }
func (f *fakeKernel) Close() error                      { f.closed = true; return nil }
func (f *fakeKernel) TestWarp(_ context.Context, _ Settings, _ WarpAccount) (string, error) {
	return "fl=1\nip=203.0.113.8\nwarp=on\n", nil
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
	err = a.SaveSettings(Settings{UpstreamV6: "2001:db8:1200::/48", V4Pool: "10.99.0.0/16", DefaultDNS: "2606:4700:4700::1111", EndpointHost: "broker.example.test", EndpointPort: 51820, InterfaceName: "wg-test", ServerAddress: "2001:db8:1200::1/64", MTU: 1420, Keepalive: 25, MinPrefix: 56, MaxPrefix: 64, DefaultPrefix: 56, UpstreamInterface: "eth0"})
	if err != nil {
		t.Fatal(err)
	}
	return a, f
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
	if cfg := a.ClientConfig(tunnel, mustSettings(t, a)); !containsAll(cfg, expectedAddress, "Endpoint = broker.example.test:51820") {
		t.Fatalf("bad client config: %s", cfg)
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
	newRecorder := httptest.NewRecorder()
	a.render(newRecorder, "new", view{Title: "New tunnel", Settings: mustSettings(t, a), Prefixes: []int{56}, RoutingGroups: managed})
	if body := newRecorder.Body.String(); !containsAll(body, `name="quota_gib"`, `value="100"`, `name="routing_groups"`, `multiple`, "Monthly upload + download quota") {
		t.Fatalf("new tunnel quota field is missing: %s", body)
	}

	detailRecorder := httptest.NewRecorder()
	a.render(detailRecorder, "detail", view{Title: "Tunnel", Tunnel: Tunnel{ID: 1, V6CIDR: "2001:db8::/64", QuotaGiB: 250, QuotaPeriod: "2026-08", RoutingGroups: []string{"internal"}}, RoutingGroups: managed, EffectiveV4Mode: V4ModeOff})
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
	cfg := mustSettings(t, a)
	cfg.EndpointHost = "2001:db8::10"
	tunnel := Tunnel{V6CIDR: "2001:db8:1200::9/128", PresharedKey: "test"}
	generated := a.ClientConfig(tunnel, cfg)
	if !containsAll(generated, "Address = 2001:db8:1200::9/128", "Endpoint = [2001:db8::10]:51820") {
		t.Fatalf("bad client config: %s", generated)
	}
}

func TestClientConfigGlobalNATToggleControlsIPv4(t *testing.T) {
	a, _ := testApp(t)
	cfg := mustSettings(t, a)
	tunnel := Tunnel{V6CIDR: "2001:db8:1200:100::/56", V4Enabled: true, V4Address: "10.99.0.2"}

	cfg.V4NAT = false
	v6Only := a.ClientConfig(tunnel, cfg)
	if strings.Contains(v6Only, "10.99.0.2") || strings.Contains(v6Only, "0.0.0.0/0") || !strings.Contains(v6Only, "AllowedIPs = ::/0") {
		t.Fatalf("IPv4 leaked into config while global NAT was disabled: %s", v6Only)
	}

	cfg.V4NAT = true
	dualStack := a.ClientConfig(tunnel, cfg)
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

	native, err := a.CreateTunnel(CreateTunnelInput{Label: "native", V4Mode: V4ModeNative, GenerateKeys: true}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if native.V4Mode != V4ModeNative || native.V4Address != "10.99.0.1" || !tunnelIPv4Enabled(cfg, native) {
		t.Fatalf("native override was not applied: %+v", native)
	}
	if current := mustSettings(t, a); current.V4NAT || current.V4Warp {
		t.Fatalf("tunnel override changed global mode: %+v", current)
	}
	if generated := a.ClientConfig(native, cfg); !containsAll(generated, "10.99.0.1/32", "AllowedIPs = 0.0.0.0/0, ::/0") {
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
	if disabled.V4Address != "" || tunnelIPv4Enabled(cfg, disabled) {
		t.Fatalf("disabled override inherited global native mode: %+v", disabled)
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
	legacy := Tunnel{Label: "legacy", PublicKey: "legacy-key", PresharedKey: "legacy-psk", V6CIDR: "2001:db8::/64", QuotaGiB: 100, QuotaPeriod: "2026-08", Enabled: true}
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
	if err != nil || tunnel.V4Mode != V4ModeOff || tunnelIPv4Enabled(mustSettings(t, a), tunnel) {
		t.Fatalf("disabled mode edit was not applied: %+v, %v", tunnel, err)
	}
	if err = a.SetTunnelV4Mode(tunnel.ID, "invalid", "admin"); err == nil {
		t.Fatal("invalid tunnel IPv4 mode was accepted")
	}
}

func TestResetGeneralSettingsPreservesDeploymentIdentity(t *testing.T) {
	a, _ := testApp(t)
	cfg := mustSettings(t, a)
	cfg.V4NAT = true
	cfg.V4Pool = "10.88.0.0/16"
	cfg.DefaultDNS = "2001:db8::53"
	cfg.EndpointPort = 12345
	cfg.MTU = 1280
	cfg.Keepalive = 9
	cfg.MinPrefix, cfg.MaxPrefix, cfg.DefaultPrefix = 60, 72, 64
	if err := a.SaveSettings(cfg); err != nil {
		t.Fatal(err)
	}
	if err := a.ResetGeneralSettings("admin"); err != nil {
		t.Fatal(err)
	}
	reset := mustSettings(t, a)
	if reset.V4NAT || reset.V4Warp || reset.V4Pool != "10.99.0.0/16" || reset.DefaultDNS != "2606:4700:4700::1111" || reset.EndpointPort != 51820 || reset.MTU != 1420 || reset.Keepalive != 25 || reset.MinPrefix != 48 || reset.DefaultPrefix != 56 || reset.MaxPrefix != 64 {
		t.Fatalf("general defaults not restored: %+v", reset)
	}
	if reset.UpstreamV6 != cfg.UpstreamV6 || reset.EndpointHost != cfg.EndpointHost || reset.ServerAddress != cfg.ServerAddress || reset.ServerPrivateKey != cfg.ServerPrivateKey || reset.UpstreamInterface != cfg.UpstreamInterface || reset.InterfaceName != cfg.InterfaceName {
		t.Fatalf("deployment identity changed: before=%+v after=%+v", cfg, reset)
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
