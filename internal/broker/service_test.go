package broker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
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
	if tunnel.V6CIDR != "2001:db8:1200:100::/56" || tunnel.Status != "applied" {
		t.Fatalf("unexpected tunnel: %+v", tunnel)
	}
	if len(kernel.applied) != 1 || kernel.applied[0].ID != tunnel.ID {
		t.Fatal("kernel did not receive persisted tunnel")
	}
	if tunnel.QuotaGiB != 100 || tunnel.QuotaPeriod != quotaMonth(time.Now()) {
		t.Fatalf("unexpected default monthly quota: %+v", tunnel)
	}
	if cfg := a.ClientConfig(tunnel, mustSettings(t, a)); !containsAll(cfg, "Address = 2001:db8:1200:100::1/56", "Endpoint = broker.example.test:51820") {
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
	newRecorder := httptest.NewRecorder()
	a.render(newRecorder, "new", view{Title: "New tunnel", Settings: mustSettings(t, a), Prefixes: []int{56}})
	if body := newRecorder.Body.String(); !containsAll(body, `name="quota_gib"`, `value="100"`, "Monthly upload + download quota") {
		t.Fatalf("new tunnel quota field is missing: %s", body)
	}

	detailRecorder := httptest.NewRecorder()
	a.render(detailRecorder, "detail", view{Title: "Tunnel", Tunnel: Tunnel{ID: 1, V6CIDR: "2001:db8::/64", QuotaGiB: 250, QuotaPeriod: "2026-08"}, EffectiveV4Mode: V4ModeOff})
	if body := detailRecorder.Body.String(); !containsAll(body, `name="quota_gib"`, `value="250"`, "Monthly traffic:", "2026-08") {
		t.Fatalf("edit tunnel quota field is missing: %s", body)
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
