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
)

type fakeKernel struct {
	applyErr error
	applied  []Tunnel
}

func (f *fakeKernel) Apply(_ context.Context, _ Settings, _ WarpAccount, tunnels []Tunnel) ([]Tunnel, error) {
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
	if cfg := a.ClientConfig(tunnel, mustSettings(t, a)); !containsAll(cfg, "Address = 2001:db8:1200:100::1/56", "Endpoint = broker.example.test:51820") {
		t.Fatalf("bad client config: %s", cfg)
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
