package broker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestRegisterWarpPersistsValidatedAccount(t *testing.T) {
	a, _ := testApp(t)
	peer, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected request: %s %s", r.Method, r.Header.Get("Content-Type"))
		}
		var request warpRegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		if request.Key == "" || !request.WarpEnabled || request.Type != "Linux" {
			t.Errorf("bad registration payload: %+v", request)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"device-1","created":"2026-08-06T08:00:00Z","account":{"id":"account-1","account_type":"free","warp_plus":false},"config":{"interface":{"addresses":{"v4":"172.16.0.2"}},"peers":[{"public_key":"` + peer.PublicKey().String() + `","endpoint":{"host":"engage.cloudflareclient.com:2408"}}]}}`))
	}))
	defer server.Close()
	a.warpAPIURL = server.URL
	a.httpClient = server.Client()

	account, err := a.RegisterWarp(context.Background(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !account.Exists() || account.IPv4Address != "172.16.0.2" || account.AccountID != "account-1" {
		t.Fatalf("unexpected account: %+v", account)
	}
	stored, err := a.store.WarpAccount()
	if err != nil || stored.PrivateKey != account.PrivateKey || stored.PeerPublicKey != account.PeerPublicKey {
		t.Fatalf("account was not persisted: %+v, %v", stored, err)
	}
}

func TestIPv4EgressModesAreExclusiveAndWarpNeedsAccount(t *testing.T) {
	a, _ := testApp(t)
	cfg := mustSettings(t, a)
	cfg.V4NAT, cfg.V4Warp = true, true
	if err := a.SaveSettings(cfg); err == nil || !strings.Contains(err.Error(), "cannot be enabled together") {
		t.Fatalf("expected exclusive mode error, got %v", err)
	}
	cfg.V4NAT, cfg.V4Warp = false, true
	if err := a.SaveSettings(cfg); err == nil || !strings.Contains(err.Error(), "create a Cloudflare WARP account") {
		t.Fatalf("expected missing account error, got %v", err)
	}
	if _, err := a.CreateTunnel(CreateTunnelInput{Label: "warp", V4Mode: V4ModeWarp, GenerateKeys: true}, "admin"); err == nil || !strings.Contains(err.Error(), "create a Cloudflare WARP account") {
		t.Fatalf("expected tunnel override missing account error, got %v", err)
	}
}

func TestWarpTraceIsPersisted(t *testing.T) {
	a, _ := testApp(t)
	key, _ := wgtypes.GeneratePrivateKey()
	peer, _ := wgtypes.GeneratePrivateKey()
	account := WarpAccount{PrivateKey: key.String(), PeerPublicKey: peer.PublicKey().String(), IPv4Address: "172.16.0.2", Endpoint: "engage.cloudflareclient.com:2408", CreatedAt: time.Now().UTC()}
	if err := a.store.SaveWarpAccount(account); err != nil {
		t.Fatal(err)
	}
	cfg := mustSettings(t, a)
	cfg.V4Warp = true
	if err := a.SaveSettings(cfg); err != nil {
		t.Fatal(err)
	}
	trace, err := a.TestWarp(context.Background(), "admin")
	if err != nil || !strings.Contains(trace, "ip=203.0.113.8") {
		t.Fatalf("unexpected trace: %q, %v", trace, err)
	}
	stored, err := a.store.WarpAccount()
	if err != nil || stored.LastTrace != trace || stored.LastTestAt.IsZero() {
		t.Fatalf("trace was not persisted: %+v, %v", stored, err)
	}
}
