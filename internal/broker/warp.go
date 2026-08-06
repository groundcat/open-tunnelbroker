package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const defaultWarpAPIURL = "https://api.cloudflareclient.com/v0a737/reg"

type warpRegisterRequest struct {
	Key         string `json:"key"`
	InstallID   string `json:"install_id"`
	WarpEnabled bool   `json:"warp_enabled"`
	TOS         string `json:"tos"`
	Type        string `json:"type"`
	Locale      string `json:"locale"`
}

type warpRegisterResponse struct {
	ID      string `json:"id"`
	Created string `json:"created"`
	Account struct {
		ID          string `json:"id"`
		AccountType string `json:"account_type"`
		WarpPlus    bool   `json:"warp_plus"`
	} `json:"account"`
	Config struct {
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
			} `json:"addresses"`
		} `json:"interface"`
		Peers []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				Host string `json:"host"`
			} `json:"endpoint"`
		} `json:"peers"`
	} `json:"config"`
}

func (a *App) RegisterWarp(ctx context.Context, admin string) (WarpAccount, error) {
	a.warpMu.Lock()
	defer a.warpMu.Unlock()
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return WarpAccount{}, err
	}
	payload, err := json.Marshal(warpRegisterRequest{Key: privateKey.PublicKey().String(), InstallID: "", WarpEnabled: true, TOS: time.Now().UTC().Format("2006-01-02T15:04:05.000-07:00"), Type: "Linux", Locale: "en_US"})
	if err != nil {
		return WarpAccount{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.warpAPIURL, bytes.NewReader(payload))
	if err != nil {
		return WarpAccount{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "open-tunnelbroker/1")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return WarpAccount{}, fmt.Errorf("WARP registration: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return WarpAccount{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return WarpAccount{}, fmt.Errorf("WARP registration returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var registered warpRegisterResponse
	if err = json.Unmarshal(body, &registered); err != nil {
		return WarpAccount{}, fmt.Errorf("WARP registration response: %w", err)
	}
	if len(registered.Config.Peers) == 0 {
		return WarpAccount{}, errors.New("WARP registration response has no peer")
	}
	peer := registered.Config.Peers[0]
	if _, err = wgtypes.ParseKey(peer.PublicKey); err != nil {
		return WarpAccount{}, fmt.Errorf("WARP peer key: %w", err)
	}
	ipv4 := strings.TrimSpace(registered.Config.Interface.Addresses.V4)
	if prefix, parseErr := netip.ParsePrefix(ipv4); parseErr == nil {
		ipv4 = prefix.Addr().String()
	}
	address, err := netip.ParseAddr(ipv4)
	if err != nil || !address.Is4() {
		return WarpAccount{}, errors.New("WARP registration response has no valid IPv4 address")
	}
	if strings.TrimSpace(peer.Endpoint.Host) == "" {
		return WarpAccount{}, errors.New("WARP registration response has no endpoint")
	}
	created, _ := time.Parse(time.RFC3339Nano, registered.Created)
	if created.IsZero() {
		created = time.Now().UTC()
	}
	accountType := registered.Account.AccountType
	if registered.Account.WarpPlus {
		accountType = "WARP+ " + accountType
	}
	account := WarpAccount{PrivateKey: privateKey.String(), PeerPublicKey: peer.PublicKey, IPv4Address: address.String(), Endpoint: peer.Endpoint.Host, DeviceID: registered.ID, AccountID: registered.Account.ID, AccountType: strings.TrimSpace(accountType), CreatedAt: created}
	if err = a.store.SaveWarpAccount(account); err != nil {
		return WarpAccount{}, err
	}
	_ = a.store.AddAudit(admin, "warp-register", "device "+account.DeviceID)
	cfg, err := a.store.Settings()
	if err != nil {
		return account, err
	}
	if cfg.V4Warp {
		if err = a.Reconcile(ctx); err != nil {
			return account, fmt.Errorf("WARP account saved but apply failed: %w", err)
		}
	}
	return account, nil
}

func (a *App) TestWarp(ctx context.Context, admin string) (string, error) {
	a.warpMu.Lock()
	defer a.warpMu.Unlock()
	a.mu.Lock()
	defer a.mu.Unlock()
	cfg, err := a.store.Settings()
	if err != nil {
		return "", err
	}
	if !cfg.V4Warp {
		return "", errors.New("Cloudflare WARP IPv4 egress is not enabled")
	}
	account, err := a.store.WarpAccount()
	if err != nil {
		return "", err
	}
	if !account.Exists() {
		return "", errors.New("no Cloudflare WARP account exists")
	}
	trace, err := a.kernel.TestWarp(ctx, cfg, account)
	if err != nil {
		return "", err
	}
	if err = a.store.SaveWarpTest(trace, time.Now().UTC()); err != nil {
		return "", err
	}
	_ = a.store.AddAudit(admin, "warp-test", firstTraceValue(trace, "ip"))
	return trace, nil
}

func firstTraceValue(trace, key string) string {
	for _, line := range strings.Split(trace, "\n") {
		if value, ok := strings.CutPrefix(line, key+"="); ok {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
