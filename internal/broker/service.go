package broker

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type App struct {
	store      *Store
	kernel     Kernel
	logger     *log.Logger
	mu         sync.Mutex
	warpMu     sync.Mutex
	health     Health
	sessions   map[string]session
	httpClient *http.Client
	warpAPIURL string
	upgrader   Upgrader
}
type session struct {
	Username, CSRF string
	Expires        time.Time
}

func New(path string, dry bool, logger *log.Logger) (*App, error) {
	s, e := OpenStore(path)
	if e != nil {
		return nil, e
	}
	return &App{store: s, kernel: &LinuxKernel{DryRun: dry}, logger: logger, sessions: map[string]session{}, httpClient: &http.Client{Timeout: 20 * time.Second}, warpAPIURL: defaultWarpAPIURL, upgrader: NewSystemUpgrader()}, nil
}
func (a *App) Close() error { return a.store.Close() }
func (a *App) BootstrapAdmin(user, password string) error {
	n, e := a.store.AdminCount()
	if e != nil {
		return e
	}
	if n > 0 {
		return nil
	}
	if user == "" || password == "" {
		return errors.New("no admin exists: set OTB_ADMIN_PASSWORD for first start")
	}
	if len(password) < 12 {
		return errors.New("bootstrap admin password must be at least 12 characters")
	}
	h, e := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if e != nil {
		return e
	}
	return a.store.AddAdmin(user, h)
}
func (a *App) Authenticate(user, password string) bool {
	h, e := a.store.AdminHash(user)
	return e == nil && bcrypt.CompareHashAndPassword(h, []byte(password)) == nil
}
func token() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (a *App) SaveSettings(v Settings) error {
	if v.InterTunnelPolicy == "" {
		v.InterTunnelPolicy = InterTunnelIsolated
	}
	if e := validateSettings(v); e != nil {
		return e
	}
	if v.V4Warp {
		account, e := a.store.WarpAccount()
		if e != nil {
			return e
		}
		if !account.Exists() {
			return errors.New("create a Cloudflare WARP account before enabling WARP IPv4 egress")
		}
	}
	if v.ServerPrivateKey == "" {
		k, e := wgtypes.GeneratePrivateKey()
		if e != nil {
			return e
		}
		v.ServerPrivateKey = k.String()
	}
	return a.store.SaveSettings(v)
}

func (a *App) ResetGeneralSettings(admin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	cfg, err := a.store.Settings()
	if err != nil {
		return err
	}
	upstream, err := netip.ParsePrefix(cfg.UpstreamV6)
	if err != nil {
		return err
	}
	minPrefix := max(upstream.Bits(), 48)
	maxPrefix := max(minPrefix, 64)
	defaultPrefix := min(max(56, minPrefix), maxPrefix)
	cfg.V4NAT = false
	cfg.V4Warp = false
	cfg.V4Pool = "10.99.0.0/16"
	cfg.DefaultDNS = "2606:4700:4700::1111"
	cfg.EndpointPort = 51820
	cfg.MTU = 1420
	cfg.Keepalive = 25
	cfg.MinPrefix = minPrefix
	cfg.MaxPrefix = maxPrefix
	cfg.DefaultPrefix = defaultPrefix
	cfg.InterTunnelPolicy = InterTunnelIsolated
	if err = a.store.SaveSettings(cfg); err != nil {
		return err
	}
	_ = a.store.AddAudit(admin, "settings-reset", "general defaults restored")
	return a.reconcileLocked(context.Background())
}
func validateSettings(v Settings) error {
	p, e := netip.ParsePrefix(v.UpstreamV6)
	if e != nil || !p.Addr().Is6() {
		return errors.New("upstream IPv6 must be an IPv6 CIDR")
	}
	if v.MinPrefix < p.Bits() || v.MaxPrefix < v.MinPrefix || v.MaxPrefix > 128 || v.DefaultPrefix < v.MinPrefix || v.DefaultPrefix > v.MaxPrefix {
		return errors.New("prefix limits must satisfy upstream <= min <= default <= max <= 128")
	}
	if v.EndpointHost == "" {
		return errors.New("endpoint hostname or address is required")
	}
	if v.UpstreamInterface == "" {
		return errors.New("upstream interface is required")
	}
	if v.InterfaceName == warpInterfaceName {
		return errors.New("primary WireGuard interface name is reserved for Cloudflare WARP")
	}
	if v.EndpointPort < 1 || v.EndpointPort > 65535 {
		return errors.New("invalid endpoint port")
	}
	if v.ServerAddress != "" {
		s, e := netip.ParsePrefix(v.ServerAddress)
		if e != nil || !p.Contains(s.Addr()) {
			return errors.New("server address must be a CIDR within the upstream prefix")
		}
	}
	if v.V4NAT && v.V4Warp {
		return errors.New("native IPv4 NAT and Cloudflare WARP IPv4 egress cannot be enabled together")
	}
	if v.V4NAT || v.V4Warp {
		q, e := netip.ParsePrefix(v.V4Pool)
		if e != nil || !q.Addr().Is4() {
			return errors.New("v4 pool must be an IPv4 CIDR")
		}
	}
	if !validInterTunnelPolicy(v.InterTunnelPolicy) {
		return errors.New("invalid inter-tunnel routing policy")
	}
	return nil
}

func validInterTunnelPolicy(policy string) bool {
	return policy == InterTunnelIsolated || policy == InterTunnelGroups || policy == InterTunnelAny
}

func validateRoutingGroup(group string) error {
	if utf8.RuneCountInString(group) > 64 {
		return errors.New("routing group must be at most 64 characters")
	}
	for _, character := range group {
		if unicode.IsControl(character) {
			return errors.New("routing group cannot contain control characters")
		}
	}
	return nil
}

func normalizeRoutingGroups(groups []string) ([]string, error) {
	unique := make(map[string]bool, len(groups))
	for _, group := range groups {
		group = strings.TrimSpace(group)
		if group == "" {
			continue
		}
		if err := validateRoutingGroup(group); err != nil {
			return nil, err
		}
		unique[group] = true
	}
	normalized := make([]string, 0, len(unique))
	for group := range unique {
		normalized = append(normalized, group)
	}
	sort.Strings(normalized)
	return normalized, nil
}

type CreateTunnelInput struct {
	Label, PublicKey, DNS string
	V4Mode                string
	RoutingGroups         []string
	Prefix                int
	QuotaGiB              int64
	GenerateKeys          bool
}

func (a *App) CreateTunnel(in CreateTunnelInput, admin string) (Tunnel, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	cfg, e := a.store.Settings()
	if e != nil {
		return Tunnel{}, e
	}
	if e = validateSettings(cfg); e != nil {
		return Tunnel{}, e
	}
	if strings.TrimSpace(in.Label) == "" {
		return Tunnel{}, errors.New("label is required")
	}
	if !validTunnelV4Mode(in.V4Mode) {
		return Tunnel{}, errors.New("invalid IPv4 egress mode")
	}
	if in.QuotaGiB == 0 {
		in.QuotaGiB = 100
	}
	if err := validateQuota(in.QuotaGiB); err != nil {
		return Tunnel{}, err
	}
	in.RoutingGroups, e = normalizeRoutingGroups(in.RoutingGroups)
	if e != nil {
		return Tunnel{}, e
	}
	if in.V4Mode == V4ModeWarp {
		account, accountErr := a.store.WarpAccount()
		if accountErr != nil {
			return Tunnel{}, accountErr
		}
		if !account.Exists() {
			return Tunnel{}, errors.New("create a Cloudflare WARP account before selecting WARP IPv4 egress")
		}
	}
	if in.Prefix == 0 {
		in.Prefix = cfg.DefaultPrefix
	}
	if in.Prefix < cfg.MinPrefix || in.Prefix > cfg.MaxPrefix {
		return Tunnel{}, errors.New("requested prefix is outside configured limits")
	}
	used, e := a.store.UsedPrefixes()
	if e != nil {
		return Tunnel{}, e
	}
	if cfg.ServerAddress != "" {
		s := netip.MustParsePrefix(cfg.ServerAddress)
		reserveBits := cfg.MaxPrefix
		if s.Bits() < reserveBits {
			s = netip.PrefixFrom(s.Addr(), reserveBits).Masked()
		}
		used = append(used, s)
	}
	pool := netip.MustParsePrefix(cfg.UpstreamV6)
	alloc, e := Allocate(pool, used, in.Prefix)
	if e != nil {
		return Tunnel{}, e
	}
	t := Tunnel{Label: strings.TrimSpace(in.Label), PublicKey: strings.TrimSpace(in.PublicKey), V6CIDR: alloc.String(), DNSOverride: strings.TrimSpace(in.DNS), V4Mode: in.V4Mode, QuotaGiB: in.QuotaGiB, QuotaPeriod: quotaMonth(time.Now()), RoutingGroups: in.RoutingGroups, Enabled: true}
	t.V4Enabled = tunnelV4Mode(cfg, t) != V4ModeOff
	if in.GenerateKeys {
		priv, e := wgtypes.GeneratePrivateKey()
		if e != nil {
			return t, e
		}
		t.PrivateKey = priv.String()
		t.PublicKey = priv.PublicKey().String()
	} else if _, e = wgtypes.ParseKey(t.PublicKey); e != nil {
		return t, errors.New("a valid WireGuard public key is required")
	}
	psk, e := wgtypes.GenerateKey()
	if e != nil {
		return t, e
	}
	t.PresharedKey = psk.String()
	if t.V4Enabled {
		t.V4Address, e = a.store.NextV4(netip.MustParsePrefix(cfg.V4Pool))
		if e != nil {
			return t, e
		}
	}
	if e = a.store.InsertTunnel(&t, admin); e != nil {
		return t, e
	}
	if e = a.reconcileLocked(context.Background()); e != nil {
		return t, fmt.Errorf("tunnel saved but apply failed: %w", e)
	}
	return a.store.Tunnel(t.ID)
}
func (a *App) SetTunnelV4Mode(id int64, mode, admin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !validTunnelV4Mode(mode) {
		return errors.New("invalid IPv4 egress mode")
	}
	if _, err := a.store.Tunnel(id); err != nil {
		return err
	}
	if mode == V4ModeWarp {
		account, err := a.store.WarpAccount()
		if err != nil {
			return err
		}
		if !account.Exists() {
			return errors.New("create a Cloudflare WARP account before selecting WARP IPv4 egress")
		}
	}
	if err := a.store.SetTunnelV4Mode(id, mode, admin); err != nil {
		return err
	}
	return a.reconcileLocked(context.Background())
}
func validateQuota(quotaGiB int64) error {
	if quotaGiB < 1 || quotaGiB > (1<<33)-1 {
		return errors.New("monthly quota must be between 1 and 8589934591 GiB")
	}
	return nil
}
func (a *App) SetTunnelQuota(id, quotaGiB int64, admin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := validateQuota(quotaGiB); err != nil {
		return err
	}
	if _, err := a.store.Tunnel(id); err != nil {
		return err
	}
	if err := a.store.SetTunnelQuota(id, quotaGiB, admin); err != nil {
		return err
	}
	return a.reconcileLocked(context.Background())
}
func (a *App) SetTunnelRoutingGroups(id int64, groups []string, admin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	groups, err := normalizeRoutingGroups(groups)
	if err != nil {
		return err
	}
	if _, err := a.store.Tunnel(id); err != nil {
		return err
	}
	if err := a.store.SetTunnelRoutingGroups(id, groups, admin); err != nil {
		return err
	}
	return a.reconcileLocked(context.Background())
}
func (a *App) CreateRoutingGroup(name, admin string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("routing group name is required")
	}
	if err := validateRoutingGroup(name); err != nil {
		return err
	}
	return a.store.CreateRoutingGroup(name, admin)
}
func (a *App) RenameRoutingGroup(id int64, name, admin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("routing group name is required")
	}
	if err := validateRoutingGroup(name); err != nil {
		return err
	}
	if err := a.store.RenameRoutingGroup(id, name, admin); err != nil {
		return err
	}
	return a.reconcileLocked(context.Background())
}
func (a *App) DeleteRoutingGroup(id int64, admin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.store.DeleteRoutingGroup(id, admin); err != nil {
		return err
	}
	return a.reconcileLocked(context.Background())
}
func (a *App) DeleteTunnel(id int64, admin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	t, e := a.store.Tunnel(id)
	if e != nil {
		return e
	}
	cfg, e := a.store.Settings()
	if e != nil {
		return e
	}
	if e = a.kernel.Remove(cfg, t); e != nil {
		_ = a.store.SetStatus(id, "error", e.Error())
		return e
	}
	return a.store.DeleteTunnel(id, admin)
}
func (a *App) SetEnabled(id int64, on bool, admin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e := a.store.SetEnabled(id, on, admin); e != nil {
		return e
	}
	return a.reconcileLocked(context.Background())
}
func (a *App) Reconcile(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.reconcileLocked(ctx)
}
func (a *App) reconcileLocked(ctx context.Context) error {
	cfg, e := a.store.Settings()
	if e != nil {
		return e
	}
	now := time.Now().UTC()
	if e = a.store.ResetMonthlyQuotas(now); e != nil {
		return e
	}
	if cfg.UpstreamV6 == "" {
		return nil
	}
	ts, e := a.store.Tunnels()
	if e != nil {
		return e
	}
	needsIPv4 := false
	needsWarp := false
	for _, t := range ts {
		mode := tunnelV4Mode(cfg, t)
		needsIPv4 = needsIPv4 || mode != V4ModeOff
		needsWarp = needsWarp || mode == V4ModeWarp
	}
	if needsWarp {
		account, accountErr := a.store.WarpAccount()
		if accountErr != nil {
			return accountErr
		}
		if !account.Exists() {
			return errors.New("create a Cloudflare WARP account before applying WARP IPv4 egress")
		}
	}
	if needsIPv4 {
		pool, parseErr := netip.ParsePrefix(cfg.V4Pool)
		if parseErr != nil {
			return parseErr
		}
		if !pool.Addr().Is4() {
			return errors.New("v4 pool must be an IPv4 CIDR")
		}
		if e = a.store.EnsureIPv4Allocations(cfg); e != nil {
			return e
		}
		ts, e = a.store.Tunnels()
		if e != nil {
			return e
		}
	}
	warp, e := a.store.WarpAccount()
	if e != nil {
		return e
	}
	live, e := a.kernel.Apply(ctx, cfg, warp, ts)
	a.health.LastReconcile = now
	if e != nil {
		a.health.Error = e.Error()
		for _, t := range ts {
			_ = a.store.SetStatus(t.ID, "error", e.Error())
		}
		return e
	}
	a.health.Error = ""
	quotaHit := false
	for _, t := range live {
		hit, telemetryErr := a.store.UpdateTelemetry(t, now)
		if telemetryErr != nil {
			a.health.Error = telemetryErr.Error()
			return telemetryErr
		}
		quotaHit = quotaHit || hit
	}
	if quotaHit {
		ts, e = a.store.Tunnels()
		if e != nil {
			return e
		}
		if _, e = a.kernel.Apply(ctx, cfg, warp, ts); e != nil {
			a.health.Error = e.Error()
			return e
		}
	} else {
		ts, e = a.store.Tunnels()
		if e != nil {
			return e
		}
	}
	for _, t := range ts {
		if !t.QuotaDisabled {
			_ = a.store.SetStatus(t.ID, "applied", "")
		}
	}
	a.health.Drift, e = a.kernel.Inspect(cfg, warp, ts)
	if e != nil {
		a.health.Error = e.Error()
		return e
	}
	return nil
}

func (a *App) RunReconciler(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.Reconcile(ctx); err != nil {
				a.logger.Printf("periodic reconcile: %v", err)
			}
		}
	}
}
func (a *App) ClientConfig(t Tunnel, cfg Settings) string {
	priv := t.PrivateKey
	if priv == "" {
		priv = "<client-private-key>"
	}
	dns := t.DNSOverride
	if dns == "" {
		dns = cfg.DefaultDNS
	}
	address := firstUsable(netip.MustParsePrefix(t.V6CIDR)).String() + "/" + fmt.Sprint(netip.MustParsePrefix(t.V6CIDR).Bits())
	if tunnelIPv4Enabled(cfg, t) {
		address += ", " + t.V4Address + "/32"
	}
	allowed := "::/0"
	if tunnelIPv4Enabled(cfg, t) {
		allowed = "0.0.0.0/0, ::/0"
	}
	pub := ""
	if k, e := wgtypes.ParseKey(cfg.ServerPrivateKey); e == nil {
		pub = k.PublicKey().String()
	}
	endpoint := net.JoinHostPort(cfg.EndpointHost, strconv.Itoa(cfg.EndpointPort))
	return fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\nDNS = %s\nMTU = %d\n\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nEndpoint = %s\nAllowedIPs = %s\nPersistentKeepalive = %d\n", priv, address, dns, chooseMTU(t, cfg), pub, t.PresharedKey, endpoint, allowed, cfg.Keepalive)
}
func firstUsable(p netip.Prefix) netip.Addr {
	if p.Bits() == p.Addr().BitLen() {
		return p.Masked().Addr()
	}
	return p.Masked().Addr().Next()
}
func chooseMTU(t Tunnel, c Settings) int {
	if t.MTUOverride > 0 {
		return t.MTUOverride
	}
	return c.MTU
}
