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
	return &App{store: s, kernel: &LinuxKernel{DryRun: dry, Logger: logger}, logger: logger, sessions: map[string]session{}, httpClient: &http.Client{Timeout: 20 * time.Second}, warpAPIURL: defaultWarpAPIURL, upgrader: NewSystemUpgrader()}, nil
}

// Close stops kernel helpers and then the store. Kernel state that carries
// traffic is intentionally left in place across restarts.
func (a *App) Close() error {
	kernelErr := a.kernel.Close()
	storeErr := a.store.Close()
	if storeErr != nil {
		return storeErr
	}
	return kernelErr
}
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

func (a *App) Settings() (Settings, error) { return a.store.Settings() }

func (a *App) SaveSettings(v Settings) error {
	if v.InterTunnelPolicy == "" {
		v.InterTunnelPolicy = InterTunnelIsolated
	}
	if e := validateSettings(v); e != nil {
		return e
	}
	if v.V4Warp {
		account, accountErr := a.store.WarpAccount()
		if accountErr != nil {
			return accountErr
		}
		if !account.Exists() {
			return errors.New("create a Cloudflare WARP account before enabling WARP IPv4 egress")
		}
	}
	return a.store.SaveSettings(v)
}

func validateSettings(v Settings) error {
	if v.V4NAT && v.V4Warp {
		return errors.New("native IPv4 NAT and Cloudflare WARP IPv4 egress cannot be enabled together")
	}
	if v.V4NAT || v.V4Warp {
		pool, err := netip.ParsePrefix(v.V4Pool)
		if err != nil || !pool.Addr().Is4() {
			return errors.New("v4 pool must be an IPv4 CIDR")
		}
	}
	if !validInterTunnelPolicy(v.InterTunnelPolicy) {
		return errors.New("invalid inter-tunnel routing policy")
	}
	return nil
}

func (a *App) ResetGeneralSettings(admin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	cfg, err := a.store.Settings()
	if err != nil {
		return err
	}
	cfg.V4NAT = false
	cfg.V4Warp = false
	cfg.V4Pool = "10.99.0.0/16"
	cfg.DefaultDNS = "2606:4700:4700::1111"
	cfg.InterTunnelPolicy = InterTunnelIsolated
	if err = a.store.SaveSettings(cfg); err != nil {
		return err
	}
	_ = a.store.AddAudit(admin, "settings-reset", "general defaults restored")
	return a.reconcileLocked(context.Background())
}

// defaultTransportAddress numbers a WireGuard interface outside any delegated
// prefix. It is used when the whole prefix goes downstream and therefore has no
// room for an infrastructure address. Each upstream needs its own range, so the
// first ULA subnet not already claimed by another upstream is chosen.
const defaultTransportPrefix = "fd00:6b72:6f6b:%x::1/64"

func defaultTransportAddress(others []Upstream) string {
	taken := make(map[string]bool, len(others))
	for _, other := range others {
		if transport, ok := transportPrefix(other); ok {
			taken[transport.Masked().String()] = true
		}
	}
	for index := 0; index < 0x10000; index++ {
		candidate := fmt.Sprintf(defaultTransportPrefix, index)
		prefix, err := netip.ParsePrefix(candidate)
		if err != nil {
			continue
		}
		if !taken[prefix.Masked().String()] {
			return candidate
		}
	}
	return fmt.Sprintf(defaultTransportPrefix, 0)
}

// othersExcept drops the upstream being edited from a list, so that its own
// current values never count as a conflict with itself.
func othersExcept(upstreams []Upstream, id int64) []Upstream {
	others := make([]Upstream, 0, len(upstreams))
	for _, upstream := range upstreams {
		if upstream.ID != id {
			others = append(others, upstream)
		}
	}
	return others
}

func (a *App) Upstreams() ([]Upstream, error) { return a.store.Upstreams() }
func (a *App) Upstream(id int64) (Upstream, error) {
	return a.store.Upstream(id)
}

// UpstreamInput carries the editable fields of one provider connection.
type UpstreamInput struct {
	ID                                  int64
	Name                                string
	V6CIDR                              string
	Mode                                string
	PublicV4                            string
	EgressInterface                     string
	InterfaceName                       string
	EndpointHost                        string
	EndpointPort                        int
	ServerAddress                       string
	TransportAddress                    string
	MTU, Keepalive                      int
	MinPrefix, MaxPrefix, DefaultPrefix int
	V4Mode                              string
}

func (in UpstreamInput) apply(existing Upstream) Upstream {
	existing.Name = strings.TrimSpace(in.Name)
	existing.V6CIDR = strings.TrimSpace(in.V6CIDR)
	existing.Mode = strings.TrimSpace(in.Mode)
	existing.PublicV4 = strings.TrimSpace(in.PublicV4)
	existing.EgressInterface = strings.TrimSpace(in.EgressInterface)
	existing.InterfaceName = strings.TrimSpace(in.InterfaceName)
	existing.EndpointHost = strings.TrimSpace(in.EndpointHost)
	existing.EndpointPort = in.EndpointPort
	existing.ServerAddress = strings.TrimSpace(in.ServerAddress)
	existing.TransportAddress = strings.TrimSpace(in.TransportAddress)
	existing.MTU = in.MTU
	existing.Keepalive = in.Keepalive
	existing.MinPrefix, existing.MaxPrefix, existing.DefaultPrefix = in.MinPrefix, in.MaxPrefix, in.DefaultPrefix
	existing.V4Mode = in.V4Mode
	return existing
}

func (a *App) CreateUpstream(in UpstreamInput, admin string) (Upstream, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	upstream := in.apply(Upstream{MTU: 1420, Keepalive: 25, MinPrefix: 48, MaxPrefix: 64, DefaultPrefix: 56, EndpointPort: 51820})
	upstream, err := a.prepareUpstream(upstream, nil)
	if err != nil {
		return Upstream{}, err
	}
	if err = a.store.InsertUpstream(&upstream, admin); err != nil {
		return Upstream{}, err
	}
	if err = a.reconcileLocked(context.Background()); err != nil {
		return upstream, fmt.Errorf("upstream saved but apply failed: %w", err)
	}
	return a.store.Upstream(upstream.ID)
}

func (a *App) UpdateUpstream(in UpstreamInput, admin string) (Upstream, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	existing, err := a.store.Upstream(in.ID)
	if err != nil {
		return Upstream{}, err
	}
	previousInterface := existing.InterfaceName
	updated, err := a.prepareUpstream(in.apply(existing), nil)
	if err != nil {
		return Upstream{}, err
	}
	tunnels, err := a.store.TunnelsForUpstream(updated.ID)
	if err != nil {
		return Upstream{}, err
	}
	if err = validateUpstreamAgainstTunnels(updated, tunnels); err != nil {
		return Upstream{}, err
	}
	if err = a.store.UpdateUpstream(updated, admin); err != nil {
		return Upstream{}, err
	}
	// A renamed WireGuard interface leaves the old device behind, still holding
	// peers and routes, so it is torn down explicitly.
	if previousInterface != updated.InterfaceName {
		stale := existing
		stale.InterfaceName = previousInterface
		if err = a.kernel.RemoveUpstream(stale); err != nil {
			return updated, fmt.Errorf("upstream saved but the previous interface %s could not be removed: %w", previousInterface, err)
		}
	}
	if err = a.reconcileLocked(context.Background()); err != nil {
		return updated, fmt.Errorf("upstream saved but apply failed: %w", err)
	}
	return a.store.Upstream(updated.ID)
}

func (a *App) DeleteUpstream(id int64, admin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	upstream, err := a.store.Upstream(id)
	if err != nil {
		return err
	}
	if upstream.TunnelCount > 0 {
		return fmt.Errorf("upstream %q still has %d tunnel(s); delete them first", upstream.Name, upstream.TunnelCount)
	}
	// Kernel state is removed before the row, because the row is what a later
	// reconciliation would use to find this interface again. Dropping it first
	// and then failing would leak the device and its policy table permanently.
	if err = a.kernel.RemoveUpstream(upstream); err != nil {
		return fmt.Errorf("upstream not deleted because its interface could not be removed: %w", err)
	}
	if err = a.store.DeleteUpstream(id, admin); err != nil {
		return err
	}
	return a.reconcileLocked(context.Background())
}

// prepareUpstream normalizes and validates one provider connection, generating
// its server key on first use. Uniqueness is checked against every other
// upstream, because two connections that share an interface, a listening
// endpoint, or overlapping address space would silently fight in the kernel.
func (a *App) prepareUpstream(upstream Upstream, others []Upstream) (Upstream, error) {
	var err error
	if others == nil {
		if others, err = a.store.Upstreams(); err != nil {
			return upstream, err
		}
	}
	if upstream, err = normalizeUpstream(upstream, others); err != nil {
		return upstream, err
	}
	if err = validateUpstream(upstream); err != nil {
		return upstream, err
	}
	if err = validateUpstreamUniqueness(upstream, others); err != nil {
		return upstream, err
	}
	if upstream.ServerPrivateKey == "" {
		key, keyErr := wgtypes.GeneratePrivateKey()
		if keyErr != nil {
			return upstream, keyErr
		}
		upstream.ServerPrivateKey = key.String()
	}
	return upstream, nil
}

// normalizeUpstream makes a delegation configuration self-consistent so that a
// single-/64 upstream needs no manual per-tunnel work.
//
// A provider that hands this host exactly one /64 leaves no room to split off
// an infrastructure subnet: SLAAC needs a full /64 on the downstream LAN. The
// whole prefix is therefore delegated as one allocation, the WireGuard
// transport is numbered from a ULA instead, and no part of the prefix is
// reserved for the server.
func normalizeUpstream(v Upstream, others []Upstream) (Upstream, error) {
	if v.MTU == 0 {
		v.MTU = 1420
	}
	if v.Keepalive == 0 {
		v.Keepalive = 25
	}
	if v.EndpointPort == 0 {
		v.EndpointPort = 51820
	}
	if !validTunnelV4Mode(v.V4Mode) {
		return v, errors.New("invalid IPv4 egress mode for this upstream")
	}
	upstream, err := netip.ParsePrefix(v.V6CIDR)
	if err != nil || !upstream.Addr().Is6() {
		// Leave validation to report the real problem.
		return v, nil
	}
	upstream = upstream.Masked()
	v.V6CIDR = upstream.String()
	if !validUpstreamMode(v.Mode) {
		v.Mode = UpstreamRouted
	}
	// A prefix no larger than a single /64 cannot be subdivided for SLAAC, so
	// the entire prefix becomes the one allocation size on offer.
	if upstream.Bits() >= 64 {
		v.MinPrefix, v.MaxPrefix, v.DefaultPrefix = upstream.Bits(), upstream.Bits(), upstream.Bits()
	} else {
		v.MinPrefix = min(max(v.MinPrefix, upstream.Bits()), 128)
		v.MaxPrefix = min(max(v.MaxPrefix, v.MinPrefix), 128)
		v.DefaultPrefix = min(max(v.DefaultPrefix, v.MinPrefix), v.MaxPrefix)
	}
	if v.Mode == UpstreamOnLink && v.TransportAddress == "" {
		// The prefix is handed downstream in full, so the tunnel has to be
		// numbered from somewhere else. A server address inside the prefix is
		// rejected by validation rather than cleared here: silently dropping it
		// would change an existing deployment's addressing without saying so.
		v.TransportAddress = defaultTransportAddress(othersExcept(others, v.ID))
	}
	if v.TransportAddress != "" {
		transport, transportErr := netip.ParsePrefix(v.TransportAddress)
		if transportErr != nil {
			return v, errors.New("WireGuard transport address must be an IPv6 CIDR")
		}
		// Keep the host bits: this is an interface address, not a route.
		v.TransportAddress = transport.String()
	}
	return v, nil
}

func validateUpstream(v Upstream) error {
	if v.Name == "" {
		return errors.New("upstream name is required")
	}
	if utf8.RuneCountInString(v.Name) > 64 {
		return errors.New("upstream name must be at most 64 characters")
	}
	for _, character := range v.Name {
		if unicode.IsControl(character) {
			return errors.New("upstream name cannot contain control characters")
		}
	}
	p, e := netip.ParsePrefix(v.V6CIDR)
	if e != nil || !p.Addr().Is6() {
		return errors.New("upstream IPv6 must be an IPv6 CIDR")
	}
	if !validUpstreamMode(upstreamMode(v)) {
		return errors.New("invalid upstream delegation mode")
	}
	if v.MinPrefix < p.Bits() || v.MaxPrefix < v.MinPrefix || v.MaxPrefix > 128 || v.DefaultPrefix < v.MinPrefix || v.DefaultPrefix > v.MaxPrefix {
		return errors.New("prefix limits must satisfy upstream <= min <= default <= max <= 128")
	}
	if v.TransportAddress != "" {
		transport, transportErr := netip.ParsePrefix(v.TransportAddress)
		if transportErr != nil || !transport.Addr().Is6() {
			return errors.New("WireGuard transport address must be an IPv6 CIDR")
		}
		if p.Contains(transport.Addr()) {
			return errors.New("WireGuard transport address must be outside the delegated prefix; use a ULA such as fd00:0:0:1::1/64")
		}
	}
	if upstreamMode(v) == UpstreamOnLink {
		if v.ServerAddress != "" {
			return errors.New("on-link delegation hands the entire prefix downstream, so it cannot also reserve a server address: clear the server address field")
		}
		if v.TransportAddress == "" {
			return errors.New("on-link delegation requires a WireGuard transport address outside the delegated prefix, such as fd00:0:0:1::1/64")
		}
	}
	if v.EndpointHost == "" {
		return errors.New("endpoint hostname or address is required")
	}
	if v.EgressInterface == "" {
		return errors.New("upstream egress interface is required")
	}
	if v.InterfaceName == "" {
		return errors.New("WireGuard interface name is required")
	}
	if v.InterfaceName == warpInterfaceName {
		return errors.New("WireGuard interface name is reserved for Cloudflare WARP")
	}
	if len(v.InterfaceName) > 15 {
		return errors.New("WireGuard interface name must be at most 15 characters")
	}
	if v.InterfaceName == v.EgressInterface {
		return errors.New("the WireGuard interface cannot be the upstream egress interface")
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
	if v.MTU < 1280 || v.MTU > 9000 {
		return errors.New("MTU must be between 1280 and 9000")
	}
	if v.Keepalive < 0 || v.Keepalive > 3600 {
		return errors.New("keepalive must be between 0 and 3600 seconds")
	}
	return nil
}

// validateUpstreamUniqueness rejects a connection that would collide with an
// existing one. Upstreams are independent by design, so overlap in delegated
// space, WireGuard interface, or listening endpoint is always a configuration
// error rather than something to resolve silently.
func validateUpstreamUniqueness(candidate Upstream, existing []Upstream) error {
	prefix, ok := delegatedPrefix(candidate)
	if !ok {
		return errors.New("upstream IPv6 must be an IPv6 CIDR")
	}
	transport, hasTransport := transportPrefix(candidate)
	for _, other := range existing {
		if other.ID == candidate.ID {
			continue
		}
		if strings.EqualFold(other.Name, candidate.Name) {
			return errors.New("another upstream already uses that name")
		}
		if other.InterfaceName == candidate.InterfaceName {
			return errors.New("another upstream already uses that WireGuard interface name")
		}
		// Egressing through another upstream's tunnel device would install a
		// forwarding pair between two managed WireGuard interfaces, which is
		// exactly what the inter-tunnel policy governs. That would let every
		// client of one upstream reach every client of the other while the
		// policy still reads as isolated, so it is refused outright.
		if other.InterfaceName == candidate.EgressInterface {
			return fmt.Errorf("egress interface %s belongs to upstream %q; chain upstreams through a separate interface instead", candidate.EgressInterface, other.Name)
		}
		if other.EgressInterface == candidate.InterfaceName {
			return fmt.Errorf("WireGuard interface %s is the egress interface of upstream %q", candidate.InterfaceName, other.Name)
		}
		if otherPrefix, otherOK := delegatedPrefix(other); otherOK && overlaps(prefix, otherPrefix) {
			return fmt.Errorf("delegated prefix %s overlaps upstream %q (%s)", prefix, other.Name, otherPrefix)
		}
		if otherTransport, otherOK := transportPrefix(other); hasTransport && otherOK && overlaps(transport.Masked(), otherTransport.Masked()) {
			return fmt.Errorf("WireGuard transport range %s overlaps upstream %q (%s)", transport, other.Name, otherTransport)
		}
		// Two interfaces cannot bind the same UDP port, and clients reach an
		// upstream by endpoint, so a shared host and port is ambiguous too.
		if other.EndpointPort == candidate.EndpointPort && strings.EqualFold(other.EndpointHost, candidate.EndpointHost) {
			return fmt.Errorf("upstream %q already listens on %s", other.Name, net.JoinHostPort(candidate.EndpointHost, strconv.Itoa(candidate.EndpointPort)))
		}
	}
	return nil
}

// validateUpstreamAgainstTunnels refuses an edit that would orphan an existing
// allocation, so a running deployment can never be renumbered by accident.
func validateUpstreamAgainstTunnels(upstream Upstream, tunnels []Tunnel) error {
	prefix, ok := delegatedPrefix(upstream)
	if !ok {
		return errors.New("upstream IPv6 must be an IPv6 CIDR")
	}
	reserved, hasReservation := serverReservation(upstream)
	for _, tunnel := range tunnels {
		allocation, err := netip.ParsePrefix(tunnel.V6CIDR)
		if err != nil {
			continue
		}
		allocation = allocation.Masked()
		if !prefix.Contains(allocation.Addr()) || allocation.Bits() < prefix.Bits() {
			return fmt.Errorf("tunnel %q is allocated %s, which is outside the new delegated prefix %s", tunnel.Label, allocation, prefix)
		}
		if hasReservation && overlaps(reserved, allocation) {
			return fmt.Errorf("the server address reserves %s, which tunnel %q already holds", reserved, tunnel.Label)
		}
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
	UpstreamID            int64
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
	upstream, e := a.resolveUpstream(in.UpstreamID)
	if e != nil {
		return Tunnel{}, e
	}
	if e = validateUpstream(upstream); e != nil {
		return Tunnel{}, fmt.Errorf("upstream %q is not usable: %w", upstream.Name, e)
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
	t := Tunnel{UpstreamID: upstream.ID, Label: strings.TrimSpace(in.Label), PublicKey: strings.TrimSpace(in.PublicKey), DNSOverride: strings.TrimSpace(in.DNS), V4Mode: in.V4Mode, QuotaGiB: in.QuotaGiB, QuotaPeriod: quotaMonth(time.Now()), RoutingGroups: in.RoutingGroups, Enabled: true}
	if tunnelV4Mode(cfg, upstream, t) == V4ModeWarp {
		account, accountErr := a.store.WarpAccount()
		if accountErr != nil {
			return Tunnel{}, accountErr
		}
		if !account.Exists() {
			return Tunnel{}, errors.New("create a Cloudflare WARP account before selecting WARP IPv4 egress")
		}
	}
	if in.Prefix == 0 {
		in.Prefix = upstream.DefaultPrefix
	}
	if in.Prefix < upstream.MinPrefix || in.Prefix > upstream.MaxPrefix {
		return Tunnel{}, errors.New("requested prefix is outside the limits configured for this upstream")
	}
	used, e := a.store.UsedPrefixes(upstream.ID)
	if e != nil {
		return Tunnel{}, e
	}
	if reserved, ok := serverReservation(upstream); ok {
		used = append(used, reserved)
	}
	pool, ok := delegatedPrefix(upstream)
	if !ok {
		return Tunnel{}, errors.New("upstream IPv6 must be an IPv6 CIDR")
	}
	alloc, e := Allocate(pool, used, in.Prefix)
	if e != nil {
		return Tunnel{}, e
	}
	t.V6CIDR = alloc.String()
	t.V4Enabled = tunnelV4Mode(cfg, upstream, t) != V4ModeOff
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
		pool, poolErr := netip.ParsePrefix(cfg.V4Pool)
		if poolErr != nil {
			return t, errors.New("v4 pool must be an IPv4 CIDR")
		}
		t.V4Address, e = a.store.NextV4(pool)
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

// resolveUpstream returns the requested upstream, or the only configured one
// when no choice was made. Deployments with a single provider connection
// therefore need no upstream selection at all.
func (a *App) resolveUpstream(id int64) (Upstream, error) {
	if id > 0 {
		upstream, err := a.store.Upstream(id)
		if err != nil {
			return Upstream{}, errors.New("the selected upstream does not exist")
		}
		return upstream, nil
	}
	upstreams, err := a.store.Upstreams()
	if err != nil {
		return Upstream{}, err
	}
	switch len(upstreams) {
	case 0:
		return Upstream{}, errors.New("configure an upstream before creating tunnels")
	case 1:
		return upstreams[0], nil
	default:
		return Upstream{}, errors.New("select which upstream this tunnel is allocated from")
	}
}

// TunnelUpstream returns the connection a tunnel was allocated from.
func (a *App) TunnelUpstream(t Tunnel) (Upstream, error) {
	return a.store.Upstream(t.UpstreamID)
}

func (a *App) SetTunnelV4Mode(id int64, mode, admin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !validTunnelV4Mode(mode) {
		return errors.New("invalid IPv4 egress mode")
	}
	tunnel, err := a.store.Tunnel(id)
	if err != nil {
		return err
	}
	cfg, err := a.store.Settings()
	if err != nil {
		return err
	}
	upstream, err := a.store.Upstream(tunnel.UpstreamID)
	if err != nil {
		return err
	}
	tunnel.V4Mode = mode
	if tunnelV4Mode(cfg, upstream, tunnel) == V4ModeWarp {
		account, accountErr := a.store.WarpAccount()
		if accountErr != nil {
			return accountErr
		}
		if !account.Exists() {
			return errors.New("create a Cloudflare WARP account before selecting WARP IPv4 egress")
		}
	}
	if err = a.store.SetTunnelV4Mode(id, mode, admin); err != nil {
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
	upstream, e := a.store.Upstream(t.UpstreamID)
	if e != nil {
		// An orphaned tunnel has no kernel state of its own to remove, because
		// the interface went away with its upstream.
		return a.store.DeleteTunnel(id, admin)
	}
	if e = a.kernel.Remove(upstream, t); e != nil {
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
	upstreams, e := a.store.Upstreams()
	if e != nil {
		return e
	}
	if len(upstreams) == 0 {
		// Nothing is delegated, so the kernel must hold nothing either. Applying
		// the empty set is what tears down the rules of a deleted last upstream
		// rather than leaving them installed with nothing to authorize.
		warp, warpErr := a.store.WarpAccount()
		if warpErr != nil {
			return warpErr
		}
		if _, e = a.kernel.Apply(ctx, cfg, warp, nil, nil); e != nil {
			a.health.Error = e.Error()
			return e
		}
		a.health.LastReconcile, a.health.Error, a.health.Drift = now, "", nil
		return nil
	}
	ts, e := a.store.Tunnels()
	if e != nil {
		return e
	}
	byUpstream := upstreamsByID(upstreams)
	needsIPv4 := false
	needsWarp := false
	for _, t := range ts {
		mode := tunnelV4Mode(cfg, byUpstream[t.UpstreamID], t)
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
	live, e := a.kernel.Apply(ctx, cfg, warp, upstreams, ts)
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
	ts, e = a.store.Tunnels()
	if e != nil {
		return e
	}
	if quotaHit {
		if _, e = a.kernel.Apply(ctx, cfg, warp, upstreams, ts); e != nil {
			a.health.Error = e.Error()
			return e
		}
	}
	for _, t := range ts {
		if !t.QuotaDisabled {
			_ = a.store.SetStatus(t.ID, "applied", "")
		}
	}
	a.health.Drift, e = a.kernel.Inspect(cfg, warp, upstreams, ts)
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
func (a *App) ClientConfig(t Tunnel, up Upstream, cfg Settings) string {
	priv := t.PrivateKey
	if priv == "" {
		priv = "<client-private-key>"
	}
	dns := t.DNSOverride
	if dns == "" {
		dns = cfg.DefaultDNS
	}
	delegated, err := netip.ParsePrefix(t.V6CIDR)
	if err != nil {
		return ""
	}
	// The whole delegated prefix is handed to the client's LAN when it is a
	// single /64, because SLAAC needs a full /64 there. The tunnel interface is
	// then numbered from the transport range instead, leaving the prefix free.
	// Otherwise the tunnel keeps its historical address inside the prefix.
	notes := ""
	address := firstUsable(delegated).String() + "/" + fmt.Sprint(delegated.Bits())
	if client, ok := clientTransportAddress(up, t); ok {
		transport, _ := transportPrefix(up)
		address = client.String() + "/" + fmt.Sprint(transport.Bits())
		notes = fmt.Sprintf("# Routed to this peer: %s\n# Put that prefix on the LAN and advertise it there (OpenWrt: RA server, DHCPv6 server, NDP disabled).\n# Do not add it to this interface: the LAN needs the whole /64 for SLAAC.\n", delegated.Masked())
	}
	if tunnelIPv4Enabled(cfg, up, t) {
		address += ", " + t.V4Address + "/32"
	}
	allowed := "::/0"
	if tunnelIPv4Enabled(cfg, up, t) {
		allowed = "0.0.0.0/0, ::/0"
	}
	pub := ""
	if k, e := wgtypes.ParseKey(up.ServerPrivateKey); e == nil {
		pub = k.PublicKey().String()
	}
	endpoint := net.JoinHostPort(up.EndpointHost, strconv.Itoa(up.EndpointPort))
	return fmt.Sprintf("%s[Interface]\nPrivateKey = %s\nAddress = %s\nDNS = %s\nMTU = %d\n\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nEndpoint = %s\nAllowedIPs = %s\nPersistentKeepalive = %d\n", notes, priv, address, dns, chooseMTU(t, up), pub, t.PresharedKey, endpoint, allowed, up.Keepalive)
}

func firstUsable(p netip.Prefix) netip.Addr {
	if p.Bits() == p.Addr().BitLen() {
		return p.Masked().Addr()
	}
	return p.Masked().Addr().Next()
}
func chooseMTU(t Tunnel, up Upstream) int {
	if t.MTUOverride > 0 {
		return t.MTUOverride
	}
	return up.MTU
}
