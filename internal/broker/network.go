//go:build linux

package broker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Kernel interface {
	Apply(context.Context, Settings, WarpAccount, []Upstream, []Tunnel) ([]Tunnel, error)
	Inspect(Settings, WarpAccount, []Upstream, []Tunnel) ([]string, error)
	Remove(Upstream, Tunnel) error
	RemoveUpstream(Upstream) error
	TestWarp(context.Context, Settings, WarpAccount) (string, error)
	Close() error
}
type LinuxKernel struct {
	DryRun bool
	Logger *log.Logger

	ndpOnce sync.Once
	ndp     *ndpProxyManager
}

const (
	warpRouteTable   = 51822
	warpRulePriority = 90

	// Traffic between delegated prefixes must keep using the main table, where
	// every tunnel route lives, so those destinations are matched before any
	// source-based egress rule. This is what lets a tunnel on one upstream reach
	// a tunnel on another. It is deliberately evaluated before the WARP rule as
	// well: a WARP tunnel's packets to another tunnel belong on the main table,
	// not in the WARP table, whose only route is the default one.
	interUpstreamRulePriority = 80
	// Everything else leaves through the provider that delegated the source
	// address, which BCP 38 filtering upstream requires.
	upstreamRulePriority = 110
	// Each upstream owns one policy table, numbered from its database ID.
	upstreamRouteTableBase = 52000
	// The kernel's main routing table, which holds every tunnel route.
	mainRouteTable = 254

	// Tunnel routes are installed with a better metric than the kernel's
	// connected route, which IPv6 creates at metric 256. On an on-link
	// upstream a tunnel may be delegated the entire prefix, producing a route
	// of exactly the connected route's length, where only the metric decides.
	tunnelRouteMetric = 128

	// A gateway inside a delegated prefix is pinned to the egress interface
	// at a longer prefix than any tunnel route, so delegating the whole prefix
	// downstream can never strand the host's own default route.
	gatewayRouteMetric = 64
)

// upstreamRouteTable is the policy table holding one upstream's default route.
func upstreamRouteTable(up Upstream) int { return upstreamRouteTableBase + int(up.ID) }

// responder returns the lazily created Neighbor Discovery proxy manager, so a
// kernel value stays usable when constructed directly.
func (k *LinuxKernel) responder() *ndpProxyManager {
	k.ndpOnce.Do(func() {
		logger := k.Logger
		if logger == nil {
			logger = log.New(io.Discard, "", 0)
		}
		k.ndp = newNDPProxyManager(logger)
	})
	return k.ndp
}

// Close stops the Neighbor Discovery proxies. Routes, peers, and nftables rules
// are deliberately left in place so that a restart does not interrupt traffic.
func (k *LinuxKernel) Close() error {
	if k.DryRun {
		return nil
	}
	k.responder().Close()
	return nil
}

func (k *LinuxKernel) Apply(ctx context.Context, cfg Settings, warp WarpAccount, upstreams []Upstream, tunnels []Tunnel) ([]Tunnel, error) {
	if k.DryRun {
		return tunnels, nil
	}
	grouped := tunnelsByUpstream(upstreams, tunnels)
	wg, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer wg.Close()
	// Telemetry is collected per upstream and merged back into the caller's
	// slice, which keeps quota accounting independent of interface layout.
	live := make(map[string]wgtypes.Peer)
	// One unhealthy provider must not stop the others from being programmed.
	// The global passes below — policy routing, nftables, and the Neighbor
	// Discovery proxies — are shared, so returning here would leave healthy
	// upstreams without the forwarding rules their traffic depends on. The
	// failure is reported after everything that can still be applied has been.
	var upstreamErr error
	healthy := make([]Upstream, 0, len(upstreams))
	for _, upstream := range upstreams {
		peers, applyErr := k.applyUpstream(wg, cfg, upstream, grouped[upstream.ID])
		if applyErr != nil {
			if upstreamErr == nil {
				upstreamErr = fmt.Errorf("upstream %q: %w", upstream.Name, applyErr)
			}
			continue
		}
		healthy = append(healthy, upstream)
		for key, peer := range peers {
			live[key] = peer
		}
	}
	for i, tunnel := range tunnels {
		if peer, ok := live[tunnel.PublicKey]; ok {
			tunnels[i].LastHandshake = peer.LastHandshakeTime
			tunnels[i].RXBytes = peer.ReceiveBytes
			tunnels[i].TXBytes = peer.TransmitBytes
		}
	}
	// The shared passes describe only the upstreams whose interfaces actually
	// exist. Programming rules for a device that could not be brought up would
	// reference an interface the kernel does not have.
	warpEnabled := false
	byID := upstreamsByID(healthy)
	for _, tunnel := range tunnels {
		warpEnabled = warpEnabled || resolvedV4Mode(cfg, byID, tunnel) == V4ModeWarp
	}
	if warpEnabled {
		if err = k.ensureWarp(cfg, warp, healthy, tunnels); err != nil {
			return tunnels, err
		}
	} else if err = k.disableWarp(); err != nil {
		return tunnels, err
	}
	if err = k.applyPolicyRouting(cfg, healthy, tunnels); err != nil {
		return tunnels, err
	}
	if err = k.applyNAT(ctx, cfg, healthy, tunnels); err != nil {
		return tunnels, err
	}
	if err = k.applyNDPProxy(healthy, grouped); err != nil {
		return tunnels, err
	}
	return tunnels, upstreamErr
}

// applyUpstream reconciles one provider connection: its WireGuard interface,
// peer table, and the routes for the prefixes it delegated. It returns the live
// peers so that traffic counters can be read without a second device query.
func (k *LinuxKernel) applyUpstream(wg *wgctrl.Client, cfg Settings, upstream Upstream, tunnels []Tunnel) (map[string]wgtypes.Peer, error) {
	if upstream.InterfaceName == "" {
		return nil, errors.New("interface name is required")
	}
	key, err := wgtypes.ParseKey(upstream.ServerPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("server private key: %w", err)
	}
	link, err := netlink.LinkByName(upstream.InterfaceName)
	if _, ok := err.(netlink.LinkNotFoundError); ok {
		g := &netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: upstream.InterfaceName}, LinkType: "wireguard"}
		if err = netlink.LinkAdd(g); err != nil {
			return nil, err
		}
		link = g
	} else if err != nil {
		return nil, err
	}
	if upstream.MTU > 0 && link.Attrs().MTU != upstream.MTU {
		if err = netlink.LinkSetMTU(link, upstream.MTU); err != nil {
			return nil, err
		}
	}
	if tunnelAddress := tunnelInterfaceAddress(upstream); tunnelAddress != "" {
		p, e := netip.ParsePrefix(tunnelAddress)
		if e != nil {
			return nil, fmt.Errorf("tunnel interface address: %w", e)
		}
		if _, ok := delegatedPrefix(upstream); !ok {
			return nil, errors.New("upstream prefix is not an IPv6 CIDR")
		}
		addresses, e := netlink.AddrList(link, netlink.FAMILY_V6)
		if e != nil {
			return nil, e
		}
		for _, existing := range addresses {
			addr, ok := netip.AddrFromSlice(existing.IP)
			// This interface is owned entirely by this application and by this
			// upstream, so every routable address other than the configured one
			// is stale. This is what clears an address left inside the delegated
			// prefix after a switch to on-link delegation, where the whole prefix
			// belongs to downstream tunnels. Kernel link-local addresses are left
			// alone because Neighbor Discovery needs them.
			if ok && addr != p.Addr() && !addr.IsLinkLocalUnicast() {
				if e = netlink.AddrDel(link, &existing); e != nil {
					return nil, e
				}
			}
		}
		if e = netlink.AddrReplace(link, &netlink.Addr{IPNet: addressIPNet(p)}); e != nil {
			return nil, e
		}
	}
	if err = netlink.LinkSetUp(link); err != nil {
		return nil, err
	}
	dev, err := wg.Device(upstream.InterfaceName)
	if err != nil {
		return nil, err
	}
	desired := map[string]Tunnel{}
	peers := make([]wgtypes.PeerConfig, 0, len(tunnels)+len(dev.Peers))
	for _, t := range tunnels {
		desired[t.PublicKey] = t
		if !t.Enabled {
			continue
		}
		pub, e := wgtypes.ParseKey(t.PublicKey)
		if e != nil {
			return nil, fmt.Errorf("tunnel %d public key: %w", t.ID, e)
		}
		pc := wgtypes.PeerConfig{PublicKey: pub, ReplaceAllowedIPs: true}
		for _, allowed := range tunnelAllowedIPs(cfg, upstream, t) {
			pc.AllowedIPs = append(pc.AllowedIPs, *prefixIPNet(allowed))
		}
		if t.PresharedKey != "" {
			psk, e := wgtypes.ParseKey(t.PresharedKey)
			if e != nil {
				return nil, e
			}
			pc.PresharedKey = &psk
		}
		if upstream.Keepalive > 0 {
			d := time.Duration(upstream.Keepalive) * time.Second
			pc.PersistentKeepaliveInterval = &d
		}
		peers = append(peers, pc)
	}
	for _, p := range dev.Peers {
		if t, ok := desired[p.PublicKey.String()]; !ok || !t.Enabled {
			peers = append(peers, wgtypes.PeerConfig{PublicKey: p.PublicKey, Remove: true})
		}
	}
	port := upstream.EndpointPort
	if err = wg.ConfigureDevice(upstream.InterfaceName, wgtypes.Config{PrivateKey: &key, ListenPort: &port, ReplacePeers: false, Peers: peers}); err != nil {
		return nil, err
	}
	dev, err = wg.Device(upstream.InterfaceName)
	if err != nil {
		return nil, err
	}
	// On an on-link upstream, tunnel routes can cover the addresses the host
	// needs to reach its own router, so those are pinned to the provider first.
	if err = k.pinUpstreamNeighbors(upstream); err != nil {
		return nil, err
	}
	for _, t := range tunnels {
		p, parseErr := netip.ParsePrefix(t.V6CIDR)
		if parseErr != nil {
			return nil, fmt.Errorf("tunnel %d allocation: %w", t.ID, parseErr)
		}
		v6Route := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: prefixIPNet(p), Protocol: 0x42, Priority: tunnelRouteMetric}
		if t.Enabled {
			if err = netlink.RouteReplace(v6Route); err != nil {
				return nil, err
			}
		} else {
			_ = netlink.RouteDel(v6Route)
		}
		if t.V4Address != "" {
			a, addrErr := netip.ParseAddr(t.V4Address)
			if addrErr != nil {
				return nil, fmt.Errorf("tunnel %d IPv4 address: %w", t.ID, addrErr)
			}
			v4Route := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: prefixIPNet(netip.PrefixFrom(a, 32)), Protocol: 0x42}
			if t.Enabled && tunnelIPv4Enabled(cfg, upstream, t) {
				if err = netlink.RouteReplace(v4Route); err != nil {
					return nil, err
				}
			} else {
				_ = netlink.RouteDel(v4Route)
			}
		}
	}
	live := make(map[string]wgtypes.Peer, len(dev.Peers))
	for _, peer := range dev.Peers {
		live[peer.PublicKey.String()] = peer
	}
	return live, nil
}

// applyPolicyRouting sends each delegated prefix out of the provider that
// delegated it. With one upstream the main table already does exactly that, so
// no rules are installed and an existing deployment is untouched; with several,
// a source address from one provider must not leave through another, which
// upstream ingress filtering would drop.
//
// Traffic between delegated prefixes is matched first and left to the main
// table, where every tunnel route lives, so tunnels on different upstreams can
// still reach each other when the routing policy allows it.
func (k *LinuxKernel) applyPolicyRouting(cfg Settings, upstreams []Upstream, tunnels []Tunnel) error {
	if len(upstreams) < 2 {
		// A single upstream needs no source decision: the main table already
		// sends everything to the only provider there is.
		if err := k.reconcilePolicyRules(nil); err != nil {
			return err
		}
		return k.clearPolicyTables(upstreams)
	}
	for _, upstream := range upstreams {
		if err := k.ensureUpstreamTable(upstream); err != nil {
			return err
		}
	}
	return k.reconcilePolicyRules(desiredPolicyRules(cfg, upstreams, tunnels))
}

// policyRule is one source or destination rule this application owns, in a form
// that can be compared against what the kernel currently holds.
type policyRule struct {
	family   int
	priority int
	table    int
	source   string
	dest     string
}

func (r policyRule) netlinkRule() *netlink.Rule {
	rule := netlink.NewRule()
	rule.Family = r.family
	rule.Priority = r.priority
	rule.Table = r.table
	if r.source != "" {
		rule.Src = prefixIPNet(netip.MustParsePrefix(r.source))
	}
	if r.dest != "" {
		rule.Dst = prefixIPNet(netip.MustParsePrefix(r.dest))
	}
	return rule
}

// desiredPolicyRules lists the complete rule set for a multi-upstream host.
func desiredPolicyRules(cfg Settings, upstreams []Upstream, tunnels []Tunnel) map[policyRule]bool {
	desired := make(map[policyRule]bool)
	// Destinations that stay inside this host's own routing: delegated
	// prefixes, transport ranges, and the internal IPv4 pool. Matching them
	// first is what keeps tunnel-to-tunnel traffic on the main table, where
	// every tunnel route lives, instead of being pushed out to a provider.
	local := make([]netip.Prefix, 0, len(upstreams)*2+1)
	for _, upstream := range upstreams {
		if prefix, ok := delegatedPrefix(upstream); ok {
			local = append(local, prefix)
		}
		if transport, ok := transportPrefix(upstream); ok {
			local = append(local, transport.Masked())
		}
	}
	if pool, err := netip.ParsePrefix(cfg.V4Pool); err == nil && pool.Addr().Is4() {
		local = append(local, pool.Masked())
	}
	for _, destination := range local {
		desired[policyRule{family: ruleFamily(destination), priority: interUpstreamRulePriority, table: mainRouteTable, dest: destination.String()}] = true
	}
	for _, upstream := range upstreams {
		if prefix, ok := delegatedPrefix(upstream); ok {
			desired[policyRule{family: netlink.FAMILY_V6, priority: upstreamRulePriority, table: upstreamRouteTable(upstream), source: prefix.String()}] = true
		}
	}
	// Internal IPv4 addresses are masqueraded at the egress interface, so they
	// need the same per-source decision. WARP-mode tunnels are excluded: their
	// higher-priority rule already sends them to the WARP table.
	byID := upstreamsByID(upstreams)
	for _, tunnel := range tunnels {
		upstream, ok := byID[tunnel.UpstreamID]
		if !ok || tunnelV4Mode(cfg, upstream, tunnel) != V4ModeNative || tunnel.V4Address == "" {
			continue
		}
		address, err := netip.ParseAddr(tunnel.V4Address)
		if err != nil || !address.Is4() {
			continue
		}
		desired[policyRule{family: netlink.FAMILY_V4, priority: upstreamRulePriority, table: upstreamRouteTable(upstream), source: netip.PrefixFrom(address, 32).String()}] = true
	}
	return desired
}

// reconcilePolicyRules converges the kernel on the desired rule set. Missing
// rules are added before stale ones are removed, so a reconciliation never
// opens a window in which a delegated source address could leave through the
// wrong provider.
func (k *LinuxKernel) reconcilePolicyRules(desired map[policyRule]bool) error {
	existing, err := k.currentPolicyRules()
	if err != nil {
		return err
	}
	for rule := range desired {
		if existing[rule] {
			continue
		}
		if err = netlink.RuleAdd(rule.netlinkRule()); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("add policy rule for %s%s: %w", rule.source, rule.dest, err)
		}
	}
	for rule := range existing {
		if desired[rule] {
			continue
		}
		if err = netlink.RuleDel(rule.netlinkRule()); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove stale policy rule for %s%s: %w", rule.source, rule.dest, err)
		}
	}
	return nil
}

// currentPolicyRules reads back the rules this application owns, identified by
// the two priorities it reserves.
func (k *LinuxKernel) currentPolicyRules() (map[policyRule]bool, error) {
	current := make(map[policyRule]bool)
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := netlink.RuleList(family)
		if err != nil {
			return nil, err
		}
		for _, rule := range rules {
			if rule.Priority != interUpstreamRulePriority && rule.Priority != upstreamRulePriority {
				continue
			}
			current[policyRule{family: family, priority: rule.Priority, table: rule.Table, source: ipNetString(rule.Src), dest: ipNetString(rule.Dst)}] = true
		}
	}
	return current, nil
}

func ipNetString(value *net.IPNet) string {
	if value == nil {
		return ""
	}
	prefix, err := netip.ParsePrefix(value.String())
	if err != nil {
		return value.String()
	}
	return prefix.Masked().String()
}

func ruleFamily(prefix netip.Prefix) int {
	if prefix.Addr().Is4() {
		return netlink.FAMILY_V4
	}
	return netlink.FAMILY_V6
}

// ensureUpstreamTable copies the host's default route for one provider into
// that upstream's policy table. A provider reached through a gateway keeps that
// gateway; a point-to-point link such as ppp0 gets a plain device route.
func (k *LinuxKernel) ensureUpstreamTable(upstream Upstream) error {
	if upstream.EgressInterface == "" {
		return nil
	}
	link, err := netlink.LinkByName(upstream.EgressInterface)
	if err != nil {
		return fmt.Errorf("egress interface %s: %w", upstream.EgressInterface, err)
	}
	table := upstreamRouteTable(upstream)
	for _, family := range []int{netlink.FAMILY_V6, netlink.FAMILY_V4} {
		defaultRoute := &netlink.Route{LinkIndex: link.Attrs().Index, Table: table, Protocol: 0x42}
		if family == netlink.FAMILY_V6 {
			defaultRoute.Dst = prefixIPNet(netip.MustParsePrefix("::/0"))
		} else {
			defaultRoute.Dst = prefixIPNet(netip.MustParsePrefix("0.0.0.0/0"))
		}
		if gateway := defaultGatewayVia(link.Attrs().Index, family); gateway != nil {
			defaultRoute.Gw = gateway
		}
		if err = netlink.RouteReplace(defaultRoute); err != nil {
			// A provider without IPv4 (or without IPv6) connectivity is normal;
			// only report the family that is actually configured as an error.
			if family == netlink.FAMILY_V6 {
				return fmt.Errorf("default route for upstream %q: %w", upstream.Name, err)
			}
		}
	}
	return nil
}

// defaultGatewayVia reports the next hop the main table uses for one interface.
//
// A default route is not always a single-gateway route: some providers hand
// out an ECMP default (multiple weighted nexthops, e.g. a documented gateway
// alongside a link-local fallback), in which case the kernel reports the
// gateway on each entry in Route.MultiPath rather than on Route.Gw itself.
// Skipping those would leave a policy table's default route without a
// gateway, which silently blackholes every packet sent through it.
func defaultGatewayVia(linkIndex, family int) net.IP {
	routes, err := netlink.RouteList(nil, family)
	if err != nil {
		return nil
	}
	for _, route := range routes {
		if route.Table != 254 || (route.Dst != nil && !isDefaultRoute(route.Dst)) {
			continue
		}
		if route.LinkIndex == linkIndex && route.Gw != nil {
			return route.Gw
		}
		for _, hop := range route.MultiPath {
			if hop != nil && hop.LinkIndex == linkIndex && hop.Gw != nil {
				return hop.Gw
			}
		}
	}
	return nil
}

func isDefaultRoute(destination *net.IPNet) bool {
	ones, _ := destination.Mask.Size()
	return ones == 0
}

// clearPolicyTables empties the per-upstream tables, which is what returns a
// deployment that dropped back to a single upstream to plain main-table routing.
func (k *LinuxKernel) clearPolicyTables(upstreams []Upstream) error {
	for _, upstream := range upstreams {
		if err := flushRouteTable(upstreamRouteTable(upstream)); err != nil {
			return err
		}
	}
	return nil
}

func flushRouteTable(table int) error {
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return err
		}
		for _, route := range routes {
			existing := route
			if err = netlink.RouteDel(&existing); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

func (k *LinuxKernel) Inspect(cfg Settings, warp WarpAccount, upstreams []Upstream, tunnels []Tunnel) ([]string, error) {
	if k.DryRun {
		return nil, nil
	}
	wg, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer wg.Close()
	grouped := tunnelsByUpstream(upstreams, tunnels)
	var drift []string
	for _, upstream := range upstreams {
		upstreamDrift, inspectErr := k.inspectUpstream(wg, cfg, upstream, grouped[upstream.ID])
		if inspectErr != nil {
			return nil, inspectErr
		}
		for _, item := range upstreamDrift {
			drift = append(drift, upstream.Name+": "+item)
		}
	}
	warpDrift, err := k.inspectWarp(wg, cfg, warp, upstreams, tunnels)
	if err != nil {
		return nil, err
	}
	drift = append(drift, warpDrift...)
	return append(drift, k.inspectNDPProxy(upstreams, grouped)...), nil
}

func (k *LinuxKernel) inspectUpstream(wg *wgctrl.Client, cfg Settings, upstream Upstream, tunnels []Tunnel) ([]string, error) {
	link, err := netlink.LinkByName(upstream.InterfaceName)
	if _, ok := err.(netlink.LinkNotFoundError); ok {
		return []string{"WireGuard interface is missing"}, nil
	}
	if err != nil {
		return nil, err
	}
	dev, err := wg.Device(upstream.InterfaceName)
	if err != nil {
		return nil, err
	}
	desired := make(map[string]Tunnel)
	for _, t := range tunnels {
		if t.Enabled {
			desired[t.PublicKey] = t
		}
	}
	live := make(map[string]wgtypes.Peer)
	for _, peer := range dev.Peers {
		live[peer.PublicKey.String()] = peer
		if _, ok := desired[peer.PublicKey.String()]; !ok {
			return []string{"unmanaged or disabled WireGuard peer is present"}, nil
		}
	}
	var drift []string
	for key, t := range desired {
		peer, ok := live[key]
		if !ok {
			drift = append(drift, fmt.Sprintf("tunnel %d peer is missing", t.ID))
			continue
		}
		expected := map[string]bool{}
		for _, allowed := range tunnelAllowedIPs(cfg, upstream, t) {
			expected[allowed.String()] = true
		}
		if len(peer.AllowedIPs) != len(expected) {
			drift = append(drift, fmt.Sprintf("tunnel %d AllowedIPs differ", t.ID))
			continue
		}
		for _, allowed := range peer.AllowedIPs {
			if !expected[allowed.String()] {
				drift = append(drift, fmt.Sprintf("tunnel %d AllowedIPs differ", t.ID))
				break
			}
		}
	}
	routes, err := netlink.RouteList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	liveRoutes := make(map[string]bool)
	for _, route := range routes {
		if route.Dst != nil {
			liveRoutes[route.Dst.String()] = true
		}
	}
	for _, t := range tunnels {
		if !t.Enabled {
			continue
		}
		allocation, parseErr := netip.ParsePrefix(t.V6CIDR)
		if parseErr != nil {
			drift = append(drift, fmt.Sprintf("tunnel %d has an invalid allocation", t.ID))
			continue
		}
		if !liveRoutes[allocation.Masked().String()] {
			drift = append(drift, fmt.Sprintf("tunnel %d IPv6 route is missing", t.ID))
		}
		if tunnelIPv4Enabled(cfg, upstream, t) && !liveRoutes[t.V4Address+"/32"] {
			drift = append(drift, fmt.Sprintf("tunnel %d IPv4 route is missing", t.ID))
		}
	}
	return drift, nil
}

func (k *LinuxKernel) inspectWarp(wg *wgctrl.Client, cfg Settings, warp WarpAccount, upstreams []Upstream, tunnels []Tunnel) ([]string, error) {
	byID := upstreamsByID(upstreams)
	warpSources := make(map[string]bool)
	for _, tunnel := range tunnels {
		if resolvedV4Mode(cfg, byID, tunnel) == V4ModeWarp && tunnel.V4Address != "" {
			warpSources[tunnel.V4Address+"/32"] = true
		}
	}
	if len(warpSources) == 0 {
		return nil, nil
	}
	var drift []string
	link, linkErr := netlink.LinkByName(warpInterfaceName)
	if linkErr != nil {
		drift = append(drift, "Cloudflare WARP interface is missing")
	} else {
		warpDevice, deviceErr := wg.Device(warpInterfaceName)
		if deviceErr != nil || len(warpDevice.Peers) != 1 || warpDevice.Peers[0].PublicKey.String() != warp.PeerPublicKey || link.Attrs().Flags&net.FlagUp == 0 {
			drift = append(drift, "Cloudflare WARP interface differs")
		}
	}
	rules, rulesErr := netlink.RuleList(netlink.FAMILY_V4)
	if rulesErr != nil {
		return nil, rulesErr
	}
	foundSources := make(map[string]bool)
	for _, rule := range rules {
		if rule.Table == warpRouteTable && rule.Priority == warpRulePriority && rule.Src != nil {
			foundSources[rule.Src.String()] = true
		}
	}
	for source := range warpSources {
		if !foundSources[source] {
			drift = append(drift, "Cloudflare WARP policy rule is missing for "+source)
		}
	}
	warpRoutes, routesErr := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: warpRouteTable}, netlink.RT_FILTER_TABLE)
	if routesErr != nil {
		return nil, routesErr
	}
	for _, route := range warpRoutes {
		if route.Dst != nil && route.Dst.String() == "0.0.0.0/0" {
			return drift, nil
		}
	}
	return append(drift, "Cloudflare WARP policy route is missing"), nil
}

func (k *LinuxKernel) inspectNDPProxy(upstreams []Upstream, grouped map[int64][]Tunnel) []string {
	expected, err := k.desiredNDPProxySets(upstreams, grouped)
	if err != nil {
		return []string{"Neighbor Discovery proxy: " + err.Error()}
	}
	running := k.responder().states()
	var drift []string
	for name, set := range expected {
		current, ok := running[name]
		switch {
		case !ok:
			drift = append(drift, "Neighbor Discovery proxy is not running on "+name)
		case !current.equal(set):
			drift = append(drift, "Neighbor Discovery proxy on "+name+" does not match the delegated prefixes")
		}
	}
	for name := range running {
		if _, ok := expected[name]; !ok {
			drift = append(drift, "Neighbor Discovery proxy is running on "+name+" with no delegated prefix")
		}
	}
	return drift
}

func (k *LinuxKernel) Remove(upstream Upstream, t Tunnel) error {
	if k.DryRun {
		return nil
	}
	link, e := netlink.LinkByName(upstream.InterfaceName)
	if e == nil {
		if prefix, parseErr := netip.ParsePrefix(t.V6CIDR); parseErr == nil {
			_ = netlink.RouteDel(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: prefixIPNet(prefix), Priority: tunnelRouteMetric})
		}
		if a, parseErr := netip.ParseAddr(t.V4Address); parseErr == nil {
			_ = netlink.RouteDel(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: prefixIPNet(netip.PrefixFrom(a, 32))})
		}
	}
	wg, e := wgctrl.New()
	if e != nil {
		return e
	}
	defer wg.Close()
	pub, e := wgtypes.ParseKey(t.PublicKey)
	if e != nil {
		return e
	}
	return wg.ConfigureDevice(upstream.InterfaceName, wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: pub, Remove: true}}})
}

// RemoveUpstream tears down one provider connection: its WireGuard interface,
// which takes its peers and routes with it, and its policy table.
func (k *LinuxKernel) RemoveUpstream(upstream Upstream) error {
	if k.DryRun {
		return nil
	}
	if err := flushRouteTable(upstreamRouteTable(upstream)); err != nil {
		return err
	}
	link, err := netlink.LinkByName(upstream.InterfaceName)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return nil
		}
		return err
	}
	return netlink.LinkDel(link)
}

func (k *LinuxKernel) ensureWarp(cfg Settings, account WarpAccount, upstreams []Upstream, tunnels []Tunnel) error {
	if !account.Exists() {
		return errors.New("Cloudflare WARP is enabled but no account exists")
	}
	privateKey, err := wgtypes.ParseKey(account.PrivateKey)
	if err != nil {
		return fmt.Errorf("WARP private key: %w", err)
	}
	peerKey, err := wgtypes.ParseKey(account.PeerPublicKey)
	if err != nil {
		return fmt.Errorf("WARP peer key: %w", err)
	}
	address, err := netip.ParseAddr(account.IPv4Address)
	if err != nil || !address.Is4() {
		return errors.New("WARP account has no valid IPv4 address")
	}
	endpoint, err := net.ResolveUDPAddr("udp", account.Endpoint)
	if err != nil {
		return fmt.Errorf("resolve WARP endpoint: %w", err)
	}
	link, err := netlink.LinkByName(warpInterfaceName)
	if _, ok := err.(netlink.LinkNotFoundError); ok {
		generic := &netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: warpInterfaceName}, LinkType: "wireguard"}
		if err = netlink.LinkAdd(generic); err != nil {
			return err
		}
		link = generic
	} else if err != nil {
		return err
	}
	if err = netlink.LinkSetMTU(link, 1280); err != nil {
		return err
	}
	addresses, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	for _, existing := range addresses {
		if !existing.IP.Equal(net.ParseIP(account.IPv4Address)) {
			_ = netlink.AddrDel(link, &existing)
		}
	}
	if err = netlink.AddrReplace(link, &netlink.Addr{IPNet: addressIPNet(netip.PrefixFrom(address, 32))}); err != nil {
		return err
	}
	if err = netlink.LinkSetUp(link); err != nil {
		return err
	}
	wg, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer wg.Close()
	keepalive := 25 * time.Second
	allowed := *prefixIPNet(netip.MustParsePrefix("0.0.0.0/0"))
	if err = wg.ConfigureDevice(warpInterfaceName, wgtypes.Config{PrivateKey: &privateKey, ReplacePeers: true, Peers: []wgtypes.PeerConfig{{PublicKey: peerKey, Endpoint: endpoint, ReplaceAllowedIPs: true, AllowedIPs: []net.IPNet{allowed}, PersistentKeepaliveInterval: &keepalive}}}); err != nil {
		return err
	}
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	for _, existing := range rules {
		if existing.Table == warpRouteTable && existing.Priority == warpRulePriority {
			copy := existing
			_ = netlink.RuleDel(&copy)
		}
	}
	byID := upstreamsByID(upstreams)
	for _, tunnel := range tunnels {
		if resolvedV4Mode(cfg, byID, tunnel) != V4ModeWarp || tunnel.V4Address == "" {
			continue
		}
		source, parseErr := netip.ParseAddr(tunnel.V4Address)
		if parseErr != nil {
			return parseErr
		}
		rule := netlink.NewRule()
		rule.Family = netlink.FAMILY_V4
		rule.Priority = warpRulePriority
		rule.Table = warpRouteTable
		rule.Src = prefixIPNet(netip.PrefixFrom(source, 32))
		if err = netlink.RuleAdd(rule); err != nil {
			return err
		}
	}
	defaultRoute := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: prefixIPNet(netip.MustParsePrefix("0.0.0.0/0")), Table: warpRouteTable}
	if err = netlink.RouteReplace(defaultRoute); err != nil {
		return err
	}
	return nil
}

func (k *LinuxKernel) disableWarp() error {
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	for _, rule := range rules {
		if rule.Table == warpRouteTable && rule.Priority == warpRulePriority {
			copy := rule
			_ = netlink.RuleDel(&copy)
		}
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: warpRouteTable}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return err
	}
	for _, route := range routes {
		copy := route
		_ = netlink.RouteDel(&copy)
	}
	if link, linkErr := netlink.LinkByName(warpInterfaceName); linkErr == nil {
		if err = netlink.LinkDel(link); err != nil {
			return err
		}
	} else if _, ok := linkErr.(netlink.LinkNotFoundError); !ok {
		return linkErr
	}
	return nil
}

func (k *LinuxKernel) TestWarp(ctx context.Context, cfg Settings, account WarpAccount) (string, error) {
	if k.DryRun {
		return "fl=test\nip=203.0.113.8\nwarp=on\n", nil
	}
	if !account.Exists() {
		return "", errors.New("Cloudflare WARP IPv4 egress is not ready")
	}
	pool, err := netip.ParsePrefix(cfg.V4Pool)
	if err != nil {
		return "", err
	}
	testAddress := pool.Masked().Addr()
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		return "", err
	}
	temporary := &netlink.Addr{IPNet: addressIPNet(netip.PrefixFrom(testAddress, 32))}
	if err = netlink.AddrReplace(loopback, temporary); err != nil {
		return "", err
	}
	defer func() { _ = netlink.AddrDel(loopback, temporary) }()
	rule := netlink.NewRule()
	rule.Family = netlink.FAMILY_V4
	rule.Priority = warpRulePriority - 1
	rule.Table = warpRouteTable
	rule.Src = prefixIPNet(netip.PrefixFrom(testAddress, 32))
	_ = netlink.RuleDel(rule)
	if err = netlink.RuleAdd(rule); err != nil {
		return "", err
	}
	defer func() { _ = netlink.RuleDel(rule) }()
	dialer := &net.Dialer{Timeout: 8 * time.Second, LocalAddr: &net.TCPAddr{IP: net.IP(testAddress.AsSlice())}}
	client := &http.Client{Timeout: 12 * time.Second, Transport: &http.Transport{Proxy: nil, DialContext: dialer.DialContext}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://1.1.1.1/cdn-cgi/trace", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("WARP trace request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
	if err != nil {
		return "", err
	}
	trace := strings.TrimSpace(string(body))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("WARP trace returned HTTP %d", resp.StatusCode)
	}
	mode := firstTraceValue(trace, "warp")
	if mode != "on" && mode != "plus" {
		return "", fmt.Errorf("Cloudflare trace reports warp=%s", mode)
	}
	if firstTraceValue(trace, "ip") == "" {
		return "", errors.New("Cloudflare trace did not report an outbound IP")
	}
	return trace + "\n", nil
}

// desiredNDPProxySets reads the host addresses of every on-link upstream's
// egress interface and builds the address set each of those interfaces must
// answer for.
func (k *LinuxKernel) desiredNDPProxySets(upstreams []Upstream, grouped map[int64][]Tunnel) (map[string]ndpProxySet, error) {
	local := make(map[string][]netip.Addr)
	for _, upstream := range upstreams {
		if upstreamMode(upstream) != UpstreamOnLink {
			continue
		}
		if upstream.EgressInterface == "" {
			return nil, fmt.Errorf("upstream %q uses on-link delegation but has no egress interface", upstream.Name)
		}
		if _, ok := local[upstream.EgressInterface]; ok {
			continue
		}
		addresses, err := upstreamLocalAddresses(upstream.EgressInterface)
		if err != nil {
			return nil, fmt.Errorf("read addresses of %s: %w", upstream.EgressInterface, err)
		}
		local[upstream.EgressInterface] = addresses
	}
	return ndpProxySetsFor(upstreams, grouped, local), nil
}

// applyNDPProxy reconciles the Neighbor Discovery proxies with the delegated
// prefixes of every on-link upstream. It also enables the kernel's own
// proxy_ndp and forwarding flags on those egress interfaces, because a proxied
// advertisement is only useful if the host then forwards the traffic it
// attracts.
func (k *LinuxKernel) applyNDPProxy(upstreams []Upstream, grouped map[int64][]Tunnel) error {
	sets, err := k.desiredNDPProxySets(upstreams, grouped)
	if err != nil {
		return fmt.Errorf("neighbor discovery proxy: %w", err)
	}
	for name := range sets {
		for _, setting := range []string{"forwarding", "proxy_ndp"} {
			if err = writeSysctl(fmt.Sprintf("net/ipv6/conf/%s/%s", name, setting), "1"); err != nil {
				return fmt.Errorf("neighbor discovery proxy: %w", err)
			}
		}
	}
	return k.responder().Configure(sets)
}

// pinUpstreamNeighbors keeps the host's provider router reachable when a tunnel
// route covers the address used to reach it. Each on-link next hop inside the
// delegated prefix gets a /128 route out of the egress interface, which is
// always more specific than a tunnel's prefix route.
func (k *LinuxKernel) pinUpstreamNeighbors(upstream Upstream) error {
	if upstreamMode(upstream) != UpstreamOnLink || upstream.EgressInterface == "" {
		return nil
	}
	prefix, ok := delegatedPrefix(upstream)
	if !ok {
		return nil
	}
	link, err := netlink.LinkByName(upstream.EgressInterface)
	if err != nil {
		return fmt.Errorf("egress interface %s: %w", upstream.EgressInterface, err)
	}
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V6)
	if err != nil {
		return err
	}
	for _, route := range routes {
		gateway, ok := netip.AddrFromSlice(route.Gw)
		if !ok || route.LinkIndex != link.Attrs().Index {
			continue
		}
		gateway = gateway.Unmap()
		if !prefix.Contains(gateway) {
			continue
		}
		pinned := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: prefixIPNet(netip.PrefixFrom(gateway, 128)), Protocol: 0x42, Priority: gatewayRouteMetric}
		if err = netlink.RouteReplace(pinned); err != nil {
			return fmt.Errorf("pin upstream gateway %s: %w", gateway, err)
		}
	}
	return nil
}

// writeSysctl sets one kernel networking flag, treating an already-correct
// value as success so that a read-only sysctl path is not a hard failure.
func writeSysctl(path, value string) error {
	full := "/proc/sys/" + path
	if current, err := os.ReadFile(full); err == nil && strings.TrimSpace(string(current)) == value {
		return nil
	}
	if err := os.WriteFile(full, []byte(value+"\n"), 0o644); err != nil {
		return fmt.Errorf("set %s=%s: %w", path, value, err)
	}
	return nil
}

func (k *LinuxKernel) applyNAT(ctx context.Context, cfg Settings, upstreams []Upstream, tunnels []Tunnel) error {
	script, err := buildNFTScript(cfg, upstreams, tunnels)
	if err != nil {
		return err
	}
	return runNft(ctx, script)
}
func runNft(ctx context.Context, script string) error {
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, e := cmd.CombinedOutput()
	if e != nil && strings.Contains(script, "delete table") && strings.Contains(string(out), "No such file") {
		lines := strings.SplitN(script, "\n", 2)
		if len(lines) == 2 {
			return runNft(ctx, lines[1])
		}
		return nil
	}
	if e != nil {
		return fmt.Errorf("nft: %s: %w", strings.TrimSpace(string(out)), e)
	}
	return nil
}
func prefixIPNet(p netip.Prefix) *net.IPNet {
	p = p.Masked()
	a := p.Addr()
	return &net.IPNet{IP: net.IP(a.AsSlice()), Mask: net.CIDRMask(p.Bits(), a.BitLen())}
}

func addressIPNet(p netip.Prefix) *net.IPNet {
	a := p.Addr()
	return &net.IPNet{IP: net.IP(a.AsSlice()), Mask: net.CIDRMask(p.Bits(), a.BitLen())}
}
