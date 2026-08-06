//go:build linux

package broker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os/exec"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Kernel interface {
	Apply(context.Context, Settings, WarpAccount, []Tunnel) ([]Tunnel, error)
	Inspect(Settings, WarpAccount, []Tunnel) ([]string, error)
	Remove(Settings, Tunnel) error
	TestWarp(context.Context, Settings, WarpAccount) (string, error)
}
type LinuxKernel struct{ DryRun bool }

const (
	warpRouteTable   = 51822
	warpRulePriority = 90
)

func (k *LinuxKernel) Apply(ctx context.Context, cfg Settings, warp WarpAccount, tunnels []Tunnel) ([]Tunnel, error) {
	if k.DryRun {
		return tunnels, nil
	}
	if cfg.InterfaceName == "" {
		return nil, errors.New("interface name is required")
	}
	key, err := wgtypes.ParseKey(cfg.ServerPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("server private key: %w", err)
	}
	link, err := netlink.LinkByName(cfg.InterfaceName)
	if _, ok := err.(netlink.LinkNotFoundError); ok {
		g := &netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: cfg.InterfaceName}, LinkType: "wireguard"}
		if err = netlink.LinkAdd(g); err != nil {
			return nil, err
		}
		link = g
	} else if err != nil {
		return nil, err
	}
	if cfg.ServerAddress != "" {
		p, e := netip.ParsePrefix(cfg.ServerAddress)
		if e != nil {
			return nil, fmt.Errorf("server address: %w", e)
		}
		upstream, e := netip.ParsePrefix(cfg.UpstreamV6)
		if e != nil {
			return nil, fmt.Errorf("upstream prefix: %w", e)
		}
		addresses, e := netlink.AddrList(link, netlink.FAMILY_V6)
		if e != nil {
			return nil, e
		}
		for _, existing := range addresses {
			addr, ok := netip.AddrFromSlice(existing.IP)
			if ok && upstream.Contains(addr) && addr != p.Addr() {
				if e = netlink.AddrDel(link, &existing); e != nil {
					return nil, e
				}
			}
		}
		ipnet := addressIPNet(p)
		if e = netlink.AddrReplace(link, &netlink.Addr{IPNet: ipnet}); e != nil {
			return nil, e
		}
	}
	if err = netlink.LinkSetUp(link); err != nil {
		return nil, err
	}
	wg, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer wg.Close()
	dev, err := wg.Device(cfg.InterfaceName)
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
		pc := wgtypes.PeerConfig{PublicKey: pub, ReplaceAllowedIPs: true, AllowedIPs: []net.IPNet{*prefixIPNet(netip.MustParsePrefix(t.V6CIDR))}}
		if tunnelIPv4Enabled(cfg, t) {
			a := netip.MustParseAddr(t.V4Address)
			pc.AllowedIPs = append(pc.AllowedIPs, *prefixIPNet(netip.PrefixFrom(a, 32)))
		}
		if t.PresharedKey != "" {
			psk, e := wgtypes.ParseKey(t.PresharedKey)
			if e != nil {
				return nil, e
			}
			pc.PresharedKey = &psk
		}
		if cfg.Keepalive > 0 {
			d := time.Duration(cfg.Keepalive) * time.Second
			pc.PersistentKeepaliveInterval = &d
		}
		peers = append(peers, pc)
	}
	for _, p := range dev.Peers {
		if t, ok := desired[p.PublicKey.String()]; !ok || !t.Enabled {
			peers = append(peers, wgtypes.PeerConfig{PublicKey: p.PublicKey, Remove: true})
		}
	}
	port := cfg.EndpointPort
	if err = wg.ConfigureDevice(cfg.InterfaceName, wgtypes.Config{PrivateKey: &key, ListenPort: &port, ReplacePeers: false, Peers: peers}); err != nil {
		return nil, err
	}
	dev, err = wg.Device(cfg.InterfaceName)
	if err != nil {
		return nil, err
	}
	for i, t := range tunnels {
		p := netip.MustParsePrefix(t.V6CIDR)
		v6Route := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: prefixIPNet(p), Protocol: 0x42}
		if t.Enabled {
			if err = netlink.RouteReplace(v6Route); err != nil {
				return nil, err
			}
		} else {
			_ = netlink.RouteDel(v6Route)
		}
		if t.V4Address != "" {
			a := netip.MustParseAddr(t.V4Address)
			v4Route := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: prefixIPNet(netip.PrefixFrom(a, 32)), Protocol: 0x42}
			if t.Enabled && tunnelIPv4Enabled(cfg, t) {
				if err = netlink.RouteReplace(v4Route); err != nil {
					return nil, err
				}
			} else {
				_ = netlink.RouteDel(v4Route)
			}
		}
		for _, live := range dev.Peers {
			if live.PublicKey.String() == t.PublicKey {
				tunnels[i].LastHandshake = live.LastHandshakeTime
				tunnels[i].RXBytes = live.ReceiveBytes
				tunnels[i].TXBytes = live.TransmitBytes
			}
		}
	}
	warpEnabled := false
	for _, t := range tunnels {
		warpEnabled = warpEnabled || tunnelV4Mode(cfg, t) == V4ModeWarp
	}
	if warpEnabled {
		if err = k.ensureWarp(cfg, warp, tunnels); err != nil {
			return tunnels, err
		}
	} else if err = k.disableWarp(); err != nil {
		return tunnels, err
	}
	if err = k.applyNAT(ctx, cfg, tunnels); err != nil {
		return tunnels, err
	}
	return tunnels, nil
}

func (k *LinuxKernel) Inspect(cfg Settings, warp WarpAccount, tunnels []Tunnel) ([]string, error) {
	if k.DryRun {
		return nil, nil
	}
	link, err := netlink.LinkByName(cfg.InterfaceName)
	if _, ok := err.(netlink.LinkNotFoundError); ok {
		return []string{"WireGuard interface is missing"}, nil
	}
	if err != nil {
		return nil, err
	}
	wg, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer wg.Close()
	dev, err := wg.Device(cfg.InterfaceName)
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
		expected := map[string]bool{netip.MustParsePrefix(t.V6CIDR).String(): true}
		if tunnelIPv4Enabled(cfg, t) {
			expected[t.V4Address+"/32"] = true
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
		if !liveRoutes[netip.MustParsePrefix(t.V6CIDR).String()] {
			drift = append(drift, fmt.Sprintf("tunnel %d IPv6 route is missing", t.ID))
		}
		if tunnelIPv4Enabled(cfg, t) && !liveRoutes[t.V4Address+"/32"] {
			drift = append(drift, fmt.Sprintf("tunnel %d IPv4 route is missing", t.ID))
		}
	}
	warpSources := make(map[string]bool)
	for _, tunnel := range tunnels {
		if tunnelV4Mode(cfg, tunnel) == V4ModeWarp && tunnel.V4Address != "" {
			warpSources[tunnel.V4Address+"/32"] = true
		}
	}
	if len(warpSources) > 0 {
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
		defaultFound := false
		for _, route := range warpRoutes {
			if route.Dst != nil && route.Dst.String() == "0.0.0.0/0" {
				defaultFound = true
				break
			}
		}
		if !defaultFound {
			drift = append(drift, "Cloudflare WARP policy route is missing")
		}
	}
	return drift, nil
}

func (k *LinuxKernel) Remove(cfg Settings, t Tunnel) error {
	if k.DryRun {
		return nil
	}
	link, e := netlink.LinkByName(cfg.InterfaceName)
	if e == nil {
		_ = netlink.RouteDel(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: prefixIPNet(netip.MustParsePrefix(t.V6CIDR))})
		if t.V4Address != "" {
			a := netip.MustParseAddr(t.V4Address)
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
	return wg.ConfigureDevice(cfg.InterfaceName, wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: pub, Remove: true}}})
}

func (k *LinuxKernel) ensureWarp(cfg Settings, account WarpAccount, tunnels []Tunnel) error {
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
	for _, tunnel := range tunnels {
		if tunnelV4Mode(cfg, tunnel) != V4ModeWarp || tunnel.V4Address == "" {
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

func (k *LinuxKernel) applyNAT(ctx context.Context, cfg Settings, tunnels []Tunnel) error {
	if cfg.UpstreamInterface == "" {
		return errors.New("upstream interface is required")
	}
	script := fmt.Sprintf("delete table inet open_tunnelbroker\nadd table inet open_tunnelbroker\nadd chain inet open_tunnelbroker forward { type filter hook forward priority 0; policy drop; }\nadd rule inet open_tunnelbroker forward iifname %q oifname %q accept\nadd rule inet open_tunnelbroker forward iifname %q oifname %q ct state established,related accept\n", cfg.InterfaceName, cfg.UpstreamInterface, cfg.UpstreamInterface, cfg.InterfaceName)
	warpEnabled := false
	for _, tunnel := range tunnels {
		warpEnabled = warpEnabled || tunnelV4Mode(cfg, tunnel) == V4ModeWarp
	}
	if warpEnabled {
		script += fmt.Sprintf("add rule inet open_tunnelbroker forward iifname %q oifname %q accept\nadd rule inet open_tunnelbroker forward iifname %q oifname %q ct state established,related accept\n", cfg.InterfaceName, warpInterfaceName, warpInterfaceName, cfg.InterfaceName)
	}
	var natRules string
	for _, tunnel := range tunnels {
		if !tunnelIPv4Enabled(cfg, tunnel) {
			continue
		}
		egress := cfg.UpstreamInterface
		if tunnelV4Mode(cfg, tunnel) == V4ModeWarp {
			egress = warpInterfaceName
		}
		natRules += fmt.Sprintf("add rule inet open_tunnelbroker postrouting ip saddr %s/32 oifname %q masquerade\n", tunnel.V4Address, egress)
	}
	if natRules != "" {
		script += "add chain inet open_tunnelbroker postrouting { type nat hook postrouting priority 100; policy accept; }\n" + natRules
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
