//go:build linux

package broker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Kernel interface {
	Apply(context.Context, Settings, []Tunnel) ([]Tunnel, error)
	Inspect(Settings, []Tunnel) ([]string, error)
	Remove(Settings, Tunnel) error
}
type LinuxKernel struct{ DryRun bool }

func (k *LinuxKernel) Apply(ctx context.Context, cfg Settings, tunnels []Tunnel) ([]Tunnel, error) {
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
		ipnet := prefixIPNet(p)
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
		if t.V4Enabled && t.V4Address != "" {
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
		routes := []*netlink.Route{{LinkIndex: link.Attrs().Index, Dst: prefixIPNet(p), Protocol: 0x42}}
		if t.V4Enabled && t.V4Address != "" {
			a := netip.MustParseAddr(t.V4Address)
			routes = append(routes, &netlink.Route{LinkIndex: link.Attrs().Index, Dst: prefixIPNet(netip.PrefixFrom(a, 32)), Protocol: 0x42})
		}
		for _, route := range routes {
			if t.Enabled {
				if err = netlink.RouteReplace(route); err != nil {
					return nil, err
				}
			} else {
				_ = netlink.RouteDel(route)
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
	if err = k.applyNAT(ctx, cfg); err != nil {
		return tunnels, err
	}
	return tunnels, nil
}

func (k *LinuxKernel) Inspect(cfg Settings, tunnels []Tunnel) ([]string, error) {
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
		if t.V4Enabled && t.V4Address != "" {
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
		if t.V4Enabled && t.V4Address != "" && !liveRoutes[t.V4Address+"/32"] {
			drift = append(drift, fmt.Sprintf("tunnel %d IPv4 route is missing", t.ID))
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

func (k *LinuxKernel) applyNAT(ctx context.Context, cfg Settings) error {
	if cfg.UpstreamInterface == "" {
		return errors.New("upstream interface is required")
	}
	script := fmt.Sprintf("delete table inet open_tunnelbroker\nadd table inet open_tunnelbroker\nadd chain inet open_tunnelbroker forward { type filter hook forward priority 0; policy drop; }\nadd rule inet open_tunnelbroker forward iifname %q oifname %q accept\nadd rule inet open_tunnelbroker forward iifname %q oifname %q ct state established,related accept\n", cfg.InterfaceName, cfg.UpstreamInterface, cfg.UpstreamInterface, cfg.InterfaceName)
	if cfg.V4NAT {
		if cfg.V4Pool == "" {
			return errors.New("v4 NAT needs an internal pool")
		}
		script += fmt.Sprintf("add chain inet open_tunnelbroker postrouting { type nat hook postrouting priority 100; policy accept; }\nadd rule inet open_tunnelbroker postrouting ip saddr %s oifname %q masquerade\n", cfg.V4Pool, cfg.UpstreamInterface)
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
