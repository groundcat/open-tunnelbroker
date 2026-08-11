# Open IPv6 Tunnelbroker

Open IPv6 Tunnelbroker is a small, self-hosted admin panel for redistributing routed IPv6 prefixes over WireGuard. Any number of independent upstreams can be configured, each with its own provider connection, delegated prefix, and WireGuard interface. SQLite is the desired-state store; the daemon owns every WireGuard peer table, the routes, the policy routing tables, and its dedicated nftables table, and reconciles them at startup and on demand.

The project is intentionally host-native: one Go binary, no container, no JavaScript build, and a server-rendered admin UI.

## What it does

- Manages any number of **upstreams**. Each one is an independent provider connection — WireGuard, L2TP/PPP, a BGP-learned path, plain Ethernet, or anything else that terminates on an interface — with its own delegated prefix, delegation mode, egress interface, WireGuard interface, listening endpoint, server key, MTU, and allocation sizes. Upstreams are mutually irrelevant: overlapping prefixes, duplicate interfaces, and shared listening endpoints are rejected at configuration time.
- Allocates variable IPv6 CIDRs from a chosen upstream's prefix using cryptographically random selection across all currently free, correctly aligned subprefixes. Free space is rebuilt per upstream from that upstream's assigned tunnels, so no free-list can drift and existing or reserved ranges cannot collide.
- Supports both routed prefixes and providers that place the prefix on-link, per upstream and in any mix, including a VPS whose only allocation is a single `/64`. On-link delegation hands the entire prefix to one tunnel and answers that provider's Neighbor Discovery for it automatically, with no per-address setup.
- Adds/removes WireGuard peers through the kernel API and adds matching routes immediately, on the interface belonging to the tunnel's own upstream.
- Sends each delegated prefix back out of the provider that delegated it, using source policy routing, so a source address from one provider is never emitted through another.
- Applies an interface-scoped default-deny forwarding policy per upstream and optionally assigns RFC1918 addresses masqueraded through either that tunnel's own upstream or an IPv4-only Cloudflare WARP interface.
- Isolates tunnels from each other by default, with optional all-to-all or same-routing-group IPv4 and IPv6 communication that never applies NAT between tunnels. The policy spans upstreams, so two tunnels fed by unrelated providers can still reach each other when permitted.
- Resolves IPv4 egress in three levels: a tunnel overrides its upstream, which overrides the global default. An upstream with no IPv4 connectivity can opt all of its tunnels out without touching the rest of the deployment.
- Creates/recreates a free WARP account from the admin UI and tests its reported outbound IPv4 address. One account serves every upstream that selects it. Native and WARP IPv4 modes are mutually exclusive at each level; IPv6 always stays on the delegating upstream.
- Generates client configs from either a supplied client public key or a server-generated keypair.
- Authenticates admins with bcrypt, HttpOnly sessions, SameSite cookies, and CSRF tokens.
- Marks failed applies as errors and reconciles all desired state after every restart or manual resync.

## Supported host

Linux with a WireGuard-capable kernel, `nft`, and systemd. The daemon must have `CAP_NET_ADMIN`, plus `CAP_NET_RAW` for on-link Neighbor Discovery proxying; the supplied unit grants both and runs as root with a restricted filesystem and capability set. SQLite and WireGuard private keys live in `/var/lib/open-tunnelbroker`, which must be backed up securely.

Every upstream transport is deliberately separate and is established outside this application. L2TP, DHCPv6-PD, a static routed prefix, a BGP session, or another WireGuard tunnel can all serve as an upstream, in any combination, as long as the host owns each delegated prefix and each connection terminates on its own interface. Return traffic normally has to be routed to the host; when a provider treats its prefix as on-link instead, select that delegation mode for that upstream and the daemon answers the resulting Neighbor Discovery itself. On-link proxying additionally requires that the upstream's egress interface be Ethernet; other upstreams on the same host are unaffected by that requirement.

## Build and test

Go 1.24 or newer is required.

```sh
go test ./...
CGO_ENABLED=0 go build -trimpath -o bin/open-tunnelbroker ./cmd/open-tunnelbroker
```

The equivalent `make test` and `make build VERSION=...` targets are provided when GNU Make is installed.

## Releases

Pushing a semantic version tag (for example, `v1.2.3`) to GitHub runs the test suite and creates a GitHub Release. Each release contains statically linked Linux archives for Debian/Ubuntu hosts on `amd64` and `arm64`, with SHA-256 checksum files. The executable reports the exact tag with `open-tunnelbroker -version`.

```sh
git tag v1.2.3
git push origin v1.2.3
```

## Install

1. Establish each provider connection first. For every one, note the delegated prefix, its egress interface (for example `ppp0` or `eth0`), and whether the provider routes the prefix or treats it as on-link — see [Prefix delegation](#prefix-delegation-routed-or-on-link). Do not store provider credentials in this repository.
2. Install prerequisites and the binary:

   ```sh
   sudo apt-get update
   sudo apt-get install -y nftables wireguard-tools nginx
   sudo install -m 0755 bin/open-tunnelbroker /usr/local/sbin/open-tunnelbroker
   sudo install -d -m 0755 /usr/local/libexec
   sudo install -m 0755 deploy/open-tunnelbroker-upgrade /usr/local/libexec/open-tunnelbroker-upgrade
   sudo install -d -m 0700 /var/lib/open-tunnelbroker /etc/open-tunnelbroker
   sudo install -m 0644 deploy/open-tunnelbroker.service /etc/systemd/system/
   sudo install -m 0644 deploy/open-tunnelbroker-upgrade.service /etc/systemd/system/
   sudo install -m 0644 deploy/sysctl.conf /etc/sysctl.d/90-open-tunnelbroker.conf
   ```

3. Bootstrap the only initial admin. The environment value is read only when no admin exists; remove it after first start:

   ```sh
   sudo sh -c 'umask 077; printf "OTB_ADMIN_PASSWORD=%s\n" "replace-with-a-long-random-password" > /etc/open-tunnelbroker/environment'
   sudo sysctl --system
   sudo systemctl daemon-reload
   sudo systemctl enable --now open-tunnelbroker
   sudo rm /etc/open-tunnelbroker/environment
   ```

4. Keep port 8080 bound to loopback. Put HTTPS in front with nginx (see `deploy/nginx.conf`) or reach it temporarily with `ssh -L 8080:127.0.0.1:8080 host`. Plain HTTP login is accepted only on a loopback Host; remote administration requires HTTPS.
5. On the **Upstreams** page, add one upstream per provider connection: its name, delegated IPv6 CIDR, prefix delegation mode, egress interface, WireGuard interface name, public endpoint, and allocation limits. For a routed prefix, also set a server address inside a reserved infrastructure slice (commonly the first address of the first `/64`). For an on-link prefix, leave the server address empty; the allocation limits and WireGuard transport address are filled in automatically, and each upstream is given its own transport range. Saving generates that upstream's server WireGuard key on first use.
6. In **Settings**, set the deployment-wide preferences: default DNS, default IPv4 egress mode, and the internal IPv4 pool. One pool serves every upstream, and its addresses are unique across the deployment.
7. Permit each upstream's WireGuard UDP port at the VPS/provider firewall. Two upstreams may not share the same endpoint host and port. The app owns only the nftables table named `open_tunnelbroker`; keep management firewall policy in a separate table.

### Web upgrades

The **Upgrade** page can fast-forward the deployment checkout from its existing `origin`, run the full test suite, build and atomically install the new binary, and restart the daemon. It will refuse a dirty checkout, detached HEAD, or non-fast-forward update. The main web service can only request the fixed `open-tunnelbroker-upgrade.service`; Git, build, install, and restart privileges remain in that separate one-shot unit.

Keep the deployment checkout at `/opt/open-tunnelbroker`, or configure `/etc/open-tunnelbroker/upgrade`:

```sh
OTB_UPGRADE_REPO=/opt/open-tunnelbroker
OTB_UPGRADE_BINARY=/usr/local/sbin/open-tunnelbroker
OTB_UPGRADE_TARGET_SERVICE=open-tunnelbroker.service
OTB_GO_BINARY=/usr/local/go/bin/go
```

The checkout must have a working `origin` remote and unattended read credentials. The upgrade service records progress in `/var/lib/open-tunnelbroker/upgrade-status`. After installing or changing either unit, run `sudo systemctl daemon-reload`.

### Optional Cloudflare WARP IPv4 egress

In Settings, create a WARP account and then select **Cloudflare WARP NAT** as an IPv4 egress mode, globally or on any upstream or tunnel. The app creates `wg-warp` with IPv4 AllowedIPs only, sends the internal RFC1918 pool through policy table 51822, and masquerades it to the WARP-assigned address. It never installs a WARP IPv6 address, AllowedIP, route, or policy rule.

Enabling either native or WARP IPv4 egress automatically assigns an RFC1918 address to every existing and future tunnel and renders `0.0.0.0/0, ::/0` in client configs. Disabling IPv4 egress immediately returns configs and kernel AllowedIPs/routes to IPv6-only mode; the internal assignments are retained for stable reuse.

The global IPv4 egress mode is the deployment-wide default. Each upstream may override it for the tunnels it delegates, and each tunnel may override its upstream: a tunnel beats its upstream, which beats the global setting. Native mode masquerades a tunnel through the egress interface of its own upstream, so a dual-provider host NATs each tunnel to the correct public address; an upstream with no IPv4 connectivity can be set to disabled or to WARP instead. Native and WARP tunnels can coexist across and within upstreams; WARP overrides require a registered WARP account, and one account serves all of them.

Each tunnel also has a combined upload and download quota, measured in GiB and defaulting to 100 GiB. Usage is sampled during the 30-second reconciliation cycle. A tunnel is disabled and removed from WireGuard as soon as a sample reaches its quota. Quota usage resets on the first reconciliation of each UTC calendar month; tunnels disabled by quota enforcement are automatically restored, while manually disabled tunnels remain disabled.

### Inter-tunnel routing

The **Routing** page controls communication between tunnels:

- **Isolated** is the secure default and installs no WireGuard-to-WireGuard forwarding rule at all, within or across upstreams.
- **Shared managed group** permits traffic when two active tunnels share at least one group. The **Groups** page creates, renames, and deletes reusable tags; tunnel creation and detail pages assign zero, one, or multiple groups with a multi-select control.
- **Any tunnel** permits all active tunnels to communicate.

The policy is deployment-wide rather than per upstream, so two tunnels fed by unrelated providers can reach each other exactly when two tunnels on one provider could. Rules are emitted for every ordered pair of managed WireGuard interfaces, and destinations inside any delegated prefix stay in the main routing table so the cross-upstream path actually resolves.

Each managed group is rendered as an nftables IPv6 interval set containing delegated prefixes and an IPv4 address set containing internal addresses, drawn from every upstream. Rules require both source and destination membership in the same set, so membership in multiple groups naturally grants the union of those relationships, and a group that spans providers works without further configuration. WireGuard AllowedIPs continue to enforce source ownership, original addresses are preserved, and inter-tunnel packets never match an egress masquerade rule. Combined quota accounting charges the sender's upload and the recipient's download.

Use **Test WARP outbound IP** to request `https://1.1.1.1/cdn-cgi/trace` through that exact source-policy path. The returned trace and test time are saved for the admin UI. Selecting native NAT and WARP simultaneously at the same level is rejected.

Account creation sends a locally generated WireGuard public key, device type, locale, and current terms-of-service timestamp to Cloudflare's WARP registration API. Review Cloudflare's applicable terms before enabling this optional integration.

### Example addressing

For an upstream `2001:db8:1200::/48`, use `2001:db8:1200::1/64` as the server address, min/default/max prefixes of 48/56/64, and create `/56` or `/64` tunnels. The server's `/64` is automatically excluded from allocations. IPv6 is routed, never NATed.

A second, unrelated upstream is configured the same way and shares nothing with the first. For instance, a routed `2001:db8:1200::/48` from a fiber provider on `eth0` with WireGuard `wg0` on port 51820, alongside an on-link `2001:db8:900:416::/64` from a VPS reached over L2TP on `ppp0` with WireGuard `wg1` on port 51821. Tunnels are allocated from whichever upstream is selected and always egress through that provider.

## Multiple upstreams

Every provider connection is modelled as one upstream, and each upstream owns:

- a delegated IPv6 prefix and its delegation mode (routed or on-link),
- the egress interface that reaches the provider,
- its own WireGuard interface, listening endpoint, server keypair, MTU, and keepalive,
- its own allocation limits and, for on-link delegation, its own transport range,
- an optional IPv4 egress override for the tunnels it delegates.

Prefixes, WireGuard interface names, transport ranges, and listening endpoints must not collide, and an upstream may not be renumbered or deleted while tunnels still depend on it. These are refused at configuration time with an actionable message rather than surfacing later as drift.

### Egress and interconnection

With more than one upstream configured, the daemon installs source policy routing:

- Traffic destined for another delegated prefix, another transport range, or the internal IPv4 pool is matched first (priority 100) and left to the main routing table, where every tunnel route lives. This is what allows a tunnel on one upstream to reach a tunnel on another.
- Everything else is matched by source address (priority 110) and sent to a per-upstream table holding that provider's default route, so an address delegated by one provider is never emitted through another — which upstream BCP 38 ingress filtering would otherwise drop.

A deployment with a single upstream installs no rules at all and routes exactly as before.

Whether tunnels may actually talk to each other is governed by the **Routing** page, and that decision spans upstreams. Under *Any tunnel*, every pair of managed WireGuard interfaces is permitted, so a tunnel on the fiber upstream can reach one on the VPS upstream. Under *Shared managed group*, the same holds for tunnels that share a group, with membership matched on addresses rather than interfaces. Under the default *Isolated*, nothing is permitted in either direction. Inter-tunnel traffic is never masqueraded, so source addresses are preserved across upstreams too.

## Prefix delegation: routed or on-link

Before configuring an upstream, determine whether that provider **routes** the prefix to this host or treats it as **on-link**. The **Prefix delegation** setting on the upstream selects between them, and the choice changes nothing else about how tunnels are managed. The setting is per upstream, so routed and on-link providers can coexist on one host.

Check `ip -6 route show` and the provider's documentation:

```sh
ip -6 addr show dev eth0     # is the delegated prefix configured here with its own prefix length?
ip -6 route show             # is there a route for the prefix pointing at this host?
```

**Routed** is the normal case and the default. The provider routes the whole block to the host, so subprefixes only need a route out of the WireGuard interface. Every prefix size within the configured limits can be allocated.

**On-link** covers the common VPS arrangement — Vultr, Linode, Hetzner and similar — where the provider assigns exactly one `/64`, places it on the server's Ethernet interface, and resolves each address in it with Neighbor Discovery on the upstream segment:

```text
Internet router
    |
    | Neighbor Discovery
    v
 VPS eth0
    |
 [NDP proxy]
    |
 WireGuard
    |
 OpenWrt
    |
 /64 LAN
```

Because the delegated addresses actually live behind WireGuard, that provider's router solicitations would go unanswered. Selecting on-link delegation for the upstream makes the daemon answer them for the whole prefix on that upstream's egress interface, so the deployment needs no `ip -6 neigh add proxy` entry per address and no `ndppd`. One responder runs per egress interface, and it answers only for the prefixes delegated over interfaces it is bound to, so an unrelated provider on another interface is never affected. Solicitations are validated the way RFC 4861 requires — hop limit 255, correct ICMPv6 checksum — and the host's own addresses are never proxied, so it stays reachable. Replies never set the Override flag and so cannot displace a genuine neighbor entry.

A single `/64` cannot be subdivided, because SLAAC needs a full `/64` on the downstream LAN. Selecting on-link delegation therefore configures the deployment accordingly by itself:

- The entire `/64` becomes the one allocation size, so the first tunnel receives the whole prefix. Allocation limits are set to match rather than requiring the admin to compute them.
- No address inside the prefix is reserved for the server, since the host keeps its provider-assigned address on that egress interface.
- The WireGuard transport is numbered from a separate ULA, because the delegated prefix has no room to spare. Each upstream is given the first free `fd00:6b72:6f6b:N::1/64` subnet, and the value is configurable; two upstreams can never share one range. This range never appears on the Internet.
- `net.ipv6.conf.<egress>.forwarding` and `proxy_ndp` are enabled on that egress interface, and the provider's gateway is pinned to a host route so that delegating the whole prefix cannot strand the server's own connectivity.

The generated client configuration reflects this: the peer's tunnel interface takes the transport address, and the delegated prefix is listed as a comment to put on the LAN instead. On OpenWrt, assign the prefix to the LAN interface and set **RA: server**, **DHCPv6: server**, **NDP: disabled**; `odhcpd` then advertises it and clients autoconfigure normally. IPv6 stays routed end to end with no NAT66.

If the provider offers a `/56` or `/48` instead, prefer that with routed delegation: multiple downstream LANs then each get their own `/64`. A host that has both — a routed block from one provider and a single on-link `/64` from another — configures each as its own upstream and serves them side by side.

## L2TP and delegated prefixes

Provider setup varies. On Ubuntu a typical L2TP connection is managed by NetworkManager or `xl2tpd`, while DHCPv6-PD is handled on the resulting PPP interface. Before starting this app, verify:

```sh
ip -6 route show
ip -6 addr show
ping -6 -c 3 2606:4700:4700::1111
```

With routed delegation the provider must route the entire delegated block back through the session; assigning a prefix locally cannot substitute for that route. A provider that instead resolves the prefix with Neighbor Discovery is the on-link case described above. Each such connection becomes one upstream, pointed at the interface the session creates. If PD changes, update that upstream and reassign its tunnels intentionally; existing allocations are not silently rewritten, and an edit that would place a live tunnel outside the new prefix is refused.

## Operations

- Health and failed reconciliation are visible on the dashboard. `journalctl -u open-tunnelbroker` has underlying errors.
- Back up with `sqlite3 /var/lib/open-tunnelbroker/broker.db '.backup /secure/path/broker.db'`. Protect the backup: it contains server, WARP, and convenience-generated client private keys.
- Never run `wg set`, modify app-owned routes, edit `wg-warp`, or edit the `inet open_tunnelbroker` nftables table by hand. A resync restores database state and removes unmanaged peers.
- Deleting a tunnel first removes its kernel peer/routes, then deletes its row and frees its prefix. If kernel removal fails, the allocation remains recorded rather than being accidentally reused.
- `-dry-run` is intended for UI/schema evaluation on non-Linux development machines; it makes no network changes.
- **Reset general settings to defaults** disables IPv4 and restores the default pool, DNS, and inter-tunnel policy. It deliberately preserves every upstream in full — prefixes, delegation modes, transport addresses, endpoint hosts, interfaces, server addresses and keys, allocation sizes — and any stored WARP account, because those describe the deployment rather than a preference.
- Deleting an upstream removes its WireGuard interface and its policy routing table. It is refused while tunnels are still allocated from it, so an allocation can never be silently stranded. Renaming an upstream's WireGuard interface tears down the previous device.
- With on-link delegation the dashboard reports drift per upstream if a Neighbor Discovery proxy is not running or no longer matches the delegated prefixes. One listener runs per egress interface, and two on-link upstreams sharing an interface share a single merged listener. The proxies are stopped on shutdown; routes, peers, and nftables rules are deliberately left in place so a restart does not interrupt traffic.
- Upgrading from a single-upstream release migrates the former Settings fields into one upstream named `primary`, keeping its prefix, keys, interfaces, endpoint, delegation mode, and allocation limits exactly as they were, and attaches every existing tunnel to it. No addressing changes and no client configuration is invalidated.

## Development

```sh
OTB_ADMIN_PASSWORD='at-least-twelve-characters' \
  ./bin/open-tunnelbroker -dry-run -db ./dev.db -listen 127.0.0.1:8080
```

Schema migrations are forward-only statements in `internal/broker/store.go`, including the conversion of a pre-upstream database into its first upstream row. Allocation behavior is covered in `internal/broker/allocator_test.go`. Networking is behind the `Kernel` interface so service tests can use a fake implementation; multi-upstream allocation, collision rejection, per-upstream egress, and the legacy migration are covered in `service_test.go`, `firewall_test.go`, and `web_test.go`.

Neighbor Discovery is split so that its logic is testable without privileges: `internal/broker/ndp.go` holds the packet codec and the per-interface proxy address sets, covered by `ndp_test.go`, while `ndp_linux.go` holds only the privileged socket loop and the manager that runs one responder per egress interface. The single-`/64` workflow and the per-upstream proxy scoping are covered end to end in `onlink_test.go`.

## Security boundaries

This is an administrator-only control plane, not a public tunnel-signup portal. Use HTTPS, restrict access by firewall/VPN where possible, keep SQLite mode `0600`, and rotate the bootstrap password. Client-supplied public keys are preferred because the server never sees their private keys. Preshared keys are stored because they are required to render and reapply configurations.

## License

MIT; see [LICENSE](LICENSE).
