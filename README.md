# Open IPv6 Tunnelbroker

Open IPv6 Tunnelbroker is a small, self-hosted admin panel for redistributing a routed IPv6 prefix over WireGuard. SQLite is the desired-state store; the daemon owns the WireGuard peer table, routes, and its dedicated nftables table and reconciles them at startup and on demand.

The project is intentionally host-native: one Go binary, no container, no JavaScript build, and a server-rendered admin UI.

## What it does

- Allocates variable IPv6 CIDRs from any upstream prefix using cryptographically random selection across all currently free, correctly aligned subprefixes. Free space is rebuilt from assigned tunnels, so no free-list can drift and existing or reserved ranges cannot collide.
- Supports both routed prefixes and providers that place the prefix on-link, including a VPS whose only allocation is a single `/64`. On-link delegation hands the entire prefix to one tunnel and answers upstream Neighbor Discovery for it automatically, with no per-address setup.
- Adds/removes WireGuard peers through the kernel API and adds matching routes immediately.
- Applies an interface-scoped default-deny forwarding policy and optionally assigns RFC1918 addresses masqueraded through either the native upstream or an IPv4-only Cloudflare WARP interface.
- Isolates tunnels from each other by default, with optional all-to-all or same-routing-group IPv4 and IPv6 communication that never applies NAT between tunnels.
- Creates/recreates a free WARP account from the admin UI and tests its reported outbound IPv4 address. Native and WARP IPv4 modes are mutually exclusive; IPv6 always stays on the configured upstream.
- Generates client configs from either a supplied client public key or a server-generated keypair.
- Authenticates admins with bcrypt, HttpOnly sessions, SameSite cookies, and CSRF tokens.
- Marks failed applies as errors and reconciles all desired state after every restart or manual resync.

## Supported host

Linux with a WireGuard-capable kernel, `nft`, and systemd. The daemon must have `CAP_NET_ADMIN`, plus `CAP_NET_RAW` for on-link Neighbor Discovery proxying; the supplied unit grants both and runs as root with a restricted filesystem and capability set. SQLite and WireGuard private keys live in `/var/lib/open-tunnelbroker`, which must be backed up securely.

The upstream transport is deliberately separate. L2TP, DHCPv6-PD, a static routed prefix, or another provider can all work as long as the host owns the delegated prefix. Return traffic normally has to be routed to the host; when the provider treats the prefix as on-link instead, select that delegation mode and the daemon answers the resulting Neighbor Discovery itself. On-link proxying additionally requires that the upstream interface be Ethernet.

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

1. Establish the provider connection first. Note the delegated prefix, its egress interface (for example `ppp0` or `eth0`), and whether the provider routes the prefix or treats it as on-link — see [Prefix delegation](#prefix-delegation-routed-or-on-link). Do not store provider credentials in this repository.
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
5. In Settings enter the delegated IPv6 CIDR, the prefix delegation mode, public endpoint, upstream interface, and allocation limits. For a routed prefix, also set a server address inside a reserved infrastructure slice (commonly the first address of the first `/64`). For an on-link prefix, leave the server address empty; the allocation limits and WireGuard transport address are filled in automatically. Saving generates the server WireGuard key on first use.
6. Permit the WireGuard UDP port at the VPS/provider firewall. The app owns only the nftables table named `open_tunnelbroker`; keep management firewall policy in a separate table.

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

In Settings, create a WARP account and then select **Cloudflare WARP NAT** as the IPv4 egress mode. The app creates `wg-warp` with IPv4 AllowedIPs only, sends the internal RFC1918 pool through policy table 51822, and masquerades it to the WARP-assigned address. It never installs a WARP IPv6 address, AllowedIP, route, or policy rule.

Enabling either native or WARP IPv4 egress automatically assigns an RFC1918 address to every existing and future tunnel and renders `0.0.0.0/0, ::/0` in client configs. Disabling IPv4 egress immediately returns configs and kernel AllowedIPs/routes to IPv6-only mode; the internal assignments are retained for stable reuse.

The global IPv4 egress mode is the default for every tunnel. When creating a tunnel, or later from its detail page, you can leave it on the global default or override that tunnel to disabled, native upstream NAT, or Cloudflare WARP NAT. Per-tunnel native and WARP modes can coexist; WARP overrides require a registered WARP account.

Each tunnel also has a combined upload and download quota, measured in GiB and defaulting to 100 GiB. Usage is sampled during the 30-second reconciliation cycle. A tunnel is disabled and removed from WireGuard as soon as a sample reaches its quota. Quota usage resets on the first reconciliation of each UTC calendar month; tunnels disabled by quota enforcement are automatically restored, while manually disabled tunnels remain disabled.

### Inter-tunnel routing

The **Routing** page controls communication between tunnels:

- **Isolated** is the secure default and installs no `wg0`-to-`wg0` forwarding rule.
- **Shared managed group** permits traffic when two active tunnels share at least one group. The **Groups** page creates, renames, and deletes reusable tags; tunnel creation and detail pages assign zero, one, or multiple groups with a multi-select control.
- **Any tunnel** permits all active tunnels to communicate.

Each managed group is rendered as an nftables IPv6 interval set containing delegated prefixes and an IPv4 address set containing internal addresses. Rules require both source and destination membership in the same set, so membership in multiple groups naturally grants the union of those relationships. WireGuard AllowedIPs continue to enforce source ownership, original addresses are preserved, and inter-tunnel packets never match an egress masquerade rule. Combined quota accounting charges the sender's upload and the recipient's download.

Use **Test WARP outbound IP** to request `https://1.1.1.1/cdn-cgi/trace` through that exact source-policy path. The returned trace and test time are saved for the admin UI. Selecting native upstream NAT and WARP simultaneously is rejected.

Account creation sends a locally generated WireGuard public key, device type, locale, and current terms-of-service timestamp to Cloudflare's WARP registration API. Review Cloudflare's applicable terms before enabling this optional integration.

### Example addressing

For an upstream `2001:db8:1200::/48`, use `2001:db8:1200::1/64` as the server address, min/default/max prefixes of 48/56/64, and create `/56` or `/64` tunnels. The server's `/64` is automatically excluded from allocations. IPv6 is routed, never NATed.

## Prefix delegation: routed or on-link

Before configuring anything, determine whether the provider **routes** the prefix to this host or treats it as **on-link**. The **Prefix delegation** setting selects between them, and the choice changes nothing else about how tunnels are managed.

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

Because the delegated addresses actually live behind WireGuard, the upstream router's solicitations would go unanswered. Selecting on-link delegation makes the daemon answer them for the whole prefix, so the deployment needs no `ip -6 neigh add proxy` entry per address and no `ndppd`. Solicitations are validated the way RFC 4861 requires — hop limit 255, correct ICMPv6 checksum — and the host's own addresses are never proxied, so it stays reachable. Replies never set the Override flag and so cannot displace a genuine neighbor entry.

A single `/64` cannot be subdivided, because SLAAC needs a full `/64` on the downstream LAN. Selecting on-link delegation therefore configures the deployment accordingly by itself:

- The entire `/64` becomes the one allocation size, so the first tunnel receives the whole prefix. Allocation limits are set to match rather than requiring the admin to compute them.
- No address inside the prefix is reserved for the server, since the host keeps its provider-assigned address on the upstream interface.
- The WireGuard transport is numbered from a separate ULA (`fd00:6b72:6f6b::1/64` by default, and configurable), because the delegated prefix has no room to spare. This range never appears on the Internet.
- `net.ipv6.conf.<upstream>.forwarding` and `proxy_ndp` are enabled on the upstream interface, and the upstream gateway is pinned to a host route so that delegating the whole prefix cannot strand the server's own connectivity.

The generated client configuration reflects this: the peer's tunnel interface takes the transport address, and the delegated prefix is listed as a comment to put on the LAN instead. On OpenWrt, assign the prefix to the LAN interface and set **RA: server**, **DHCPv6: server**, **NDP: disabled**; `odhcpd` then advertises it and clients autoconfigure normally. IPv6 stays routed end to end with no NAT66.

If the provider offers a `/56` or `/48` instead, prefer that with routed delegation: multiple downstream LANs then each get their own `/64`.

## L2TP and delegated prefixes

Provider setup varies. On Ubuntu a typical L2TP connection is managed by NetworkManager or `xl2tpd`, while DHCPv6-PD is handled on the resulting PPP interface. Before starting this app, verify:

```sh
ip -6 route show
ip -6 addr show
ping -6 -c 3 2606:4700:4700::1111
```

With routed delegation the provider must route the entire delegated block back through the session; assigning a prefix locally cannot substitute for that route. A provider that instead resolves the prefix with Neighbor Discovery is the on-link case described above. If PD changes, update Settings and reassign tunnels intentionally; existing allocations are not silently rewritten.

## Operations

- Health and failed reconciliation are visible on the dashboard. `journalctl -u open-tunnelbroker` has underlying errors.
- Back up with `sqlite3 /var/lib/open-tunnelbroker/broker.db '.backup /secure/path/broker.db'`. Protect the backup: it contains server, WARP, and convenience-generated client private keys.
- Never run `wg set`, modify app-owned routes, edit `wg-warp`, or edit the `inet open_tunnelbroker` nftables table by hand. A resync restores database state and removes unmanaged peers.
- Deleting a tunnel first removes its kernel peer/routes, then deletes its row and frees its prefix. If kernel removal fails, the allocation remains recorded rather than being accidentally reused.
- `-dry-run` is intended for UI/schema evaluation on non-Linux development machines; it makes no network changes.
- **Reset general settings to defaults** disables IPv4 and restores the default pool, DNS, port, MTU, keepalive, and allocation sizes. It deliberately preserves upstream prefixes, prefix delegation mode, transport address, endpoint host, interfaces, server address/key, and any stored WARP account, because those describe the deployment rather than a preference. Allocation sizes stay pinned to the whole prefix when it is a single `/64`.
- With on-link delegation the dashboard reports drift if the Neighbor Discovery proxy is not running or no longer matches the delegated prefixes. The proxy is stopped on shutdown; routes, peers, and nftables rules are deliberately left in place so a restart does not interrupt traffic.

## Development

```sh
OTB_ADMIN_PASSWORD='at-least-twelve-characters' \
  ./bin/open-tunnelbroker -dry-run -db ./dev.db -listen 127.0.0.1:8080
```

Schema migrations are forward-only statements in `internal/broker/store.go`. Allocation behavior is covered in `internal/broker/allocator_test.go`. Networking is behind the `Kernel` interface so service tests can use a fake implementation.

Neighbor Discovery is split so that its logic is testable without privileges: `internal/broker/ndp.go` holds the packet codec and the proxy address set, covered by `ndp_test.go`, while `ndp_linux.go` holds only the privileged socket loop. The single-`/64` workflow is covered end to end in `onlink_test.go`.

## Security boundaries

This is an administrator-only control plane, not a public tunnel-signup portal. Use HTTPS, restrict access by firewall/VPN where possible, keep SQLite mode `0600`, and rotate the bootstrap password. Client-supplied public keys are preferred because the server never sees their private keys. Preshared keys are stored because they are required to render and reapply configurations.

## License

MIT; see [LICENSE](LICENSE).
