# Open IPv6 Tunnelbroker

Open IPv6 Tunnelbroker is a small, self-hosted admin panel for redistributing a routed IPv6 prefix over WireGuard. SQLite is the desired-state store; the daemon owns the WireGuard peer table, routes, and its dedicated nftables table and reconciles them at startup and on demand.

The project is intentionally host-native: one Go binary, no container, no JavaScript build, and a server-rendered admin UI.

## What it does

- Allocates variable IPv6 CIDRs from any upstream prefix with a deterministic buddy allocator. Free space is rebuilt from assigned tunnels, so no free-list can drift.
- Adds/removes WireGuard peers through the kernel API and adds matching routes immediately.
- Applies an interface-scoped default-deny forwarding policy and optionally assigns RFC1918 addresses and masquerades them through an upstream interface.
- Generates client configs from either a supplied client public key or a server-generated keypair.
- Authenticates admins with bcrypt, HttpOnly sessions, SameSite cookies, and CSRF tokens.
- Marks failed applies as errors and reconciles all desired state after every restart or manual resync.

## Supported host

Linux with a WireGuard-capable kernel, `nft`, and systemd. The daemon must have `CAP_NET_ADMIN`; the supplied unit runs as root with a restricted filesystem and capability set. SQLite and WireGuard private keys live in `/var/lib/open-tunnelbroker`, which must be backed up securely.

The upstream transport is deliberately separate. L2TP, DHCPv6-PD, a static routed prefix, or another provider can all work as long as the host owns the delegated prefix and return traffic is routed to it.

## Build and test

Go 1.24 or newer is required.

```sh
go test ./...
CGO_ENABLED=0 go build -trimpath -o bin/open-tunnelbroker ./cmd/open-tunnelbroker
```

The equivalent `make test` and `make build VERSION=...` targets are provided when GNU Make is installed.

## Install

1. Establish the provider connection first. Confirm the delegated prefix is routed to the VPS and note its egress interface (for example `ppp0`). Do not store provider credentials in this repository.
2. Install prerequisites and the binary:

   ```sh
   sudo apt-get update
   sudo apt-get install -y nftables wireguard-tools nginx
   sudo install -m 0755 bin/open-tunnelbroker /usr/local/sbin/open-tunnelbroker
   sudo install -d -m 0700 /var/lib/open-tunnelbroker /etc/open-tunnelbroker
   sudo install -m 0644 deploy/open-tunnelbroker.service /etc/systemd/system/
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
5. In Settings enter the delegated IPv6 CIDR, a server address inside a reserved infrastructure slice (commonly the first address of the first `/64`), public endpoint, upstream interface, and allocation limits. Saving generates the server WireGuard key on first use.
6. Permit the WireGuard UDP port at the VPS/provider firewall. The app owns only the nftables table named `open_tunnelbroker`; keep management firewall policy in a separate table.

### Example addressing

For an upstream `2001:db8:1200::/48`, use `2001:db8:1200::1/64` as the server address, min/default/max prefixes of 48/56/64, and create `/56` or `/64` tunnels. The server's `/64` is automatically excluded from allocations. IPv6 is routed, never NATed.

## L2TP and delegated prefixes

Provider setup varies. On Ubuntu a typical L2TP connection is managed by NetworkManager or `xl2tpd`, while DHCPv6-PD is handled on the resulting PPP interface. Before starting this app, verify:

```sh
ip -6 route show
ip -6 addr show
ping -6 -c 3 2606:4700:4700::1111
```

The provider must route the entire delegated block back through the session. Assigning a prefix locally cannot substitute for that route. If PD changes, update Settings and reassign tunnels intentionally; existing allocations are not silently rewritten.

## Operations

- Health and failed reconciliation are visible on the dashboard. `journalctl -u open-tunnelbroker` has underlying errors.
- Back up with `sqlite3 /var/lib/open-tunnelbroker/broker.db '.backup /secure/path/broker.db'`. Protect the backup: it contains server and convenience-generated client private keys.
- Never run `wg set`, modify app-owned routes, or edit the `inet open_tunnelbroker` nftables table by hand. A resync restores database state and removes unmanaged peers.
- Deleting a tunnel first removes its kernel peer/routes, then deletes its row and frees its prefix. If kernel removal fails, the allocation remains recorded rather than being accidentally reused.
- `-dry-run` is intended for UI/schema evaluation on non-Linux development machines; it makes no network changes.

## Development

```sh
OTB_ADMIN_PASSWORD='at-least-twelve-characters' \
  ./bin/open-tunnelbroker -dry-run -db ./dev.db -listen 127.0.0.1:8080
```

Schema migrations are forward-only statements in `internal/broker/store.go`. Allocation behavior is covered in `internal/broker/allocator_test.go`. Networking is behind the `Kernel` interface so service tests can use a fake implementation.

## Security boundaries

This is an administrator-only control plane, not a public tunnel-signup portal. Use HTTPS, restrict access by firewall/VPN where possible, keep SQLite mode `0600`, and rotate the bootstrap password. Client-supplied public keys are preferred because the server never sees their private keys. Preshared keys are stored because they are required to render and reapply configurations.

## License

MIT; see [LICENSE](LICENSE).
