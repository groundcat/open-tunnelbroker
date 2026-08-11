package broker

import (
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }

func OpenStore(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY CHECK(id=1), v4_nat INTEGER NOT NULL DEFAULT 0, v4_warp INTEGER NOT NULL DEFAULT 0, v4_pool TEXT NOT NULL DEFAULT '10.99.0.0/16', default_dns TEXT NOT NULL DEFAULT '2606:4700:4700::1111', inter_tunnel_policy TEXT NOT NULL DEFAULT 'isolated');
INSERT OR IGNORE INTO settings(id) VALUES(1);
CREATE TABLE IF NOT EXISTS upstreams (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, v6_cidr TEXT NOT NULL, mode TEXT NOT NULL DEFAULT 'routed', public_v4 TEXT NOT NULL DEFAULT '', egress_interface TEXT NOT NULL DEFAULT '', interface_name TEXT NOT NULL UNIQUE, endpoint_host TEXT NOT NULL DEFAULT '', endpoint_port INTEGER NOT NULL DEFAULT 51820, server_address TEXT NOT NULL DEFAULT '', server_private_key TEXT NOT NULL DEFAULT '', transport_address TEXT NOT NULL DEFAULT '', mtu INTEGER NOT NULL DEFAULT 1420, keepalive INTEGER NOT NULL DEFAULT 25, min_prefix INTEGER NOT NULL DEFAULT 48, max_prefix INTEGER NOT NULL DEFAULT 64, default_prefix INTEGER NOT NULL DEFAULT 56, v4_mode TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS warp_account (id INTEGER PRIMARY KEY CHECK(id=1), private_key TEXT NOT NULL, peer_public_key TEXT NOT NULL, ipv4_address TEXT NOT NULL, endpoint TEXT NOT NULL, device_id TEXT NOT NULL DEFAULT '', account_id TEXT NOT NULL DEFAULT '', account_type TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, last_trace TEXT NOT NULL DEFAULT '', last_test_at TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS admin_users (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash BLOB NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tunnels (id INTEGER PRIMARY KEY, upstream_id INTEGER NOT NULL DEFAULT 0, label TEXT NOT NULL, public_key TEXT NOT NULL UNIQUE, preshared_key TEXT NOT NULL DEFAULT '', private_key TEXT NOT NULL DEFAULT '', allocated_v6_cidr TEXT NOT NULL UNIQUE, allocated_v4_internal TEXT UNIQUE, v4_enabled INTEGER NOT NULL DEFAULT 0, v4_mode TEXT NOT NULL DEFAULT '', quota_gib INTEGER NOT NULL DEFAULT 100, quota_used_bytes INTEGER NOT NULL DEFAULT 0, quota_period TEXT NOT NULL DEFAULT '', quota_disabled INTEGER NOT NULL DEFAULT 0, dns_override TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, mtu_override INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'pending', last_error TEXT NOT NULL DEFAULT '', last_handshake TEXT NOT NULL DEFAULT '', rx_bytes INTEGER NOT NULL DEFAULT 0, tx_bytes INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS tunnels_upstream ON tunnels(upstream_id);
CREATE TABLE IF NOT EXISTS routing_groups (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tunnel_routing_groups (tunnel_id INTEGER NOT NULL REFERENCES tunnels(id) ON DELETE CASCADE, group_id INTEGER NOT NULL REFERENCES routing_groups(id) ON DELETE CASCADE, PRIMARY KEY(tunnel_id,group_id));
CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY, admin TEXT NOT NULL, action TEXT NOT NULL, tunnel_id INTEGER, detail TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS audit_created ON audit_log(created_at);
`)
	if err != nil {
		return err
	}
	for _, migration := range []string{
		`ALTER TABLE settings ADD COLUMN v4_warp INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE settings ADD COLUMN inter_tunnel_policy TEXT NOT NULL DEFAULT 'isolated'`,
		`ALTER TABLE tunnels ADD COLUMN last_handshake TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE tunnels ADD COLUMN rx_bytes INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE tunnels ADD COLUMN tx_bytes INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE tunnels ADD COLUMN v4_mode TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE tunnels ADD COLUMN quota_gib INTEGER NOT NULL DEFAULT 100`,
		`ALTER TABLE tunnels ADD COLUMN quota_used_bytes INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE tunnels ADD COLUMN quota_period TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE tunnels ADD COLUMN quota_disabled INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE tunnels ADD COLUMN upstream_id INTEGER NOT NULL DEFAULT 0`,
	} {
		if _, e := s.db.Exec(migration); e != nil && !strings.Contains(e.Error(), "duplicate column") {
			return e
		}
	}
	if err = s.migrateLegacyRoutingGroups(); err != nil {
		return err
	}
	return s.migrateLegacyUpstream()
}

func (s *Store) tableColumns(table string) (map[string]bool, error) {
	rows, err := s.db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns := make(map[string]bool)
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			return nil, err
		}
		columns[name] = true
	}
	return columns, rows.Err()
}

// migrateLegacyUpstream converts a database that predates multiple upstreams,
// where the single provider connection lived in the settings row. The values are
// copied verbatim into one upstream and every existing tunnel is attached to it,
// so an upgrade keeps the exact addressing, keys, and delegation mode a running
// deployment already serves.
func (s *Store) migrateLegacyUpstream() error {
	columns, err := s.tableColumns("settings")
	if err != nil {
		return err
	}
	if !columns["upstream_v6"] {
		return nil
	}
	var existing int
	if err = s.db.QueryRow(`SELECT COUNT(*) FROM upstreams`).Scan(&existing); err != nil {
		return err
	}
	if existing > 0 {
		return nil
	}
	legacy := Upstream{Name: "primary", Mode: UpstreamRouted}
	// Delegation modes were added after the original single-upstream schema, so
	// a database predating them has neither column. Selecting them
	// unconditionally would fail to prepare and lose the whole upstream, which
	// is why the query is built from the columns that actually exist.
	query := `SELECT upstream_v6,upstream_v4,endpoint_host,endpoint_port,interface_name,server_address,server_private_key,mtu,keepalive,min_prefix,max_prefix,default_prefix,upstream_interface`
	targets := []any{&legacy.V6CIDR, &legacy.PublicV4, &legacy.EndpointHost, &legacy.EndpointPort, &legacy.InterfaceName, &legacy.ServerAddress, &legacy.ServerPrivateKey, &legacy.MTU, &legacy.Keepalive, &legacy.MinPrefix, &legacy.MaxPrefix, &legacy.DefaultPrefix, &legacy.EgressInterface}
	if columns["upstream_mode"] {
		query += `,COALESCE(upstream_mode,'routed')`
		targets = append(targets, &legacy.Mode)
	}
	if columns["transport_address"] {
		query += `,COALESCE(transport_address,'')`
		targets = append(targets, &legacy.TransportAddress)
	}
	if err = s.db.QueryRow(query + ` FROM settings WHERE id=1`).Scan(targets...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	if strings.TrimSpace(legacy.V6CIDR) == "" {
		return nil
	}
	if legacy.InterfaceName == "" {
		legacy.InterfaceName = "wg0"
	}
	if !validUpstreamMode(legacy.Mode) {
		legacy.Mode = UpstreamRouted
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`INSERT INTO upstreams(name,v6_cidr,mode,public_v4,egress_interface,interface_name,endpoint_host,endpoint_port,server_address,server_private_key,transport_address,mtu,keepalive,min_prefix,max_prefix,default_prefix,v4_mode,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'',?,?)`, legacy.Name, legacy.V6CIDR, legacy.Mode, legacy.PublicV4, legacy.EgressInterface, legacy.InterfaceName, legacy.EndpointHost, legacy.EndpointPort, legacy.ServerAddress, legacy.ServerPrivateKey, legacy.TransportAddress, legacy.MTU, legacy.Keepalive, legacy.MinPrefix, legacy.MaxPrefix, legacy.DefaultPrefix, now, now)
	if err != nil {
		return err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE tunnels SET upstream_id=? WHERE upstream_id=0`, id); err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO audit_log(admin,action,tunnel_id,detail,created_at) VALUES('system','upstream-migrate',NULL,?,?)`, fmt.Sprintf("converted single upstream %s to upstream %q", legacy.V6CIDR, legacy.Name), now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) migrateLegacyRoutingGroups() error {
	columns, err := s.tableColumns("tunnels")
	if err != nil {
		return err
	}
	if !columns["routing_group"] {
		return nil
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`INSERT OR IGNORE INTO routing_groups(name,created_at) SELECT DISTINCT TRIM(routing_group),? FROM tunnels WHERE TRIM(routing_group)<>''`, now); err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT OR IGNORE INTO tunnel_routing_groups(tunnel_id,group_id) SELECT t.id,g.id FROM tunnels t JOIN routing_groups g ON g.name=TRIM(t.routing_group) WHERE TRIM(t.routing_group)<>''`); err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE tunnels SET routing_group='' WHERE routing_group<>''`); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Settings() (Settings, error) {
	var v Settings
	err := s.db.QueryRow(`SELECT v4_nat,v4_warp,v4_pool,default_dns,inter_tunnel_policy FROM settings WHERE id=1`).Scan(&v.V4NAT, &v.V4Warp, &v.V4Pool, &v.DefaultDNS, &v.InterTunnelPolicy)
	return v, err
}

func (s *Store) SaveSettings(v Settings) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if v.V4NAT || v.V4Warp {
		pool, parseErr := netip.ParsePrefix(v.V4Pool)
		if parseErr != nil {
			return parseErr
		}
		upstreams, upstreamErr := upstreamsTx(tx)
		if upstreamErr != nil {
			return upstreamErr
		}
		if err = ensureIPv4AllocationsTx(tx, pool, v, upstreams); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(`UPDATE settings SET v4_nat=?,v4_warp=?,v4_pool=?,default_dns=?,inter_tunnel_policy=? WHERE id=1`, v.V4NAT, v.V4Warp, v.V4Pool, v.DefaultDNS, v.InterTunnelPolicy); err != nil {
		return err
	}
	return tx.Commit()
}

const upstreamCols = `id,name,v6_cidr,mode,public_v4,egress_interface,interface_name,endpoint_host,endpoint_port,server_address,server_private_key,transport_address,mtu,keepalive,min_prefix,max_prefix,default_prefix,v4_mode,created_at,updated_at`

func scanUpstream(scanner interface{ Scan(...any) error }) (Upstream, error) {
	var u Upstream
	var created, updated string
	err := scanner.Scan(&u.ID, &u.Name, &u.V6CIDR, &u.Mode, &u.PublicV4, &u.EgressInterface, &u.InterfaceName, &u.EndpointHost, &u.EndpointPort, &u.ServerAddress, &u.ServerPrivateKey, &u.TransportAddress, &u.MTU, &u.Keepalive, &u.MinPrefix, &u.MaxPrefix, &u.DefaultPrefix, &u.V4Mode, &created, &updated)
	if err == nil {
		u.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		u.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
		if !validUpstreamMode(u.Mode) {
			u.Mode = UpstreamRouted
		}
	}
	return u, err
}

func upstreamsTx(tx *sql.Tx) ([]Upstream, error) {
	rows, err := tx.Query(`SELECT ` + upstreamCols + ` FROM upstreams ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Upstream
	for rows.Next() {
		upstream, scanErr := scanUpstream(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, upstream)
	}
	return out, rows.Err()
}

func (s *Store) Upstreams() ([]Upstream, error) {
	rows, err := s.db.Query(`SELECT ` + upstreamCols + ` FROM upstreams ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Upstream
	for rows.Next() {
		upstream, scanErr := scanUpstream(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, upstream)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	counts, err := s.tunnelCountsByUpstream()
	if err != nil {
		return nil, err
	}
	for index := range out {
		out[index].TunnelCount = counts[out[index].ID]
	}
	return out, nil
}

func (s *Store) tunnelCountsByUpstream() (map[int64]int, error) {
	rows, err := s.db.Query(`SELECT upstream_id,COUNT(*) FROM tunnels GROUP BY upstream_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := make(map[int64]int)
	for rows.Next() {
		var id int64
		var count int
		if err = rows.Scan(&id, &count); err != nil {
			return nil, err
		}
		counts[id] = count
	}
	return counts, rows.Err()
}

func (s *Store) Upstream(id int64) (Upstream, error) {
	upstream, err := scanUpstream(s.db.QueryRow(`SELECT `+upstreamCols+` FROM upstreams WHERE id=?`, id))
	if err != nil {
		return upstream, err
	}
	counts, err := s.tunnelCountsByUpstream()
	if err != nil {
		return upstream, err
	}
	upstream.TunnelCount = counts[upstream.ID]
	return upstream, nil
}

func (s *Store) InsertUpstream(u *Upstream, admin string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`INSERT INTO upstreams(name,v6_cidr,mode,public_v4,egress_interface,interface_name,endpoint_host,endpoint_port,server_address,server_private_key,transport_address,mtu,keepalive,min_prefix,max_prefix,default_prefix,v4_mode,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, u.Name, u.V6CIDR, u.Mode, u.PublicV4, u.EgressInterface, u.InterfaceName, u.EndpointHost, u.EndpointPort, u.ServerAddress, u.ServerPrivateKey, u.TransportAddress, u.MTU, u.Keepalive, u.MinPrefix, u.MaxPrefix, u.DefaultPrefix, u.V4Mode, now, now)
	if err != nil {
		return translateUpstreamConflict(err)
	}
	u.ID, _ = result.LastInsertId()
	if _, err = tx.Exec(`INSERT INTO audit_log(admin,action,tunnel_id,detail,created_at) VALUES(?,'upstream-create',NULL,?,?)`, admin, u.Name+" "+u.V6CIDR, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) UpdateUpstream(u Upstream, admin string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`UPDATE upstreams SET name=?,v6_cidr=?,mode=?,public_v4=?,egress_interface=?,interface_name=?,endpoint_host=?,endpoint_port=?,server_address=?,server_private_key=?,transport_address=?,mtu=?,keepalive=?,min_prefix=?,max_prefix=?,default_prefix=?,v4_mode=?,updated_at=? WHERE id=?`, u.Name, u.V6CIDR, u.Mode, u.PublicV4, u.EgressInterface, u.InterfaceName, u.EndpointHost, u.EndpointPort, u.ServerAddress, u.ServerPrivateKey, u.TransportAddress, u.MTU, u.Keepalive, u.MinPrefix, u.MaxPrefix, u.DefaultPrefix, u.V4Mode, now, u.ID); err != nil {
		return translateUpstreamConflict(err)
	}
	if _, err = tx.Exec(`UPDATE tunnels SET status='pending',updated_at=? WHERE upstream_id=?`, now, u.ID); err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO audit_log(admin,action,tunnel_id,detail,created_at) VALUES(?,'upstream-update',NULL,?,?)`, admin, u.Name+" "+u.V6CIDR, now); err != nil {
		return err
	}
	return tx.Commit()
}

func translateUpstreamConflict(err error) error {
	if err == nil || !strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return err
	}
	if strings.Contains(err.Error(), "interface_name") {
		return errors.New("another upstream already uses that WireGuard interface name")
	}
	return errors.New("another upstream already uses that name")
}

func (s *Store) DeleteUpstream(id int64, admin string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var name string
	if err = tx.QueryRow(`SELECT name FROM upstreams WHERE id=?`, id).Scan(&name); err != nil {
		return err
	}
	var tunnels int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM tunnels WHERE upstream_id=?`, id).Scan(&tunnels); err != nil {
		return err
	}
	if tunnels > 0 {
		return fmt.Errorf("upstream %q still has %d tunnel(s); delete them first", name, tunnels)
	}
	if _, err = tx.Exec(`DELETE FROM upstreams WHERE id=?`, id); err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO audit_log(admin,action,tunnel_id,detail,created_at) VALUES(?,'upstream-delete',NULL,?,?)`, admin, name, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) EnsureIPv4Allocations(cfg Settings) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	pool, err := netip.ParsePrefix(cfg.V4Pool)
	if err != nil {
		return err
	}
	upstreams, err := upstreamsTx(tx)
	if err != nil {
		return err
	}
	if err = ensureIPv4AllocationsTx(tx, pool, cfg, upstreams); err != nil {
		return err
	}
	return tx.Commit()
}

// ensureIPv4AllocationsTx assigns an internal IPv4 address to every tunnel whose
// effective egress mode needs one. The mode is resolved per upstream, so a
// tunnel on an IPv4-less upstream is skipped rather than consuming a pool
// address it can never use.
func ensureIPv4AllocationsTx(tx *sql.Tx, pool netip.Prefix, cfg Settings, upstreams []Upstream) error {
	rows, err := tx.Query(`SELECT id,upstream_id,COALESCE(allocated_v4_internal,''),v4_mode FROM tunnels ORDER BY id`)
	if err != nil {
		return err
	}
	type allocation struct {
		id            int64
		upstreamID    int64
		address, mode string
	}
	var tunnels []allocation
	used := make(map[netip.Addr]bool)
	for rows.Next() {
		var tunnel allocation
		if err = rows.Scan(&tunnel.id, &tunnel.upstreamID, &tunnel.address, &tunnel.mode); err != nil {
			rows.Close()
			return err
		}
		if address, parseErr := netip.ParseAddr(tunnel.address); parseErr == nil {
			used[address] = true
		}
		tunnels = append(tunnels, tunnel)
	}
	if err = rows.Close(); err != nil {
		return err
	}
	byID := upstreamsByID(upstreams)
	for _, tunnel := range tunnels {
		upstream, known := byID[tunnel.upstreamID]
		// A tunnel whose upstream is gone carries no traffic, so it must not
		// consume a pool address it could never use.
		if !known || tunnelV4Mode(cfg, upstream, Tunnel{V4Mode: tunnel.mode}) == V4ModeOff || tunnel.address != "" {
			continue
		}
		next, ok := nextFreeIPv4(pool.Masked(), used)
		if !ok {
			return ErrPoolExhausted
		}
		used[next] = true
		if _, err = tx.Exec(`UPDATE tunnels SET allocated_v4_internal=?,v4_enabled=1,updated_at=? WHERE id=?`, next.String(), time.Now().UTC().Format(time.RFC3339Nano), tunnel.id); err != nil {
			return err
		}
	}
	return nil
}

func nextFreeIPv4(pool netip.Prefix, used map[netip.Addr]bool) (netip.Addr, bool) {
	for address := pool.Masked().Addr().Next(); pool.Contains(address); address = address.Next() {
		if !used[address] {
			return address, true
		}
	}
	return netip.Addr{}, false
}

func (s *Store) WarpAccount() (WarpAccount, error) {
	var account WarpAccount
	var created, tested string
	err := s.db.QueryRow(`SELECT private_key,peer_public_key,ipv4_address,endpoint,device_id,account_id,account_type,created_at,last_trace,last_test_at FROM warp_account WHERE id=1`).Scan(&account.PrivateKey, &account.PeerPublicKey, &account.IPv4Address, &account.Endpoint, &account.DeviceID, &account.AccountID, &account.AccountType, &created, &account.LastTrace, &tested)
	if errors.Is(err, sql.ErrNoRows) {
		return WarpAccount{}, nil
	}
	if err == nil {
		account.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		account.LastTestAt, _ = time.Parse(time.RFC3339Nano, tested)
	}
	return account, err
}

func (s *Store) SaveWarpAccount(account WarpAccount) error {
	created := account.CreatedAt.UTC().Format(time.RFC3339Nano)
	_, err := s.db.Exec(`INSERT INTO warp_account(id,private_key,peer_public_key,ipv4_address,endpoint,device_id,account_id,account_type,created_at,last_trace,last_test_at) VALUES(1,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET private_key=excluded.private_key,peer_public_key=excluded.peer_public_key,ipv4_address=excluded.ipv4_address,endpoint=excluded.endpoint,device_id=excluded.device_id,account_id=excluded.account_id,account_type=excluded.account_type,created_at=excluded.created_at,last_trace='',last_test_at=''`, account.PrivateKey, account.PeerPublicKey, account.IPv4Address, account.Endpoint, account.DeviceID, account.AccountID, account.AccountType, created, "", "")
	return err
}

func (s *Store) SaveWarpTest(trace string, tested time.Time) error {
	_, err := s.db.Exec(`UPDATE warp_account SET last_trace=?,last_test_at=? WHERE id=1`, trace, tested.UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) AddAudit(admin, action, detail string) error {
	_, err := s.db.Exec(`INSERT INTO audit_log(admin,action,tunnel_id,detail,created_at) VALUES(?,?,NULL,?,?)`, admin, action, detail, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func scanTunnel(scanner interface{ Scan(...any) error }) (Tunnel, error) {
	var t Tunnel
	var created, updated, handshake string
	err := scanner.Scan(&t.ID, &t.UpstreamID, &t.Label, &t.PublicKey, &t.PresharedKey, &t.PrivateKey, &t.V6CIDR, &t.V4Address, &t.V4Enabled, &t.V4Mode, &t.QuotaGiB, &t.QuotaUsedBytes, &t.QuotaPeriod, &t.QuotaDisabled, &t.DNSOverride, &t.Enabled, &t.MTUOverride, &t.Status, &t.LastError, &handshake, &t.RXBytes, &t.TXBytes, &created, &updated)
	if err == nil {
		t.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		t.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
		t.LastHandshake, _ = time.Parse(time.RFC3339Nano, handshake)
	}
	return t, err
}

const tunnelCols = `id,upstream_id,label,public_key,preshared_key,private_key,allocated_v6_cidr,COALESCE(allocated_v4_internal,''),v4_enabled,v4_mode,quota_gib,quota_used_bytes,quota_period,quota_disabled,dns_override,enabled,mtu_override,status,last_error,last_handshake,rx_bytes,tx_bytes,created_at,updated_at`

func (s *Store) Tunnels() ([]Tunnel, error) {
	return s.queryTunnels(`SELECT ` + tunnelCols + ` FROM tunnels ORDER BY upstream_id,allocated_v6_cidr`)
}

// TunnelsForUpstream lists the tunnels carved out of one upstream's prefix.
func (s *Store) TunnelsForUpstream(upstreamID int64) ([]Tunnel, error) {
	return s.queryTunnels(`SELECT `+tunnelCols+` FROM tunnels WHERE upstream_id=? ORDER BY allocated_v6_cidr`, upstreamID)
}

func (s *Store) queryTunnels(query string, args ...any) ([]Tunnel, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	var out []Tunnel
	for rows.Next() {
		t, e := scanTunnel(rows)
		if e != nil {
			rows.Close()
			return nil, e
		}
		out = append(out, t)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	if err = s.loadRoutingMemberships(out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) Tunnel(id int64) (Tunnel, error) {
	tunnel, err := scanTunnel(s.db.QueryRow(`SELECT `+tunnelCols+` FROM tunnels WHERE id=?`, id))
	if err != nil {
		return tunnel, err
	}
	tunnels := []Tunnel{tunnel}
	if err = s.loadRoutingMemberships(tunnels); err != nil {
		return tunnel, err
	}
	return tunnels[0], nil
}

func (s *Store) loadRoutingMemberships(tunnels []Tunnel) error {
	if len(tunnels) == 0 {
		return nil
	}
	byID := make(map[int64]*Tunnel, len(tunnels))
	for index := range tunnels {
		byID[tunnels[index].ID] = &tunnels[index]
	}
	rows, err := s.db.Query(`SELECT trg.tunnel_id,g.name FROM tunnel_routing_groups trg JOIN routing_groups g ON g.id=trg.group_id ORDER BY g.name`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var tunnelID int64
		var name string
		if err = rows.Scan(&tunnelID, &name); err != nil {
			return err
		}
		if tunnel := byID[tunnelID]; tunnel != nil {
			tunnel.RoutingGroups = append(tunnel.RoutingGroups, name)
		}
	}
	return rows.Err()
}

func setTunnelRoutingGroupsTx(tx *sql.Tx, tunnelID int64, groups []string) error {
	for _, name := range groups {
		var exists bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM routing_groups WHERE name=?)`, name).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("routing group %q does not exist", name)
		}
	}
	if _, err := tx.Exec(`DELETE FROM tunnel_routing_groups WHERE tunnel_id=?`, tunnelID); err != nil {
		return err
	}
	for _, name := range groups {
		if _, err := tx.Exec(`INSERT INTO tunnel_routing_groups(tunnel_id,group_id) SELECT ?,id FROM routing_groups WHERE name=?`, tunnelID, name); err != nil {
			return err
		}
	}
	return nil
}
func (s *Store) InsertTunnel(t *Tunnel, admin string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	r, e := tx.Exec(`INSERT INTO tunnels(upstream_id,label,public_key,preshared_key,private_key,allocated_v6_cidr,allocated_v4_internal,v4_enabled,v4_mode,quota_gib,quota_period,dns_override,enabled,mtu_override,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,'pending',?,?)`, t.UpstreamID, t.Label, t.PublicKey, t.PresharedKey, t.PrivateKey, t.V6CIDR, nullable(t.V4Address), t.V4Enabled, t.V4Mode, t.QuotaGiB, t.QuotaPeriod, t.DNSOverride, t.Enabled, t.MTUOverride, now, now)
	if e != nil {
		return e
	}
	t.ID, _ = r.LastInsertId()
	if e = setTunnelRoutingGroupsTx(tx, t.ID, t.RoutingGroups); e != nil {
		return e
	}
	if _, e = tx.Exec(`INSERT INTO audit_log(admin,action,tunnel_id,detail,created_at) VALUES(?,'create',?,?,?)`, admin, t.ID, t.V6CIDR, now); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) SetTunnelV4Mode(id int64, mode, admin string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`UPDATE tunnels SET v4_mode=?,status='pending',updated_at=? WHERE id=?`, mode, now, id); err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO audit_log(admin,action,tunnel_id,detail,created_at) VALUES(?,'v4-mode',?,?,?)`, admin, id, mode, now); err != nil {
		return err
	}
	return tx.Commit()
}
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
func (s *Store) DeleteTunnel(id int64, admin string) error {
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.Exec(`DELETE FROM tunnels WHERE id=?`, id); e != nil {
		return e
	}
	_, e = tx.Exec(`INSERT INTO audit_log(admin,action,tunnel_id,detail,created_at) VALUES(?,'delete',?,'',?)`, admin, id, time.Now().UTC().Format(time.RFC3339Nano))
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) SetEnabled(id int64, on bool, admin string) error {
	_, e := s.db.Exec(`UPDATE tunnels SET enabled=?,quota_disabled=0,status='pending',updated_at=? WHERE id=?`, on, time.Now().UTC().Format(time.RFC3339Nano), id)
	if e == nil {
		_, e = s.db.Exec(`INSERT INTO audit_log(admin,action,tunnel_id,detail,created_at) VALUES(?,'enable',?,?,?)`, admin, id, fmt.Sprint(on), time.Now().UTC().Format(time.RFC3339Nano))
	}
	return e
}
func (s *Store) SetStatus(id int64, status, msg string) error {
	_, e := s.db.Exec(`UPDATE tunnels SET status=?,last_error=?,updated_at=? WHERE id=?`, status, msg, time.Now().UTC().Format(time.RFC3339Nano), id)
	return e
}
func (s *Store) UpdateTelemetry(t Tunnel, now time.Time) (bool, error) {
	handshake := ""
	if !t.LastHandshake.IsZero() {
		handshake = t.LastHandshake.UTC().Format(time.RFC3339Nano)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var oldRX, oldTX, used, quota int64
	var period string
	var quotaDisabled bool
	if err = tx.QueryRow(`SELECT rx_bytes,tx_bytes,quota_used_bytes,quota_gib,quota_period,quota_disabled FROM tunnels WHERE id=?`, t.ID).Scan(&oldRX, &oldTX, &used, &quota, &period, &quotaDisabled); err != nil {
		return false, err
	}
	currentPeriod := quotaMonth(now)
	if period != currentPeriod {
		used = 0
		period = currentPeriod
		quotaDisabled = false
	}
	used += counterDelta(oldRX, t.RXBytes) + counterDelta(oldTX, t.TXBytes)
	exceeded := quota > 0 && used >= quota*(1<<30)
	status := ""
	if exceeded {
		status = "quota-exceeded"
	}
	_, err = tx.Exec(`UPDATE tunnels SET last_handshake=?,rx_bytes=?,tx_bytes=?,quota_used_bytes=?,quota_period=?,quota_disabled=?,enabled=CASE WHEN ? THEN 0 ELSE enabled END,status=CASE WHEN ? THEN ? ELSE status END,updated_at=? WHERE id=?`, handshake, t.RXBytes, t.TXBytes, used, period, exceeded, exceeded, exceeded, status, now.UTC().Format(time.RFC3339Nano), t.ID)
	if err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return exceeded && !quotaDisabled, nil
}

func counterDelta(previous, current int64) int64 {
	if current >= previous {
		return current - previous
	}
	return current
}

func quotaMonth(now time.Time) string { return now.UTC().Format("2006-01") }

func (s *Store) ResetMonthlyQuotas(now time.Time) error {
	period := quotaMonth(now)
	_, err := s.db.Exec(`UPDATE tunnels SET quota_used_bytes=0,quota_period=?,enabled=CASE WHEN quota_disabled=1 THEN 1 ELSE enabled END,status=CASE WHEN quota_disabled=1 THEN 'pending' ELSE status END,quota_disabled=0,updated_at=? WHERE quota_period<>?`, period, now.UTC().Format(time.RFC3339Nano), period)
	return err
}

func (s *Store) SetTunnelQuota(id, quotaGiB int64, admin string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var used int64
	var quotaDisabled bool
	if err = tx.QueryRow(`SELECT quota_used_bytes,quota_disabled FROM tunnels WHERE id=?`, id).Scan(&used, &quotaDisabled); err != nil {
		return err
	}
	exceeded := used >= quotaGiB*(1<<30)
	_, err = tx.Exec(`UPDATE tunnels SET quota_gib=?,quota_disabled=?,enabled=CASE WHEN ? THEN 0 WHEN quota_disabled=1 THEN 1 ELSE enabled END,status=CASE WHEN ? THEN 'quota-exceeded' WHEN quota_disabled=1 THEN 'pending' ELSE status END,updated_at=? WHERE id=?`, quotaGiB, exceeded, exceeded, exceeded, now, id)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO audit_log(admin,action,tunnel_id,detail,created_at) VALUES(?,'quota',?,?,?)`, admin, id, fmt.Sprint(quotaGiB), now); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) SetTunnelRoutingGroups(id int64, groups []string, admin string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = setTunnelRoutingGroupsTx(tx, id, groups); err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE tunnels SET status='pending',updated_at=? WHERE id=?`, now, id); err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO audit_log(admin,action,tunnel_id,detail,created_at) VALUES(?,'routing-groups',?,?,?)`, admin, id, strings.Join(groups, ", "), now); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) RoutingGroups() ([]RoutingGroup, error) {
	rows, err := s.db.Query(`SELECT g.id,g.name,g.created_at,COUNT(trg.tunnel_id) FROM routing_groups g LEFT JOIN tunnel_routing_groups trg ON trg.group_id=g.id GROUP BY g.id,g.name,g.created_at ORDER BY g.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var groups []RoutingGroup
	for rows.Next() {
		var group RoutingGroup
		var created string
		if err = rows.Scan(&group.ID, &group.Name, &created, &group.TunnelCount); err != nil {
			return nil, err
		}
		group.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		groups = append(groups, group)
	}
	return groups, rows.Err()
}
func (s *Store) CreateRoutingGroup(name, admin string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`INSERT INTO routing_groups(name,created_at) VALUES(?,?)`, name, now); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return errors.New("routing group already exists")
		}
		return err
	}
	if _, err = tx.Exec(`INSERT INTO audit_log(admin,action,tunnel_id,detail,created_at) VALUES(?,'routing-group-create',NULL,?,?)`, admin, name, now); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) RenameRoutingGroup(id int64, name, admin string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var oldName string
	if err = tx.QueryRow(`SELECT name FROM routing_groups WHERE id=?`, id).Scan(&oldName); err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE routing_groups SET name=? WHERE id=?`, name, id); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return errors.New("routing group already exists")
		}
		return err
	}
	if _, err = tx.Exec(`INSERT INTO audit_log(admin,action,tunnel_id,detail,created_at) VALUES(?,'routing-group-rename',NULL,?,?)`, admin, oldName+" -> "+name, now); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) DeleteRoutingGroup(id int64, admin string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var name string
	if err = tx.QueryRow(`SELECT name FROM routing_groups WHERE id=?`, id).Scan(&name); err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM routing_groups WHERE id=?`, id); err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO audit_log(admin,action,tunnel_id,detail,created_at) VALUES(?,'routing-group-delete',NULL,?,?)`, admin, name, now); err != nil {
		return err
	}
	return tx.Commit()
}

// UsedPrefixes lists the allocations carved out of one upstream. Free space is
// always rebuilt from these rows, so allocations can never drift.
func (s *Store) UsedPrefixes(upstreamID int64) ([]netip.Prefix, error) {
	ts, e := s.TunnelsForUpstream(upstreamID)
	if e != nil {
		return nil, e
	}
	out := make([]netip.Prefix, 0, len(ts))
	for _, t := range ts {
		p, e := netip.ParsePrefix(t.V6CIDR)
		if e != nil {
			return nil, e
		}
		out = append(out, p)
	}
	return out, nil
}
func (s *Store) NextV4(pool netip.Prefix) (string, error) {
	ts, e := s.Tunnels()
	if e != nil {
		return "", e
	}
	used := map[netip.Addr]bool{}
	for _, t := range ts {
		if a, e := netip.ParseAddr(t.V4Address); e == nil {
			used[a] = true
		}
	}
	if address, ok := nextFreeIPv4(pool.Masked(), used); ok {
		return address.String(), nil
	}
	return "", ErrPoolExhausted
}
func (s *Store) AdminCount() (int, error) {
	var n int
	e := s.db.QueryRow(`SELECT count(*) FROM admin_users`).Scan(&n)
	return n, e
}
func (s *Store) AddAdmin(user string, hash []byte) error {
	_, e := s.db.Exec(`INSERT INTO admin_users(username,password_hash,created_at) VALUES(?,?,?)`, user, hash, time.Now().UTC().Format(time.RFC3339Nano))
	return e
}
func (s *Store) AdminHash(user string) ([]byte, error) {
	var h []byte
	e := s.db.QueryRow(`SELECT password_hash FROM admin_users WHERE username=?`, user).Scan(&h)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, errors.New("invalid credentials")
	}
	return h, e
}
