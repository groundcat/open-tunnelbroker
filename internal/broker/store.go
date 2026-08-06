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
CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY CHECK(id=1), upstream_v6 TEXT NOT NULL DEFAULT '', upstream_v4 TEXT NOT NULL DEFAULT '', v4_nat INTEGER NOT NULL DEFAULT 0, v4_warp INTEGER NOT NULL DEFAULT 0, v4_pool TEXT NOT NULL DEFAULT '10.99.0.0/16', default_dns TEXT NOT NULL DEFAULT '2606:4700:4700::1111', endpoint_host TEXT NOT NULL DEFAULT '', endpoint_port INTEGER NOT NULL DEFAULT 51820, interface_name TEXT NOT NULL DEFAULT 'wg0', server_address TEXT NOT NULL DEFAULT '', server_private_key TEXT NOT NULL DEFAULT '', mtu INTEGER NOT NULL DEFAULT 1420, keepalive INTEGER NOT NULL DEFAULT 25, min_prefix INTEGER NOT NULL DEFAULT 48, max_prefix INTEGER NOT NULL DEFAULT 64, default_prefix INTEGER NOT NULL DEFAULT 56, upstream_interface TEXT NOT NULL DEFAULT 'ppp0');
INSERT OR IGNORE INTO settings(id) VALUES(1);
CREATE TABLE IF NOT EXISTS warp_account (id INTEGER PRIMARY KEY CHECK(id=1), private_key TEXT NOT NULL, peer_public_key TEXT NOT NULL, ipv4_address TEXT NOT NULL, endpoint TEXT NOT NULL, device_id TEXT NOT NULL DEFAULT '', account_id TEXT NOT NULL DEFAULT '', account_type TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, last_trace TEXT NOT NULL DEFAULT '', last_test_at TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS admin_users (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash BLOB NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tunnels (id INTEGER PRIMARY KEY, interface_id INTEGER NOT NULL DEFAULT 1, label TEXT NOT NULL, public_key TEXT NOT NULL UNIQUE, preshared_key TEXT NOT NULL DEFAULT '', private_key TEXT NOT NULL DEFAULT '', allocated_v6_cidr TEXT NOT NULL UNIQUE, allocated_v4_internal TEXT UNIQUE, v4_enabled INTEGER NOT NULL DEFAULT 0, dns_override TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, mtu_override INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'pending', last_error TEXT NOT NULL DEFAULT '', last_handshake TEXT NOT NULL DEFAULT '', rx_bytes INTEGER NOT NULL DEFAULT 0, tx_bytes INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY, admin TEXT NOT NULL, action TEXT NOT NULL, tunnel_id INTEGER, detail TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS audit_created ON audit_log(created_at);
`)
	if err != nil {
		return err
	}
	for _, migration := range []string{
		`ALTER TABLE settings ADD COLUMN v4_warp INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE tunnels ADD COLUMN last_handshake TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE tunnels ADD COLUMN rx_bytes INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE tunnels ADD COLUMN tx_bytes INTEGER NOT NULL DEFAULT 0`,
	} {
		if _, e := s.db.Exec(migration); e != nil && !strings.Contains(e.Error(), "duplicate column") {
			return e
		}
	}
	return nil
}

func (s *Store) Settings() (Settings, error) {
	var v Settings
	err := s.db.QueryRow(`SELECT upstream_v6,upstream_v4,v4_nat,v4_warp,v4_pool,default_dns,endpoint_host,endpoint_port,interface_name,server_address,server_private_key,mtu,keepalive,min_prefix,max_prefix,default_prefix,upstream_interface FROM settings WHERE id=1`).Scan(&v.UpstreamV6, &v.UpstreamV4, &v.V4NAT, &v.V4Warp, &v.V4Pool, &v.DefaultDNS, &v.EndpointHost, &v.EndpointPort, &v.InterfaceName, &v.ServerAddress, &v.ServerPrivateKey, &v.MTU, &v.Keepalive, &v.MinPrefix, &v.MaxPrefix, &v.DefaultPrefix, &v.UpstreamInterface)
	return v, err
}
func (s *Store) SaveSettings(v Settings) error {
	_, err := s.db.Exec(`UPDATE settings SET upstream_v6=?,upstream_v4=?,v4_nat=?,v4_warp=?,v4_pool=?,default_dns=?,endpoint_host=?,endpoint_port=?,interface_name=?,server_address=?,server_private_key=?,mtu=?,keepalive=?,min_prefix=?,max_prefix=?,default_prefix=?,upstream_interface=? WHERE id=1`, v.UpstreamV6, v.UpstreamV4, v.V4NAT, v.V4Warp, v.V4Pool, v.DefaultDNS, v.EndpointHost, v.EndpointPort, v.InterfaceName, v.ServerAddress, v.ServerPrivateKey, v.MTU, v.Keepalive, v.MinPrefix, v.MaxPrefix, v.DefaultPrefix, v.UpstreamInterface)
	return err
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
	err := scanner.Scan(&t.ID, &t.InterfaceID, &t.Label, &t.PublicKey, &t.PresharedKey, &t.PrivateKey, &t.V6CIDR, &t.V4Address, &t.V4Enabled, &t.DNSOverride, &t.Enabled, &t.MTUOverride, &t.Status, &t.LastError, &handshake, &t.RXBytes, &t.TXBytes, &created, &updated)
	if err == nil {
		t.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		t.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
		t.LastHandshake, _ = time.Parse(time.RFC3339Nano, handshake)
	}
	return t, err
}

const tunnelCols = `id,interface_id,label,public_key,preshared_key,private_key,allocated_v6_cidr,COALESCE(allocated_v4_internal,''),v4_enabled,dns_override,enabled,mtu_override,status,last_error,last_handshake,rx_bytes,tx_bytes,created_at,updated_at`

func (s *Store) Tunnels() ([]Tunnel, error) {
	rows, err := s.db.Query(`SELECT ` + tunnelCols + ` FROM tunnels ORDER BY allocated_v6_cidr`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Tunnel
	for rows.Next() {
		t, e := scanTunnel(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
func (s *Store) Tunnel(id int64) (Tunnel, error) {
	return scanTunnel(s.db.QueryRow(`SELECT `+tunnelCols+` FROM tunnels WHERE id=?`, id))
}
func (s *Store) InsertTunnel(t *Tunnel, admin string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	r, e := tx.Exec(`INSERT INTO tunnels(interface_id,label,public_key,preshared_key,private_key,allocated_v6_cidr,allocated_v4_internal,v4_enabled,dns_override,enabled,mtu_override,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,'pending',?,?)`, 1, t.Label, t.PublicKey, t.PresharedKey, t.PrivateKey, t.V6CIDR, nullable(t.V4Address), t.V4Enabled, t.DNSOverride, t.Enabled, t.MTUOverride, now, now)
	if e != nil {
		return e
	}
	t.ID, _ = r.LastInsertId()
	if _, e = tx.Exec(`INSERT INTO audit_log(admin,action,tunnel_id,detail,created_at) VALUES(?,'create',?,?,?)`, admin, t.ID, t.V6CIDR, now); e != nil {
		return e
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
	_, e := s.db.Exec(`UPDATE tunnels SET enabled=?,status='pending',updated_at=? WHERE id=?`, on, time.Now().UTC().Format(time.RFC3339Nano), id)
	if e == nil {
		_, e = s.db.Exec(`INSERT INTO audit_log(admin,action,tunnel_id,detail,created_at) VALUES(?,'enable',?,?,?)`, admin, id, fmt.Sprint(on), time.Now().UTC().Format(time.RFC3339Nano))
	}
	return e
}
func (s *Store) SetStatus(id int64, status, msg string) error {
	_, e := s.db.Exec(`UPDATE tunnels SET status=?,last_error=?,updated_at=? WHERE id=?`, status, msg, time.Now().UTC().Format(time.RFC3339Nano), id)
	return e
}
func (s *Store) UpdateTelemetry(t Tunnel) error {
	handshake := ""
	if !t.LastHandshake.IsZero() {
		handshake = t.LastHandshake.UTC().Format(time.RFC3339Nano)
	}
	_, e := s.db.Exec(`UPDATE tunnels SET last_handshake=?,rx_bytes=?,tx_bytes=? WHERE id=?`, handshake, t.RXBytes, t.TXBytes, t.ID)
	return e
}
func (s *Store) UsedPrefixes() ([]netip.Prefix, error) {
	ts, e := s.Tunnels()
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
	for a := pool.Addr().Next(); pool.Contains(a); a = a.Next() {
		if !used[a] {
			return a.String(), nil
		}
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
