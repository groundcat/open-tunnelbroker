package broker

import (
	"database/sql"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type view struct {
	Title, User, CSRF, Error, Notice, Config string
	Settings                                 Settings
	Tunnels                                  []Tunnel
	Tunnel                                   Tunnel
	Health                                   Health
	Allocated                                uint64
	Largest                                  int
	Prefixes                                 []int
}

func (a *App) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/login", a.login)
	m.HandleFunc("/logout", a.auth(a.logout))
	m.HandleFunc("/", a.auth(a.dashboard))
	m.HandleFunc("/settings", a.auth(a.settings))
	m.HandleFunc("/tunnels/new", a.auth(a.newTunnel))
	m.HandleFunc("/tunnels/", a.auth(a.tunnel))
	m.HandleFunc("/resync", a.auth(a.resync))
	return securityHeaders(m)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}
func (a *App) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, e := r.Cookie("otb_session")
		if e != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		a.mu.Lock()
		s, ok := a.sessions[c.Value]
		a.mu.Unlock()
		if !ok || time.Now().After(s.Expires) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		r.Header.Set("X-OTB-User", s.Username)
		r.Header.Set("X-OTB-CSRF", s.CSRF)
		next(w, r)
	}
}
func (a *App) checkCSRF(r *http.Request) bool {
	return r.Method != "POST" || r.FormValue("csrf") == r.Header.Get("X-OTB-CSRF")
}
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		if !a.loginAllowed(r) {
			http.Error(w, "login must use HTTPS or originate on loopback", http.StatusForbidden)
			return
		}
		if a.Authenticate(r.FormValue("username"), r.FormValue("password")) {
			id := token()
			a.mu.Lock()
			a.sessions[id] = session{Username: r.FormValue("username"), CSRF: token(), Expires: time.Now().Add(12 * time.Hour)}
			a.mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "otb_session", Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: isHTTPS(r), MaxAge: 43200})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}
	a.render(w, "login", view{Title: "Login", Error: map[bool]string{true: "Invalid username or password"}[r.Method == "POST"]})
}
func (a *App) loginAllowed(r *http.Request) bool {
	if isHTTPS(r) {
		return true
	}
	host, _, e := net.SplitHostPort(r.Host)
	if e != nil {
		host = r.Host
	}
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}
func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}
func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || !a.checkCSRF(r) {
		http.Error(w, "bad request", 400)
		return
	}
	if c, e := r.Cookie("otb_session"); e == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "otb_session", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", 303)
}
func (a *App) base(r *http.Request) view {
	return view{User: r.Header.Get("X-OTB-User"), CSRF: r.Header.Get("X-OTB-CSRF")}
}

func (a *App) dashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	v := a.base(r)
	v.Largest = -1
	v.Title = "Dashboard"
	v.Notice = r.URL.Query().Get("notice")
	v.Error = r.URL.Query().Get("error")
	v.Tunnels, _ = a.store.Tunnels()
	v.Settings, _ = a.store.Settings()
	a.mu.Lock()
	v.Health = a.health
	v.Health.Drift = append([]string(nil), a.health.Drift...)
	a.mu.Unlock()
	if v.Settings.UpstreamV6 != "" {
		if pool, e := netip.ParsePrefix(v.Settings.UpstreamV6); e == nil {
			used, _ := a.store.UsedPrefixes()
			if v.Settings.ServerAddress != "" {
				server := netip.MustParsePrefix(v.Settings.ServerAddress)
				if server.Bits() < v.Settings.MaxPrefix {
					server = netip.PrefixFrom(server.Addr(), v.Settings.MaxPrefix).Masked()
				}
				used = append(used, server)
			}
			v.Allocated, v.Largest = PoolStats(pool, used, v.Settings.MaxPrefix)
		}
	}
	a.render(w, "dashboard", v)
}
func (a *App) settings(w http.ResponseWriter, r *http.Request) {
	v := a.base(r)
	v.Title = "Settings"
	v.Settings, _ = a.store.Settings()
	if r.Method == "POST" {
		if !a.checkCSRF(r) {
			http.Error(w, "invalid CSRF token", 403)
			return
		}
		old := v.Settings
		v.Settings = Settings{UpstreamV6: field(r, "upstream_v6"), UpstreamV4: field(r, "upstream_v4"), V4NAT: r.FormValue("v4_nat") != "", V4Pool: field(r, "v4_pool"), DefaultDNS: field(r, "default_dns"), EndpointHost: field(r, "endpoint_host"), EndpointPort: intField(r, "endpoint_port"), InterfaceName: field(r, "interface_name"), ServerAddress: field(r, "server_address"), ServerPrivateKey: old.ServerPrivateKey, MTU: intField(r, "mtu"), Keepalive: intField(r, "keepalive"), MinPrefix: intField(r, "min_prefix"), MaxPrefix: intField(r, "max_prefix"), DefaultPrefix: intField(r, "default_prefix"), UpstreamInterface: field(r, "upstream_interface")}
		if e := a.SaveSettings(v.Settings); e != nil {
			v.Error = e.Error()
		} else if e = a.Reconcile(r.Context()); e != nil {
			v.Error = "Saved, but reconcile failed: " + e.Error()
		} else {
			v.Notice = "Settings saved and applied"
			v.Settings, _ = a.store.Settings()
		}
	}
	a.render(w, "settings", v)
}
func field(r *http.Request, k string) string { return strings.TrimSpace(r.FormValue(k)) }
func intField(r *http.Request, k string) int { n, _ := strconv.Atoi(field(r, k)); return n }

func (a *App) newTunnel(w http.ResponseWriter, r *http.Request) {
	v := a.base(r)
	v.Title = "New tunnel"
	v.Settings, _ = a.store.Settings()
	for i := v.Settings.MinPrefix; i <= v.Settings.MaxPrefix; i++ {
		v.Prefixes = append(v.Prefixes, i)
	}
	if r.Method == "POST" {
		if !a.checkCSRF(r) {
			http.Error(w, "invalid CSRF token", 403)
			return
		}
		t, e := a.CreateTunnel(CreateTunnelInput{Label: field(r, "label"), PublicKey: field(r, "public_key"), DNS: field(r, "dns"), Prefix: intField(r, "prefix"), V4: r.FormValue("v4") != "", GenerateKeys: r.FormValue("generate") != ""}, v.User)
		if e != nil {
			v.Error = e.Error()
		} else {
			http.Redirect(w, r, fmt.Sprintf("/tunnels/%d?created=1", t.ID), 303)
			return
		}
	}
	a.render(w, "new", v)
}
func (a *App) tunnel(w http.ResponseWriter, r *http.Request) {
	tail := strings.TrimPrefix(r.URL.Path, "/tunnels/")
	parts := strings.Split(strings.Trim(tail, "/"), "/")
	id, e := strconv.ParseInt(parts[0], 10, 64)
	if e != nil {
		http.NotFound(w, r)
		return
	}
	t, e := a.store.Tunnel(id)
	if e == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	}
	if e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	v := a.base(r)
	if r.Method == "POST" {
		if !a.checkCSRF(r) {
			http.Error(w, "invalid CSRF token", 403)
			return
		}
		action := field(r, "action")
		switch action {
		case "delete":
			e = a.DeleteTunnel(id, v.User)
			if e == nil {
				http.Redirect(w, r, "/", 303)
				return
			}
		case "toggle":
			e = a.SetEnabled(id, !t.Enabled, v.User)
			if e == nil {
				http.Redirect(w, r, r.URL.Path, 303)
				return
			}
		default:
			e = fmt.Errorf("unknown action")
		}
		v.Error = e.Error()
	}
	v.Title = t.Label
	v.Tunnel, _ = a.store.Tunnel(id)
	v.Settings, _ = a.store.Settings()
	v.Config = a.ClientConfig(v.Tunnel, v.Settings)
	if r.URL.Query().Get("created") != "" {
		v.Notice = "Tunnel created and applied"
	}
	a.render(w, "detail", v)
}
func (a *App) resync(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || !a.checkCSRF(r) {
		http.Error(w, "bad request", 400)
		return
	}
	e := a.Reconcile(r.Context())
	dest := "/?notice=" + url.QueryEscape("Kernel resynchronized")
	if e != nil {
		dest = "/?error=" + url.QueryEscape(e.Error())
	}
	http.Redirect(w, r, dest, 303)
}
func (a *App) render(w http.ResponseWriter, name string, v view) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if e := pages.ExecuteTemplate(w, name, v); e != nil {
		a.logger.Printf("template: %v", e)
	}
}

var pages = template.Must(template.New("pages").Funcs(template.FuncMap{"bytes": func(n int64) string {
	if n > 1<<30 {
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	}
	if n > 1<<20 {
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	}
	return fmt.Sprintf("%d B", n)
}, "since": func(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
}}).Parse(pageHTML))

const pageHTML = `{{define "head"}}<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>{{.Title}} · Open IPv6 Tunnelbroker</title><style>body{font:16px system-ui,sans-serif;max-width:1050px;margin:2rem auto;padding:0 1rem;color:#222}nav{display:flex;gap:1rem;align-items:center;border-bottom:1px solid #ccc;padding-bottom:1rem}nav form{margin-left:auto}table{border-collapse:collapse;width:100%}th,td{text-align:left;border-bottom:1px solid #ddd;padding:.55rem}label{display:block;margin:.8rem 0 .25rem}input,select{padding:.45rem;min-width:20rem;max-width:100%}input[type=checkbox]{min-width:auto}button{padding:.45rem .8rem}pre{background:#eee;padding:1rem;overflow:auto}.error{background:#fee;padding:.7rem}.notice{background:#efe;padding:.7rem}.bad{color:#a00}.muted{color:#666}.row{display:flex;gap:2rem;flex-wrap:wrap}.danger{border:1px solid #a00;padding:1rem}</style></head><body>{{if .User}}<nav><strong>Open IPv6 Tunnelbroker</strong><a href="/">Dashboard</a><a href="/tunnels/new">New tunnel</a><a href="/settings">Settings</a><form method="post" action="/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>Log out {{.User}}</button></form></nav>{{end}}<h1>{{.Title}}</h1>{{if .Error}}<p class="error">{{.Error}}</p>{{end}}{{if .Notice}}<p class="notice">{{.Notice}}</p>{{end}}{{end}}
{{define "foot"}}</body></html>{{end}}
{{define "login"}}{{template "head" .}}<form method="post"><label>Username</label><input name="username" autocomplete="username" required><label>Password</label><input type="password" name="password" autocomplete="current-password" required><p><button>Log in</button></p></form>{{template "foot" .}}{{end}}
{{define "dashboard"}}{{template "head" .}}{{if not .Settings.UpstreamV6}}<p class="error">Configure the upstream prefix before creating tunnels.</p>{{end}}<div class="row"><div><h2>Pool</h2><p>Upstream: {{.Settings.UpstreamV6}}<br>/64 units allocated: {{.Allocated}}<br>Largest available block: {{if ge .Largest 0}}/{{.Largest}}{{else}}none{{end}}</p></div><div><h2>Reconciliation</h2><p>Last: {{since .Health.LastReconcile}}<br>{{if .Health.Error}}<span class="bad">{{.Health.Error}}</span>{{else}}No apply error{{end}}<br>{{if .Health.Drift}}<span class="bad">Drift remains: {{range .Health.Drift}}{{.}}; {{end}}</span>{{else}}Kernel matches database{{end}}</p><form method="post" action="/resync"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>Resync now</button></form></div></div><h2>Tunnels</h2><table><thead><tr><th>Name</th><th>IPv6</th><th>IPv4</th><th>Status</th><th>Last handshake</th><th>Traffic</th></tr></thead><tbody>{{range .Tunnels}}<tr><td><a href="/tunnels/{{.ID}}">{{.Label}}</a></td><td>{{.V6CIDR}}</td><td>{{.V4Address}}</td><td>{{if not .Enabled}}disabled · {{end}}<span class="{{if eq .Status "error"}}bad{{end}}">{{.Status}}</span></td><td>{{since .LastHandshake}}</td><td>↓ {{bytes .RXBytes}} / ↑ {{bytes .TXBytes}}</td></tr>{{else}}<tr><td colspan="6">No tunnels yet.</td></tr>{{end}}</tbody></table>{{template "foot" .}}{{end}}
{{define "settings"}}{{template "head" .}}<form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><div class="row"><div><h2>Upstream</h2><label>IPv6 delegated prefix</label><input name="upstream_v6" value="{{.Settings.UpstreamV6}}" placeholder="2001:db8::/48" required><label>Server address/prefix</label><input name="server_address" value="{{.Settings.ServerAddress}}" placeholder="2001:db8::1/64"><label>Public IPv4 (informational)</label><input name="upstream_v4" value="{{.Settings.UpstreamV4}}"><label>Upstream interface</label><input name="upstream_interface" value="{{.Settings.UpstreamInterface}}"></div><div><h2>WireGuard</h2><label>Interface</label><input name="interface_name" value="{{.Settings.InterfaceName}}" required><label>Endpoint hostname/IP</label><input name="endpoint_host" value="{{.Settings.EndpointHost}}" required><label>Listen port</label><input type="number" name="endpoint_port" value="{{.Settings.EndpointPort}}" required><label>MTU</label><input type="number" name="mtu" value="{{.Settings.MTU}}"><label>Keepalive seconds</label><input type="number" name="keepalive" value="{{.Settings.Keepalive}}"></div></div><div class="row"><div><h2>Allocation</h2><label>Largest allowed allocation prefix</label><input type="number" name="min_prefix" value="{{.Settings.MinPrefix}}"><label>Smallest allowed allocation prefix</label><input type="number" name="max_prefix" value="{{.Settings.MaxPrefix}}"><label>Default prefix</label><input type="number" name="default_prefix" value="{{.Settings.DefaultPrefix}}"></div><div><h2>Clients</h2><label>Default DNS</label><input name="default_dns" value="{{.Settings.DefaultDNS}}"><label><input type="checkbox" name="v4_nat" {{if .Settings.V4NAT}}checked{{end}}> Enable IPv4 NAT</label><label>Internal IPv4 pool</label><input name="v4_pool" value="{{.Settings.V4Pool}}"></div></div><p><button>Save and apply</button></p></form>{{template "foot" .}}{{end}}
{{define "new"}}{{template "head" .}}<form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><label>Label</label><input name="label" required><label>Allocation size</label><select name="prefix">{{range .Prefixes}}<option value="{{.}}" {{if eq . $.Settings.DefaultPrefix}}selected{{end}}>/{{.}}</option>{{end}}</select><label><input type="checkbox" name="generate" checked> Generate client keypair (private key is stored and shown to the admin)</label><label>Client public key (uncheck generate to use)</label><input name="public_key"><label>DNS override</label><input name="dns" placeholder="{{.Settings.DefaultDNS}}">{{if .Settings.V4NAT}}<label><input type="checkbox" name="v4"> Enable NATed IPv4</label>{{end}}<p><button>Create and apply</button></p></form>{{template "foot" .}}{{end}}
{{define "detail"}}{{template "head" .}}<p><strong>IPv6 allocation:</strong> {{.Tunnel.V6CIDR}}<br><strong>IPv4:</strong> {{if .Tunnel.V4Address}}{{.Tunnel.V4Address}}{{else}}disabled{{end}}<br><strong>State:</strong> {{if not .Tunnel.Enabled}}disabled · {{end}}{{.Tunnel.Status}}{{if .Tunnel.LastError}} — <span class="bad">{{.Tunnel.LastError}}</span>{{end}}</p><h2>Client configuration</h2><pre>{{.Config}}</pre>{{if .Tunnel.PrivateKey}}<p class="muted">This server-generated private key is sensitive. Prefer client-generated keys for higher-security deployments.</p>{{end}}<form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="toggle"><button>{{if .Tunnel.Enabled}}Disable{{else}}Enable{{end}} tunnel</button></form><h2>Delete</h2><form method="post" class="danger"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="delete"><p>Deletion immediately removes the peer and route and frees the allocation.</p><button>Delete tunnel</button></form>{{template "foot" .}}{{end}}`
