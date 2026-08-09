package broker

import (
	"database/sql"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

type view struct {
	Title, User, CSRF, Error, Notice, Config, EffectiveV4Mode string
	Settings                                                  Settings
	Warp                                                      WarpAccount
	Tunnels                                                   []Tunnel
	Tunnel                                                    Tunnel
	Health                                                    Health
	Upgrade                                                   UpgradeStatus
	Allocated                                                 uint64
	Largest                                                   int
	Prefixes                                                  []int
	RoutingGroups                                             []RoutingGroup
}

func (a *App) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/login", a.login)
	m.HandleFunc("/logout", a.auth(a.logout))
	m.HandleFunc("/", a.auth(a.dashboard))
	m.HandleFunc("/settings", a.auth(a.settings))
	m.HandleFunc("/settings/reset", a.auth(a.resetSettings))
	m.HandleFunc("/routing", a.auth(a.routing))
	m.HandleFunc("/groups", a.auth(a.groups))
	m.HandleFunc("/tunnels/new", a.auth(a.newTunnel))
	m.HandleFunc("/tunnels/", a.auth(a.tunnel))
	m.HandleFunc("/resync", a.auth(a.resync))
	m.HandleFunc("/warp", a.auth(a.warpAction))
	m.HandleFunc("/upgrade", a.auth(a.upgradeAction))
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
	v.Warp, _ = a.store.WarpAccount()
	v.Notice = r.URL.Query().Get("notice")
	v.Error = r.URL.Query().Get("error")
	if r.Method == "POST" {
		if !a.checkCSRF(r) {
			http.Error(w, "invalid CSRF token", 403)
			return
		}
		old := v.Settings
		v4Mode := field(r, "v4_mode")
		if v4Mode == "" && r.FormValue("v4_nat") != "" {
			v4Mode = "native"
		}
		v.Settings = Settings{UpstreamV6: field(r, "upstream_v6"), UpstreamV4: field(r, "upstream_v4"), V4NAT: v4Mode == "native", V4Warp: v4Mode == "warp", V4Pool: field(r, "v4_pool"), DefaultDNS: field(r, "default_dns"), EndpointHost: field(r, "endpoint_host"), EndpointPort: intField(r, "endpoint_port"), InterfaceName: field(r, "interface_name"), ServerAddress: field(r, "server_address"), ServerPrivateKey: old.ServerPrivateKey, MTU: intField(r, "mtu"), Keepalive: intField(r, "keepalive"), MinPrefix: intField(r, "min_prefix"), MaxPrefix: intField(r, "max_prefix"), DefaultPrefix: intField(r, "default_prefix"), UpstreamInterface: field(r, "upstream_interface"), InterTunnelPolicy: old.InterTunnelPolicy}
		if e := a.SaveSettings(v.Settings); e != nil {
			v.Error = e.Error()
		} else if e = a.Reconcile(r.Context()); e != nil {
			v.Error = "Saved, but reconcile failed: " + e.Error()
		} else {
			v.Notice = "Settings saved and applied"
			v.Settings, _ = a.store.Settings()
			v.Warp, _ = a.store.WarpAccount()
		}
	}
	a.render(w, "settings", v)
}
func (a *App) routing(w http.ResponseWriter, r *http.Request) {
	v := a.base(r)
	v.Title = "Inter-tunnel routing"
	v.Settings, _ = a.store.Settings()
	v.Tunnels, _ = a.store.Tunnels()
	v.Notice = r.URL.Query().Get("notice")
	v.Error = r.URL.Query().Get("error")
	if r.Method == http.MethodPost {
		if !a.checkCSRF(r) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		v.Settings.InterTunnelPolicy = field(r, "inter_tunnel_policy")
		if err := a.SaveSettings(v.Settings); err != nil {
			v.Error = err.Error()
		} else if err = a.Reconcile(r.Context()); err != nil {
			v.Error = "Saved, but reconcile failed: " + err.Error()
		} else {
			_ = a.store.AddAudit(v.User, "routing-policy", v.Settings.InterTunnelPolicy)
			v.Notice = "Inter-tunnel routing policy saved and applied"
			v.Settings, _ = a.store.Settings()
		}
	}
	a.render(w, "routing", v)
}
func (a *App) groups(w http.ResponseWriter, r *http.Request) {
	v := a.base(r)
	v.Title = "Routing groups"
	v.Notice = r.URL.Query().Get("notice")
	v.Error = r.URL.Query().Get("error")
	if r.Method == http.MethodPost {
		if !a.checkCSRF(r) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		var err error
		switch field(r, "action") {
		case "create":
			err = a.CreateRoutingGroup(field(r, "name"), v.User)
		case "rename":
			err = a.RenameRoutingGroup(int64Field(r, "group_id"), field(r, "name"), v.User)
		case "delete":
			err = a.DeleteRoutingGroup(int64Field(r, "group_id"), v.User)
		default:
			err = errors.New("unknown group action")
		}
		if err != nil {
			v.Error = err.Error()
		} else {
			http.Redirect(w, r, "/groups?notice="+url.QueryEscape("Routing groups updated"), http.StatusSeeOther)
			return
		}
	}
	v.RoutingGroups, _ = a.store.RoutingGroups()
	a.render(w, "groups", v)
}
func (a *App) upgradeAction(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		v := a.base(r)
		v.Title = "Upgrade"
		v.Notice = r.URL.Query().Get("notice")
		v.Error = r.URL.Query().Get("error")
		if a.upgrader != nil {
			v.Upgrade = a.upgrader.Status(r.Context())
		}
		a.render(w, "upgrade", v)
		return
	}
	if r.Method != http.MethodPost || !a.checkCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	err := a.StartUpgrade(r.Context(), r.Header.Get("X-OTB-User"))
	destination := "/upgrade?notice=" + url.QueryEscape("Upgrade started; refresh this page to see status")
	if err != nil {
		destination = "/upgrade?error=" + url.QueryEscape(err.Error())
	}
	http.Redirect(w, r, destination, http.StatusSeeOther)
}
func (a *App) warpAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !a.checkCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var err error
	switch field(r, "action") {
	case "register":
		_, err = a.RegisterWarp(r.Context(), r.Header.Get("X-OTB-User"))
	case "test":
		_, err = a.TestWarp(r.Context(), r.Header.Get("X-OTB-User"))
	default:
		err = errors.New("unknown WARP action")
	}
	destination := "/settings?notice=" + url.QueryEscape("Cloudflare WARP action completed")
	if err != nil {
		destination = "/settings?error=" + url.QueryEscape(err.Error())
	}
	http.Redirect(w, r, destination, http.StatusSeeOther)
}
func (a *App) resetSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !a.checkCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	err := a.ResetGeneralSettings(r.Header.Get("X-OTB-User"))
	destination := "/settings?notice=" + url.QueryEscape("General settings reset to defaults")
	if err != nil {
		destination = "/settings?error=" + url.QueryEscape(err.Error())
	}
	http.Redirect(w, r, destination, http.StatusSeeOther)
}
func field(r *http.Request, k string) string { return strings.TrimSpace(r.FormValue(k)) }
func intField(r *http.Request, k string) int { n, _ := strconv.Atoi(field(r, k)); return n }
func int64Field(r *http.Request, k string) int64 {
	n, _ := strconv.ParseInt(field(r, k), 10, 64)
	return n
}
func fields(r *http.Request, key string) []string {
	_ = r.ParseForm()
	values := make([]string, 0, len(r.Form[key]))
	for _, value := range r.Form[key] {
		if value = strings.TrimSpace(value); value != "" {
			values = append(values, value)
		}
	}
	return values
}

func (a *App) newTunnel(w http.ResponseWriter, r *http.Request) {
	v := a.base(r)
	v.Title = "New tunnel"
	v.Settings, _ = a.store.Settings()
	v.RoutingGroups, _ = a.store.RoutingGroups()
	for i := v.Settings.MinPrefix; i <= v.Settings.MaxPrefix; i++ {
		v.Prefixes = append(v.Prefixes, i)
	}
	if r.Method == "POST" {
		if !a.checkCSRF(r) {
			http.Error(w, "invalid CSRF token", 403)
			return
		}
		t, e := a.CreateTunnel(CreateTunnelInput{Label: field(r, "label"), PublicKey: field(r, "public_key"), DNS: field(r, "dns"), V4Mode: field(r, "v4_mode"), RoutingGroups: fields(r, "routing_groups"), Prefix: intField(r, "prefix"), QuotaGiB: int64Field(r, "quota_gib"), GenerateKeys: r.FormValue("generate") != ""}, v.User)
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
	if len(parts) > 1 {
		if len(parts) != 2 || parts[1] != "qr.png" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		a.tunnelQRCode(w, t)
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
		case "v4-mode":
			e = a.SetTunnelV4Mode(id, field(r, "v4_mode"), v.User)
			if e == nil {
				http.Redirect(w, r, r.URL.Path+"?notice="+url.QueryEscape("IPv4 egress mode updated"), 303)
				return
			}
		case "quota":
			e = a.SetTunnelQuota(id, int64Field(r, "quota_gib"), v.User)
			if e == nil {
				http.Redirect(w, r, r.URL.Path+"?notice="+url.QueryEscape("Monthly quota updated"), 303)
				return
			}
		case "routing-groups":
			e = a.SetTunnelRoutingGroups(id, fields(r, "routing_groups"), v.User)
			if e == nil {
				http.Redirect(w, r, r.URL.Path+"?notice="+url.QueryEscape("Routing group updated"), http.StatusSeeOther)
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
	v.EffectiveV4Mode = tunnelV4Mode(v.Settings, v.Tunnel)
	v.RoutingGroups, _ = a.store.RoutingGroups()
	v.Config = a.ClientConfig(v.Tunnel, v.Settings)
	if r.URL.Query().Get("created") != "" {
		v.Notice = "Tunnel created and applied"
	} else if r.URL.Query().Get("notice") != "" {
		v.Notice = r.URL.Query().Get("notice")
	}
	a.render(w, "detail", v)
}
func (a *App) tunnelQRCode(w http.ResponseWriter, tunnel Tunnel) {
	if tunnel.PrivateKey == "" {
		http.Error(w, "QR code unavailable for a client-managed private key", http.StatusConflict)
		return
	}
	cfg, err := a.store.Settings()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	png, err := qrcode.Encode(a.ClientConfig(tunnel, cfg), qrcode.Medium, 320)
	if err != nil {
		http.Error(w, "could not generate QR code", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="tunnel-%d.png"`, tunnel.ID))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(png)
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
	if name == "detail" {
		name = "detail-groups"
	}
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

const pageHTML = `{{define "head"}}<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>{{.Title}} · Open IPv6 Tunnelbroker</title><style>body{font:16px system-ui,sans-serif;max-width:1050px;margin:2rem auto;padding:0 1rem;color:#222}nav{display:flex;gap:1rem;align-items:center;border-bottom:1px solid #ccc;padding-bottom:1rem}nav form{margin-left:auto}table{border-collapse:collapse;width:100%}th,td{text-align:left;border-bottom:1px solid #ddd;padding:.55rem}label{display:block;margin:.8rem 0 .25rem}input,select{padding:.45rem;min-width:20rem;max-width:100%}select[multiple]{min-height:8rem}input[type=checkbox]{min-width:auto}button{padding:.45rem .8rem}pre{background:#eee;padding:1rem;overflow:auto}.error{background:#fee;padding:.7rem}.notice{background:#efe;padding:.7rem}.bad{color:#a00}.muted{color:#666}.row{display:flex;gap:2rem;flex-wrap:wrap}.danger{border:1px solid #a00;padding:1rem}.tag{display:inline-block;background:#e5edf8;border-radius:1rem;padding:.15rem .55rem;margin:.1rem}</style></head><body>{{if .User}}<nav><strong>Open IPv6 Tunnelbroker</strong><a href="/">Dashboard</a><a href="/tunnels/new">New tunnel</a><a href="/settings">Settings</a><a href="/routing">Routing</a><a href="/groups">Groups</a><a href="/upgrade">Upgrade</a><form method="post" action="/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>Log out {{.User}}</button></form></nav>{{end}}<h1>{{.Title}}</h1>{{if .Error}}<p class="error">{{.Error}}</p>{{end}}{{if .Notice}}<p class="notice">{{.Notice}}</p>{{end}}{{end}}
{{define "foot"}}</body></html>{{end}}
{{define "groups"}}{{template "head" .}}<form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="create"><h2>Create group</h2><label>Group name</label><input name="name" maxlength="64" required><p><button>Create routing group</button></p></form><h2>Managed groups</h2><table><thead><tr><th>Name</th><th>Tunnels</th><th>Created</th><th>Actions</th></tr></thead><tbody>{{range .RoutingGroups}}<tr><td><span class="tag">{{.Name}}</span></td><td>{{.TunnelCount}}</td><td>{{since .CreatedAt}}</td><td><form method="post"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="action" value="rename"><input type="hidden" name="group_id" value="{{.ID}}"><input name="name" value="{{.Name}}" maxlength="64" required><button>Rename</button></form><form method="post"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="action" value="delete"><input type="hidden" name="group_id" value="{{.ID}}"><button>Delete</button></form></td></tr>{{else}}<tr><td colspan="4">No routing groups yet.</td></tr>{{end}}</tbody></table><p class="muted">Renaming preserves membership. Deleting a group removes that tag from every tunnel and immediately reapplies the routing policy.</p>{{template "foot" .}}{{end}}
{{define "detail-groups"}}{{template "head" .}}<p><strong>IPv6 allocation:</strong> {{.Tunnel.V6CIDR}}<br><strong>IPv4:</strong> {{if ne .EffectiveV4Mode "off"}}{{.Tunnel.V4Address}} ({{.EffectiveV4Mode}}){{else}}disabled{{end}}<br><strong>Routing groups:</strong> {{range .Tunnel.RoutingGroups}}<span class="tag">{{.}}</span>{{else}}none{{end}}<br><strong>Monthly traffic:</strong> {{bytes .Tunnel.QuotaUsedBytes}} of {{.Tunnel.QuotaGiB}} GiB ({{.Tunnel.QuotaPeriod}})<br><strong>State:</strong> {{if .Tunnel.QuotaDisabled}}quota reached · {{else if not .Tunnel.Enabled}}disabled · {{end}}{{.Tunnel.Status}}{{if .Tunnel.LastError}} — <span class="bad">{{.Tunnel.LastError}}</span>{{end}}</p><div class="row"><form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="v4-mode"><h2>IPv4 egress</h2><label>Mode for this tunnel</label><select name="v4_mode"><option value="" {{if eq .Tunnel.V4Mode ""}}selected{{end}}>Use global default</option><option value="off" {{if eq .Tunnel.V4Mode "off"}}selected{{end}}>Disabled</option><option value="native" {{if eq .Tunnel.V4Mode "native"}}selected{{end}}>Native upstream NAT</option><option value="warp" {{if eq .Tunnel.V4Mode "warp"}}selected{{end}}>Cloudflare WARP NAT</option></select><p class="muted">Effective mode: {{.EffectiveV4Mode}}.</p><p><button>Save and apply mode</button></p></form><form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="routing-groups"><h2>Routing groups</h2>{{if .RoutingGroups}}<label>Managed groups</label><select name="routing_groups" multiple>{{range .RoutingGroups}}<option value="{{.Name}}" {{if $.Tunnel.HasRoutingGroup .Name}}selected{{end}}>{{.Name}}</option>{{end}}</select><p class="muted">Select zero, one, or multiple groups. Use Ctrl/Cmd to select several.</p><p><button>Save routing groups</button></p>{{else}}<p class="muted">No managed groups exist. <a href="/groups">Create one</a> to enable grouped routing.</p>{{end}}</form><form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="quota"><h2>Monthly quota</h2><label>Combined upload + download quota (GiB)</label><input type="number" name="quota_gib" value="{{.Tunnel.QuotaGiB}}" min="1" required><p class="muted">Resets automatically each calendar month (UTC).</p><p><button>Save quota</button></p></form></div><h2>Client configuration</h2><pre>{{.Config}}</pre>{{if .Tunnel.PrivateKey}}<h3>Scan configuration</h3><p><img src="/tunnels/{{.Tunnel.ID}}/qr.png" width="320" height="320" alt="QR code containing the WireGuard configuration"></p><p class="muted">The QR code contains the private key and full configuration. Treat it as sensitive.</p>{{else}}<p class="muted">QR code unavailable because the client private key remains client-side.</p>{{end}}<form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="toggle"><button>{{if .Tunnel.Enabled}}Disable{{else}}Enable{{end}} tunnel</button></form><h2>Delete</h2><form method="post" class="danger"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="delete"><p>Deletion immediately removes the peer and route and frees the allocation.</p><button>Delete tunnel</button></form>{{template "foot" .}}{{end}}
{{define "routing"}}{{template "head" .}}<form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><label>Inter-tunnel routing policy</label><select name="inter_tunnel_policy"><option value="isolated" {{if eq .Settings.InterTunnelPolicy "isolated"}}selected{{end}}>Isolated (recommended default)</option><option value="groups" {{if eq .Settings.InterTunnelPolicy "groups"}}selected{{end}}>Shared managed group</option><option value="any" {{if eq .Settings.InterTunnelPolicy "any"}}selected{{end}}>Any tunnel</option></select><p class="muted"><strong>Isolated:</strong> blocks all tunnel-to-tunnel traffic. <strong>Shared managed group:</strong> permits traffic when two tunnels share at least one group. <strong>Any tunnel:</strong> permits all active tunnels to communicate. IPv4 and IPv6 source addresses are preserved; inter-tunnel traffic is never NATed.</p><p><button>Save and apply routing policy</button></p></form><h2>Routing-group assignments</h2><table><thead><tr><th>Tunnel</th><th>Groups</th><th>State</th></tr></thead><tbody>{{range .Tunnels}}<tr><td><a href="/tunnels/{{.ID}}">{{.Label}}</a></td><td>{{range .RoutingGroups}}<span class="tag">{{.}}</span>{{else}}<span class="muted">none</span>{{end}}</td><td>{{if .Enabled}}active{{else}}disabled{{end}}</td></tr>{{else}}<tr><td colspan="3">No tunnels yet.</td></tr>{{end}}</tbody></table>{{template "foot" .}}{{end}}
{{define "detail-routing"}}{{template "head" .}}<p><strong>IPv6 allocation:</strong> {{.Tunnel.V6CIDR}}<br><strong>IPv4:</strong> {{if ne .EffectiveV4Mode "off"}}{{.Tunnel.V4Address}} ({{.EffectiveV4Mode}}){{else}}disabled{{end}}<br><strong>Routing group:</strong> {{if .Tunnel.RoutingGroup}}{{.Tunnel.RoutingGroup}}{{else}}none{{end}}<br><strong>Monthly traffic:</strong> {{bytes .Tunnel.QuotaUsedBytes}} of {{.Tunnel.QuotaGiB}} GiB ({{.Tunnel.QuotaPeriod}})<br><strong>State:</strong> {{if .Tunnel.QuotaDisabled}}quota reached · {{else if not .Tunnel.Enabled}}disabled · {{end}}{{.Tunnel.Status}}{{if .Tunnel.LastError}} — <span class="bad">{{.Tunnel.LastError}}</span>{{end}}</p><div class="row"><form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="v4-mode"><h2>IPv4 egress</h2><label>Mode for this tunnel</label><select name="v4_mode"><option value="" {{if eq .Tunnel.V4Mode ""}}selected{{end}}>Use global default</option><option value="off" {{if eq .Tunnel.V4Mode "off"}}selected{{end}}>Disabled</option><option value="native" {{if eq .Tunnel.V4Mode "native"}}selected{{end}}>Native upstream NAT</option><option value="warp" {{if eq .Tunnel.V4Mode "warp"}}selected{{end}}>Cloudflare WARP NAT</option></select><p class="muted">Effective mode: {{.EffectiveV4Mode}}.</p><p><button>Save and apply mode</button></p></form><form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="routing-group"><h2>Routing group</h2><label>Group name</label><input name="routing_group" value="{{.Tunnel.RoutingGroup}}" maxlength="64" placeholder="Leave empty to isolate"><p class="muted">Used only when the global policy is Same routing group.</p><p><button>Save routing group</button></p></form><form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="quota"><h2>Monthly quota</h2><label>Combined upload + download quota (GiB)</label><input type="number" name="quota_gib" value="{{.Tunnel.QuotaGiB}}" min="1" required><p class="muted">Resets automatically each calendar month (UTC).</p><p><button>Save quota</button></p></form></div><h2>Client configuration</h2><pre>{{.Config}}</pre>{{if .Tunnel.PrivateKey}}<h3>Scan configuration</h3><p><img src="/tunnels/{{.Tunnel.ID}}/qr.png" width="320" height="320" alt="QR code containing the WireGuard configuration"></p><p class="muted">The QR code contains the private key and full configuration. Treat it as sensitive.</p>{{else}}<p class="muted">QR code unavailable because the client private key remains client-side.</p>{{end}}<form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="toggle"><button>{{if .Tunnel.Enabled}}Disable{{else}}Enable{{end}} tunnel</button></form><h2>Delete</h2><form method="post" class="danger"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="delete"><p>Deletion immediately removes the peer and route and frees the allocation.</p><button>Delete tunnel</button></form>{{template "foot" .}}{{end}}
{{define "upgrade"}}{{template "head" .}}<p><strong>Repository:</strong> {{if .Upgrade.Repository}}{{.Upgrade.Repository}}{{else}}not configured{{end}}<br><strong>Remote:</strong> {{.Upgrade.Remote}}<br><strong>Branch:</strong> {{.Upgrade.Branch}}<br><strong>Current revision:</strong> {{.Upgrade.Revision}}<br><strong>Last upgrade:</strong> {{.Upgrade.State}}{{if .Upgrade.Detail}} — {{.Upgrade.Detail}}{{end}}</p>{{if .Upgrade.Available}}<form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><p>The upgrade service will require a clean checkout, fetch and fast-forward the current branch from <code>origin</code>, run all tests, build and atomically install the binary, then restart the application.</p><button>Pull, test, and deploy latest</button></form>{{else}}<p class="error">Self-upgrade is unavailable. Configure the deployment checkout and systemd upgrade unit.</p>{{end}}{{template "foot" .}}{{end}}
{{define "detail-quota"}}{{template "head" .}}<p><strong>IPv6 allocation:</strong> {{.Tunnel.V6CIDR}}<br><strong>IPv4:</strong> {{if ne .EffectiveV4Mode "off"}}{{.Tunnel.V4Address}} ({{.EffectiveV4Mode}}){{else}}disabled{{end}}<br><strong>Monthly traffic:</strong> {{bytes .Tunnel.QuotaUsedBytes}} of {{.Tunnel.QuotaGiB}} GiB ({{.Tunnel.QuotaPeriod}})<br><strong>State:</strong> {{if .Tunnel.QuotaDisabled}}quota reached · {{else if not .Tunnel.Enabled}}disabled · {{end}}{{.Tunnel.Status}}{{if .Tunnel.LastError}} — <span class="bad">{{.Tunnel.LastError}}</span>{{end}}</p><div class="row"><form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="v4-mode"><h2>IPv4 egress</h2><label>Mode for this tunnel</label><select name="v4_mode"><option value="" {{if eq .Tunnel.V4Mode ""}}selected{{end}}>Use global default</option><option value="off" {{if eq .Tunnel.V4Mode "off"}}selected{{end}}>Disabled</option><option value="native" {{if eq .Tunnel.V4Mode "native"}}selected{{end}}>Native upstream NAT</option><option value="warp" {{if eq .Tunnel.V4Mode "warp"}}selected{{end}}>Cloudflare WARP NAT</option></select><p class="muted">Effective mode: {{.EffectiveV4Mode}}.</p><p><button>Save and apply mode</button></p></form><form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="quota"><h2>Monthly quota</h2><label>Combined upload + download quota (GiB)</label><input type="number" name="quota_gib" value="{{.Tunnel.QuotaGiB}}" min="1" required><p class="muted">Resets automatically each calendar month (UTC).</p><p><button>Save quota</button></p></form></div><h2>Client configuration</h2><pre>{{.Config}}</pre>{{if .Tunnel.PrivateKey}}<h3>Scan configuration</h3><p><img src="/tunnels/{{.Tunnel.ID}}/qr.png" width="320" height="320" alt="QR code containing the WireGuard configuration"></p><p class="muted">The QR code contains the private key and full configuration. Treat it as sensitive.</p>{{else}}<p class="muted">QR code unavailable because the client private key remains client-side.</p>{{end}}<form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="toggle"><button>{{if .Tunnel.Enabled}}Disable{{else}}Enable{{end}} tunnel</button></form><h2>Delete</h2><form method="post" class="danger"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="delete"><p>Deletion immediately removes the peer and route and frees the allocation.</p><button>Delete tunnel</button></form>{{template "foot" .}}{{end}}
{{define "detail-v4-mode"}}{{template "head" .}}<p><strong>IPv6 allocation:</strong> {{.Tunnel.V6CIDR}}<br><strong>IPv4:</strong> {{if ne .EffectiveV4Mode "off"}}{{.Tunnel.V4Address}} ({{.EffectiveV4Mode}}){{else}}disabled{{end}}<br><strong>State:</strong> {{if not .Tunnel.Enabled}}disabled · {{end}}{{.Tunnel.Status}}{{if .Tunnel.LastError}} — <span class="bad">{{.Tunnel.LastError}}</span>{{end}}</p><h2>IPv4 egress</h2><form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="v4-mode"><label>Mode for this tunnel</label><select name="v4_mode"><option value="" {{if eq .Tunnel.V4Mode ""}}selected{{end}}>Use global default</option><option value="off" {{if eq .Tunnel.V4Mode "off"}}selected{{end}}>Disabled</option><option value="native" {{if eq .Tunnel.V4Mode "native"}}selected{{end}}>Native upstream NAT</option><option value="warp" {{if eq .Tunnel.V4Mode "warp"}}selected{{end}}>Cloudflare WARP NAT</option></select><p class="muted">Effective mode: {{.EffectiveV4Mode}}. Choosing the global default keeps this tunnel synchronized with Settings.</p><p><button>Save and apply mode</button></p></form><h2>Client configuration</h2><pre>{{.Config}}</pre>{{if .Tunnel.PrivateKey}}<h3>Scan configuration</h3><p><img src="/tunnels/{{.Tunnel.ID}}/qr.png" width="320" height="320" alt="QR code containing the WireGuard configuration"></p><p class="muted">The QR code contains the private key and full configuration. Treat it as sensitive.</p>{{else}}<p class="muted">QR code unavailable because the client private key remains client-side.</p>{{end}}<form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="toggle"><button>{{if .Tunnel.Enabled}}Disable{{else}}Enable{{end}} tunnel</button></form><h2>Delete</h2><form method="post" class="danger"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="delete"><p>Deletion immediately removes the peer and route and frees the allocation.</p><button>Delete tunnel</button></form>{{template "foot" .}}{{end}}
{{define "login"}}{{template "head" .}}<form method="post"><label>Username</label><input name="username" autocomplete="username" required><label>Password</label><input type="password" name="password" autocomplete="current-password" required><p><button>Log in</button></p></form>{{template "foot" .}}{{end}}
{{define "dashboard"}}{{template "head" .}}{{if not .Settings.UpstreamV6}}<p class="error">Configure the upstream prefix before creating tunnels.</p>{{end}}<div class="row"><div><h2>Pool</h2><p>Upstream: {{.Settings.UpstreamV6}}<br>/64 units allocated: {{.Allocated}}<br>Largest available block: {{if ge .Largest 0}}/{{.Largest}}{{else}}none{{end}}</p></div><div><h2>Reconciliation</h2><p>Last: {{since .Health.LastReconcile}}<br>{{if .Health.Error}}<span class="bad">{{.Health.Error}}</span>{{else}}No apply error{{end}}<br>{{if .Health.Drift}}<span class="bad">Drift remains: {{range .Health.Drift}}{{.}}; {{end}}</span>{{else}}Kernel matches database{{end}}</p><form method="post" action="/resync"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>Resync now</button></form></div></div><h2>Tunnels</h2><table><thead><tr><th>Name</th><th>IPv6</th><th>IPv4</th><th>Status</th><th>Last handshake</th><th>Traffic</th></tr></thead><tbody>{{range .Tunnels}}<tr><td><a href="/tunnels/{{.ID}}">{{.Label}}</a></td><td>{{.V6CIDR}}</td><td>{{.V4Address}}</td><td>{{if not .Enabled}}disabled · {{end}}<span class="{{if eq .Status "error"}}bad{{end}}">{{.Status}}</span></td><td>{{since .LastHandshake}}</td><td>↓ {{bytes .RXBytes}} / ↑ {{bytes .TXBytes}}</td></tr>{{else}}<tr><td colspan="6">No tunnels yet.</td></tr>{{end}}</tbody></table>{{template "foot" .}}{{end}}
{{define "settings"}}{{template "head" .}}<form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><div class="row"><div><h2>Upstream</h2><label>IPv6 delegated prefix</label><input name="upstream_v6" value="{{.Settings.UpstreamV6}}" placeholder="2001:db8::/48" required><label>Server address/prefix</label><input name="server_address" value="{{.Settings.ServerAddress}}" placeholder="2001:db8::1/64"><label>Public IPv4 (informational)</label><input name="upstream_v4" value="{{.Settings.UpstreamV4}}"><label>Upstream interface</label><input name="upstream_interface" value="{{.Settings.UpstreamInterface}}"></div><div><h2>WireGuard</h2><label>Interface</label><input name="interface_name" value="{{.Settings.InterfaceName}}" required><label>Endpoint hostname/IP</label><input name="endpoint_host" value="{{.Settings.EndpointHost}}" required><label>Listen port</label><input type="number" name="endpoint_port" value="{{.Settings.EndpointPort}}" required><label>MTU</label><input type="number" name="mtu" value="{{.Settings.MTU}}"><label>Keepalive seconds</label><input type="number" name="keepalive" value="{{.Settings.Keepalive}}"></div></div><div class="row"><div><h2>Allocation</h2><label>Largest allowed allocation prefix</label><input type="number" name="min_prefix" value="{{.Settings.MinPrefix}}"><label>Smallest allowed allocation prefix</label><input type="number" name="max_prefix" value="{{.Settings.MaxPrefix}}"><label>Default prefix</label><input type="number" name="default_prefix" value="{{.Settings.DefaultPrefix}}"></div><div><h2>Clients</h2><label>Default DNS</label><input name="default_dns" value="{{.Settings.DefaultDNS}}"><label>IPv4 egress mode</label><select name="v4_mode"><option value="off" {{if and (not .Settings.V4NAT) (not .Settings.V4Warp)}}selected{{end}}>Disabled</option><option value="native" {{if .Settings.V4NAT}}selected{{end}}>Native upstream NAT</option><option value="warp" {{if .Settings.V4Warp}}selected{{end}}>Cloudflare WARP NAT</option></select><label>Internal IPv4 pool</label><input name="v4_pool" value="{{.Settings.V4Pool}}"></div></div><p><button>Save and apply</button></p></form><h2>Cloudflare WARP account</h2>{{if .Warp.Exists}}<p>Account: {{if .Warp.AccountID}}{{.Warp.AccountID}}{{else}}registered{{end}}<br>Type: {{.Warp.AccountType}}<br>WARP IPv4: {{.Warp.IPv4Address}}<br>Endpoint: {{.Warp.Endpoint}}<br>Created: {{since .Warp.CreatedAt}}</p>{{else}}<p>No WARP account is registered. Create one before selecting Cloudflare WARP NAT.</p>{{end}}<p class="muted">Creating an account contacts Cloudflare's WARP registration API and records acceptance of its terms at the current time.</p><form method="post" action="/warp"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="register"><button>{{if .Warp.Exists}}Recreate{{else}}Create{{end}} WARP account</button></form>{{if and .Warp.Exists .Settings.V4Warp}}<form method="post" action="/warp"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="test"><button>Test WARP outbound IP</button></form>{{end}}{{if .Warp.LastTrace}}<h3>Last WARP trace</h3><p class="muted">Tested {{since .Warp.LastTestAt}}</p><pre>{{.Warp.LastTrace}}</pre>{{end}}<h2>Reset general settings</h2><p>Restores IPv4 mode, address pool, DNS, port, MTU, keepalive, and allocation sizes to application defaults. Upstream prefixes, endpoint host, interfaces, server address, and keys are preserved.</p><form method="post" action="/settings/reset"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>Reset general settings to defaults</button></form>{{template "foot" .}}{{end}}
{{define "new"}}{{template "head" .}}<form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><label>Label</label><input name="label" required><label>Allocation size</label><select name="prefix">{{range .Prefixes}}<option value="{{.}}" {{if eq . $.Settings.DefaultPrefix}}selected{{end}}>/{{.}}</option>{{end}}</select><label><input type="checkbox" name="generate" checked> Generate client keypair (private key is stored and shown to the admin)</label><label>Client public key (uncheck generate to use)</label><input name="public_key"><label>DNS override</label><input name="dns" placeholder="{{.Settings.DefaultDNS}}"><label>IPv4 egress mode</label><select name="v4_mode"><option value="" selected>Use global default</option><option value="off">Disabled</option><option value="native">Native upstream NAT</option><option value="warp">Cloudflare WARP NAT</option></select><p class="muted">The global setting remains the default unless this tunnel overrides it.</p><label>Routing groups</label>{{if .RoutingGroups}}<select name="routing_groups" multiple>{{range .RoutingGroups}}<option value="{{.Name}}">{{.Name}}</option>{{end}}</select><p class="muted">Select zero, one, or multiple groups. Use Ctrl/Cmd to select several.</p>{{else}}<p class="muted">No managed groups exist. <a href="/groups">Create a routing group</a> first, or leave this tunnel isolated.</p>{{end}}<label>Monthly upload + download quota (GiB)</label><input type="number" name="quota_gib" value="100" min="1" required><p class="muted">Usage resets on the first day of each calendar month (UTC).</p><p><button>Create and apply</button></p></form>{{template "foot" .}}{{end}}
{{define "detail"}}{{template "head" .}}<p><strong>IPv6 allocation:</strong> {{.Tunnel.V6CIDR}}<br><strong>IPv4:</strong> {{if and (or .Settings.V4NAT .Settings.V4Warp) .Tunnel.V4Enabled}}{{.Tunnel.V4Address}}{{else}}disabled{{end}}<br><strong>State:</strong> {{if not .Tunnel.Enabled}}disabled · {{end}}{{.Tunnel.Status}}{{if .Tunnel.LastError}} — <span class="bad">{{.Tunnel.LastError}}</span>{{end}}</p><h2>Client configuration</h2><pre>{{.Config}}</pre>{{if .Tunnel.PrivateKey}}<h3>Scan configuration</h3><p><img src="/tunnels/{{.Tunnel.ID}}/qr.png" width="320" height="320" alt="QR code containing the WireGuard configuration"></p><p class="muted">The QR code contains the private key and full configuration. Treat it as sensitive. Client-generated keys remain the preferred higher-security workflow.</p>{{else}}<p class="muted">QR code unavailable because the client private key remains client-side.</p>{{end}}<form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="toggle"><button>{{if .Tunnel.Enabled}}Disable{{else}}Enable{{end}} tunnel</button></form><h2>Delete</h2><form method="post" class="danger"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="delete"><p>Deletion immediately removes the peer and route and frees the allocation.</p><button>Delete tunnel</button></form>{{template "foot" .}}{{end}}`
