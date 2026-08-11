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

// upstreamView decorates one provider connection with the pool statistics the
// dashboard and upstream pages report.
type upstreamView struct {
	Upstream
	Allocated       uint64
	Largest         int
	EffectiveV4Mode string
}

type view struct {
	Title, User, CSRF, Error, Notice, Config, EffectiveV4Mode string
	Settings                                                  Settings
	Warp                                                      WarpAccount
	Tunnels                                                   []Tunnel
	Tunnel                                                    Tunnel
	Upstream                                                  Upstream
	Upstreams                                                 []upstreamView
	UpstreamNames                                             map[int64]string
	Health                                                    Health
	Upgrade                                                   UpgradeStatus
	Prefixes                                                  []int
	RoutingGroups                                             []RoutingGroup
	Editing                                                   bool
}

func (a *App) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/login", a.login)
	m.HandleFunc("/logout", a.auth(a.logout))
	m.HandleFunc("/", a.auth(a.dashboard))
	m.HandleFunc("/settings", a.auth(a.settings))
	m.HandleFunc("/settings/reset", a.auth(a.resetSettings))
	m.HandleFunc("/upstreams", a.auth(a.upstreams))
	m.HandleFunc("/upstreams/new", a.auth(a.newUpstream))
	m.HandleFunc("/upstreams/", a.auth(a.upstream))
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

// upstreamViews computes per-upstream pool statistics so that each connection
// reports its own free space rather than a meaningless deployment-wide total.
func (a *App) upstreamViews(cfg Settings) ([]upstreamView, error) {
	upstreams, err := a.store.Upstreams()
	if err != nil {
		return nil, err
	}
	views := make([]upstreamView, 0, len(upstreams))
	for _, upstream := range upstreams {
		item := upstreamView{Upstream: upstream, Largest: -1, EffectiveV4Mode: upstreamV4Mode(cfg, upstream)}
		if pool, ok := delegatedPrefix(upstream); ok {
			used, usedErr := a.store.UsedPrefixes(upstream.ID)
			if usedErr != nil {
				return nil, usedErr
			}
			if reserved, hasReservation := serverReservation(upstream); hasReservation {
				used = append(used, reserved)
			}
			item.Allocated, item.Largest = PoolStats(pool, used, upstream.MaxPrefix)
		}
		views = append(views, item)
	}
	return views, nil
}

func upstreamNames(upstreams []upstreamView) map[int64]string {
	names := make(map[int64]string, len(upstreams))
	for _, upstream := range upstreams {
		names[upstream.ID] = upstream.Name
	}
	return names
}

func (a *App) dashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	v := a.base(r)
	v.Title = "Dashboard"
	v.Notice = r.URL.Query().Get("notice")
	v.Error = r.URL.Query().Get("error")
	v.Tunnels, _ = a.store.Tunnels()
	v.Settings, _ = a.store.Settings()
	a.mu.Lock()
	v.Health = a.health
	v.Health.Drift = append([]string(nil), a.health.Drift...)
	a.mu.Unlock()
	upstreams, err := a.upstreamViews(v.Settings)
	if err != nil {
		v.Error = err.Error()
	}
	v.Upstreams = upstreams
	v.UpstreamNames = upstreamNames(upstreams)
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
		v.Settings = Settings{V4NAT: v4Mode == V4ModeNative, V4Warp: v4Mode == V4ModeWarp, V4Pool: field(r, "v4_pool"), DefaultDNS: field(r, "default_dns"), InterTunnelPolicy: old.InterTunnelPolicy}
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
	v.Upstreams, _ = a.upstreamViews(v.Settings)
	a.render(w, "settings", v)
}

func (a *App) upstreams(w http.ResponseWriter, r *http.Request) {
	v := a.base(r)
	v.Title = "Upstreams"
	v.Notice = r.URL.Query().Get("notice")
	v.Error = r.URL.Query().Get("error")
	v.Settings, _ = a.store.Settings()
	upstreams, err := a.upstreamViews(v.Settings)
	if err != nil {
		v.Error = err.Error()
	}
	v.Upstreams = upstreams
	a.render(w, "upstreams", v)
}

func (a *App) newUpstream(w http.ResponseWriter, r *http.Request) {
	v := a.base(r)
	v.Title = "New upstream"
	v.Settings, _ = a.store.Settings()
	v.Upstream = Upstream{Mode: UpstreamRouted, EndpointPort: 51820, MTU: 1420, Keepalive: 25, MinPrefix: 48, MaxPrefix: 64, DefaultPrefix: 56, InterfaceName: a.suggestInterfaceName()}
	if r.Method == http.MethodPost {
		if !a.checkCSRF(r) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		in := upstreamInputFrom(r, 0)
		v.Upstream = in.apply(v.Upstream)
		created, err := a.CreateUpstream(in, v.User)
		if err != nil {
			v.Error = err.Error()
		} else {
			http.Redirect(w, r, fmt.Sprintf("/upstreams/%d?notice=%s", created.ID, url.QueryEscape("Upstream created and applied")), http.StatusSeeOther)
			return
		}
	}
	a.render(w, "upstream-form", v)
}

// suggestInterfaceName proposes the first unused wgN name so that adding an
// upstream needs no manual interface bookkeeping.
func (a *App) suggestInterfaceName() string {
	existing, err := a.store.Upstreams()
	if err != nil {
		return "wg0"
	}
	taken := make(map[string]bool, len(existing))
	for _, upstream := range existing {
		taken[upstream.InterfaceName] = true
	}
	for index := 0; index < 256; index++ {
		name := fmt.Sprintf("wg%d", index)
		if !taken[name] {
			return name
		}
	}
	return ""
}

func upstreamInputFrom(r *http.Request, id int64) UpstreamInput {
	return UpstreamInput{
		ID:               id,
		Name:             field(r, "name"),
		V6CIDR:           field(r, "v6_cidr"),
		Mode:             field(r, "mode"),
		PublicV4:         field(r, "public_v4"),
		EgressInterface:  field(r, "egress_interface"),
		InterfaceName:    field(r, "interface_name"),
		EndpointHost:     field(r, "endpoint_host"),
		EndpointPort:     intField(r, "endpoint_port"),
		ServerAddress:    field(r, "server_address"),
		TransportAddress: field(r, "transport_address"),
		MTU:              intField(r, "mtu"),
		Keepalive:        intField(r, "keepalive"),
		MinPrefix:        intField(r, "min_prefix"),
		MaxPrefix:        intField(r, "max_prefix"),
		DefaultPrefix:    intField(r, "default_prefix"),
		V4Mode:           field(r, "v4_mode"),
	}
}

func (a *App) upstream(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(strings.Trim(strings.TrimPrefix(r.URL.Path, "/upstreams/"), "/"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	stored, err := a.store.Upstream(id)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	v := a.base(r)
	v.Editing = true
	v.Upstream = stored
	v.Settings, _ = a.store.Settings()
	v.Notice = r.URL.Query().Get("notice")
	if r.Method == http.MethodPost {
		if !a.checkCSRF(r) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		switch field(r, "action") {
		case "delete":
			if err = a.DeleteUpstream(id, v.User); err != nil {
				v.Error = err.Error()
			} else {
				http.Redirect(w, r, "/upstreams?notice="+url.QueryEscape("Upstream deleted"), http.StatusSeeOther)
				return
			}
		default:
			in := upstreamInputFrom(r, id)
			v.Upstream = in.apply(stored)
			if _, err = a.UpdateUpstream(in, v.User); err != nil {
				v.Error = err.Error()
			} else {
				http.Redirect(w, r, r.URL.Path+"?notice="+url.QueryEscape("Upstream saved and applied"), http.StatusSeeOther)
				return
			}
		}
	}
	v.Title = v.Upstream.Name
	v.Tunnels, _ = a.store.TunnelsForUpstream(id)
	a.render(w, "upstream-form", v)
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
	upstreams, _ := a.upstreamViews(v.Settings)
	v.UpstreamNames = upstreamNames(upstreams)
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
	upstreams, err := a.upstreamViews(v.Settings)
	if err != nil {
		v.Error = err.Error()
	}
	v.Upstreams = upstreams
	// The prefix menu belongs to one upstream, so it is offered for the
	// selected connection, defaulting to the first when none was chosen yet.
	selected := int64Field(r, "upstream_id")
	for _, upstream := range upstreams {
		if selected == 0 || upstream.ID == selected {
			v.Upstream = upstream.Upstream
			break
		}
	}
	for i := v.Upstream.MinPrefix; i <= v.Upstream.MaxPrefix && v.Upstream.ID != 0; i++ {
		v.Prefixes = append(v.Prefixes, i)
	}
	if r.Method == "POST" {
		if !a.checkCSRF(r) {
			http.Error(w, "invalid CSRF token", 403)
			return
		}
		t, e := a.CreateTunnel(CreateTunnelInput{UpstreamID: selected, Label: field(r, "label"), PublicKey: field(r, "public_key"), DNS: field(r, "dns"), V4Mode: field(r, "v4_mode"), RoutingGroups: fields(r, "routing_groups"), Prefix: intField(r, "prefix"), QuotaGiB: int64Field(r, "quota_gib"), GenerateKeys: r.FormValue("generate") != ""}, v.User)
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
	if errors.Is(e, sql.ErrNoRows) {
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
	v.Upstream, _ = a.store.Upstream(v.Tunnel.UpstreamID)
	v.EffectiveV4Mode = tunnelV4Mode(v.Settings, v.Upstream, v.Tunnel)
	v.RoutingGroups, _ = a.store.RoutingGroups()
	v.Config = a.ClientConfig(v.Tunnel, v.Upstream, v.Settings)
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
	upstream, err := a.store.Upstream(tunnel.UpstreamID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	png, err := qrcode.Encode(a.ClientConfig(tunnel, upstream, cfg), qrcode.Medium, 320)
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
}, "upstreamName": func(names map[int64]string, id int64) string {
	if name, ok := names[id]; ok {
		return name
	}
	return "unassigned"
}, "endpoint": func(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}, "cidrHost": func(cidr string) string {
	if prefix, err := netip.ParsePrefix(cidr); err == nil {
		return prefix.Masked().String()
	}
	return cidr
}}).Parse(pageHTML))

const pageHTML = `{{define "head"}}<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>{{.Title}} · Open IPv6 Tunnelbroker</title><style>body{font:16px system-ui,sans-serif;max-width:1050px;margin:2rem auto;padding:0 1rem;color:#222}nav{display:flex;gap:1rem;align-items:center;border-bottom:1px solid #ccc;padding-bottom:1rem;flex-wrap:wrap}nav form{margin-left:auto}table{border-collapse:collapse;width:100%}th,td{text-align:left;border-bottom:1px solid #ddd;padding:.55rem}label{display:block;margin:.8rem 0 .25rem}input,select{padding:.45rem;min-width:20rem;max-width:100%}select[multiple]{min-height:8rem}input[type=checkbox]{min-width:auto}button{padding:.45rem .8rem}pre{background:#eee;padding:1rem;overflow:auto}.error{background:#fee;padding:.7rem}.notice{background:#efe;padding:.7rem}.bad{color:#a00}.muted{color:#666}.row{display:flex;gap:2rem;flex-wrap:wrap}.danger{border:1px solid #a00;padding:1rem}.tag{display:inline-block;background:#e5edf8;border-radius:1rem;padding:.15rem .55rem;margin:.1rem}.card{border:1px solid #ddd;padding:1rem;margin:.5rem 0}</style></head><body>{{if .User}}<nav><strong>Open IPv6 Tunnelbroker</strong><a href="/">Dashboard</a><a href="/upstreams">Upstreams</a><a href="/tunnels/new">New tunnel</a><a href="/settings">Settings</a><a href="/routing">Routing</a><a href="/groups">Groups</a><a href="/upgrade">Upgrade</a><form method="post" action="/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>Log out {{.User}}</button></form></nav>{{end}}<h1>{{.Title}}</h1>{{if .Error}}<p class="error">{{.Error}}</p>{{end}}{{if .Notice}}<p class="notice">{{.Notice}}</p>{{end}}{{end}}
{{define "foot"}}</body></html>{{end}}
{{define "login"}}{{template "head" .}}<form method="post"><label>Username</label><input name="username" autocomplete="username" required><label>Password</label><input type="password" name="password" autocomplete="current-password" required><p><button>Log in</button></p></form>{{template "foot" .}}{{end}}
{{define "dashboard"}}{{template "head" .}}{{if not .Upstreams}}<p class="error">No upstream is configured. <a href="/upstreams/new">Add an upstream</a> before creating tunnels.</p>{{end}}<h2>Upstreams</h2><table><thead><tr><th>Name</th><th>Delegated prefix</th><th>Delegation</th><th>Interfaces</th><th>/64 units allocated</th><th>Largest free block</th><th>Tunnels</th></tr></thead><tbody>{{range .Upstreams}}<tr><td><a href="/upstreams/{{.ID}}">{{.Name}}</a></td><td>{{.V6CIDR}}</td><td>{{if eq .Mode "on-link"}}on-link, proxying ND{{else}}routed{{end}}</td><td>{{.InterfaceName}} via {{.EgressInterface}}</td><td>{{.Allocated}}</td><td>{{if ge .Largest 0}}/{{.Largest}}{{else}}none{{end}}</td><td>{{.TunnelCount}}</td></tr>{{else}}<tr><td colspan="7">No upstreams yet.</td></tr>{{end}}</tbody></table><h2>Reconciliation</h2><p>Last: {{since .Health.LastReconcile}}<br>{{if .Health.Error}}<span class="bad">{{.Health.Error}}</span>{{else}}No apply error{{end}}<br>{{if .Health.Drift}}<span class="bad">Drift remains: {{range .Health.Drift}}{{.}}; {{end}}</span>{{else}}Kernel matches database{{end}}</p><form method="post" action="/resync"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>Resync now</button></form><h2>Tunnels</h2><table><thead><tr><th>Name</th><th>Upstream</th><th>IPv6</th><th>IPv4</th><th>Status</th><th>Last handshake</th><th>Traffic</th></tr></thead><tbody>{{range .Tunnels}}<tr><td><a href="/tunnels/{{.ID}}">{{.Label}}</a></td><td>{{upstreamName $.UpstreamNames .UpstreamID}}</td><td>{{.V6CIDR}}</td><td>{{.V4Address}}</td><td>{{if not .Enabled}}disabled · {{end}}<span class="{{if eq .Status "error"}}bad{{end}}">{{.Status}}</span></td><td>{{since .LastHandshake}}</td><td>↓ {{bytes .RXBytes}} / ↑ {{bytes .TXBytes}}</td></tr>{{else}}<tr><td colspan="7">No tunnels yet.</td></tr>{{end}}</tbody></table>{{template "foot" .}}{{end}}
{{define "upstreams"}}{{template "head" .}}<p>Each upstream is an independent provider connection with its own delegated IPv6 prefix, egress interface, and WireGuard interface. Tunnels are allocated from one upstream and always egress through that provider.</p><p><a href="/upstreams/new">Add an upstream</a></p>{{range .Upstreams}}<div class="card"><h2><a href="/upstreams/{{.ID}}">{{.Name}}</a></h2><p><strong>Delegated prefix:</strong> {{.V6CIDR}}<br><strong>Delegation:</strong> {{if eq .Mode "on-link"}}on-link, proxying Neighbor Discovery{{else}}routed to this host{{end}}<br><strong>Egress interface:</strong> {{.EgressInterface}}<br><strong>WireGuard interface:</strong> {{.InterfaceName}} on {{endpoint .EndpointHost .EndpointPort}}<br><strong>Allocation sizes:</strong> /{{.MinPrefix}} to /{{.MaxPrefix}}, default /{{.DefaultPrefix}}<br><strong>IPv4 egress:</strong> {{.EffectiveV4Mode}}{{if eq .V4Mode ""}} (global default){{end}}<br><strong>/64 units allocated:</strong> {{.Allocated}}<br><strong>Largest free block:</strong> {{if ge .Largest 0}}/{{.Largest}}{{else}}none{{end}}<br><strong>Tunnels:</strong> {{.TunnelCount}}</p></div>{{else}}<p>No upstreams are configured yet.</p>{{end}}{{template "foot" .}}{{end}}
{{define "upstream-form"}}{{template "head" .}}<form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><div class="row"><div><h2>Identity</h2><label>Upstream name</label><input name="name" value="{{.Upstream.Name}}" maxlength="64" required><p class="muted">A label for this provider connection, shown when choosing where to allocate a tunnel.</p><label>IPv6 delegated prefix</label><input name="v6_cidr" value="{{.Upstream.V6CIDR}}" placeholder="2001:db8::/48" required><label>Prefix delegation</label><select name="mode"><option value="routed" {{if ne .Upstream.Mode "on-link"}}selected{{end}}>Routed to this host (normal)</option><option value="on-link" {{if eq .Upstream.Mode "on-link"}}selected{{end}}>On-link, proxy Neighbor Discovery (single /64 VPS)</option></select><p class="muted"><strong>Routed:</strong> the provider routes the whole prefix here, so subprefixes only need a route. <strong>On-link:</strong> the provider resolves every address in the prefix with Neighbor Discovery on its segment, as many VPS hosts do with a single /64. The daemon then answers that discovery for delegated addresses.</p><label>Server address/prefix</label><input name="server_address" value="{{.Upstream.ServerAddress}}" placeholder="2001:db8::1/64"><p class="muted">Leave empty for on-link delegation: the whole prefix goes downstream, and the host keeps its provider-assigned address on the egress interface.</p><label>WireGuard transport address</label><input name="transport_address" value="{{.Upstream.TransportAddress}}" placeholder="fd00:6b72:6f6b:1::1/64"><p class="muted">Numbers this upstream's tunnel interface from outside the delegated prefix, which on-link delegation requires. Each upstream needs its own range; a ULA is appropriate.</p><label>Public IPv4 (informational)</label><input name="public_v4" value="{{.Upstream.PublicV4}}"><label>Egress interface</label><input name="egress_interface" value="{{.Upstream.EgressInterface}}" placeholder="eth0, ppp0, wg-provider" required><p class="muted">The interface this provider's traffic leaves through: Ethernet, an L2TP/PPP session, another WireGuard tunnel, or any interface carrying a BGP-learned path. On-link delegation proxies Neighbor Discovery here, so it must then be Ethernet.</p></div><div><h2>WireGuard</h2><label>Interface name</label><input name="interface_name" value="{{.Upstream.InterfaceName}}" maxlength="15" required><p class="muted">Must be unique across upstreams; each connection gets its own device.</p><label>Endpoint hostname/IP</label><input name="endpoint_host" value="{{.Upstream.EndpointHost}}" required><label>Listen port</label><input type="number" name="endpoint_port" value="{{.Upstream.EndpointPort}}" required><p class="muted">Two upstreams cannot share the same endpoint host and port.</p><label>MTU</label><input type="number" name="mtu" value="{{.Upstream.MTU}}"><label>Keepalive seconds</label><input type="number" name="keepalive" value="{{.Upstream.Keepalive}}"><h2>Allocation</h2><label>Largest allowed allocation prefix</label><input type="number" name="min_prefix" value="{{.Upstream.MinPrefix}}"><label>Smallest allowed allocation prefix</label><input type="number" name="max_prefix" value="{{.Upstream.MaxPrefix}}"><label>Default prefix</label><input type="number" name="default_prefix" value="{{.Upstream.DefaultPrefix}}"><label>IPv4 egress mode</label><select name="v4_mode"><option value="" {{if eq .Upstream.V4Mode ""}}selected{{end}}>Use global default</option><option value="off" {{if eq .Upstream.V4Mode "off"}}selected{{end}}>Disabled</option><option value="native" {{if eq .Upstream.V4Mode "native"}}selected{{end}}>Native NAT through this upstream</option><option value="warp" {{if eq .Upstream.V4Mode "warp"}}selected{{end}}>Cloudflare WARP NAT</option></select><p class="muted">An upstream with no IPv4 connectivity of its own can disable IPv4 for all of its tunnels here, or send them through WARP instead.</p></div></div><p><button>{{if .Editing}}Save and apply{{else}}Create upstream{{end}}</button></p></form>{{if .Editing}}<h2>Tunnels on this upstream</h2><table><thead><tr><th>Name</th><th>IPv6</th><th>Status</th></tr></thead><tbody>{{range .Tunnels}}<tr><td><a href="/tunnels/{{.ID}}">{{.Label}}</a></td><td>{{.V6CIDR}}</td><td>{{if not .Enabled}}disabled · {{end}}{{.Status}}</td></tr>{{else}}<tr><td colspan="3">No tunnels are allocated from this upstream.</td></tr>{{end}}</tbody></table><h2>Delete</h2><form method="post" class="danger"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="delete"><p>Deleting an upstream removes its WireGuard interface and policy routing table. It is refused while tunnels are still allocated from it.</p><button>Delete upstream</button></form>{{end}}{{template "foot" .}}{{end}}
{{define "groups"}}{{template "head" .}}<form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="create"><h2>Create group</h2><label>Group name</label><input name="name" maxlength="64" required><p><button>Create routing group</button></p></form><h2>Managed groups</h2><table><thead><tr><th>Name</th><th>Tunnels</th><th>Created</th><th>Actions</th></tr></thead><tbody>{{range .RoutingGroups}}<tr><td><span class="tag">{{.Name}}</span></td><td>{{.TunnelCount}}</td><td>{{since .CreatedAt}}</td><td><form method="post"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="action" value="rename"><input type="hidden" name="group_id" value="{{.ID}}"><input name="name" value="{{.Name}}" maxlength="64" required><button>Rename</button></form><form method="post"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="action" value="delete"><input type="hidden" name="group_id" value="{{.ID}}"><button>Delete</button></form></td></tr>{{else}}<tr><td colspan="4">No routing groups yet.</td></tr>{{end}}</tbody></table><p class="muted">Renaming preserves membership. Deleting a group removes that tag from every tunnel and immediately reapplies the routing policy. Group membership spans upstreams: two tunnels in one group can reach each other even when their prefixes come from different providers.</p>{{template "foot" .}}{{end}}
{{define "routing"}}{{template "head" .}}<form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><label>Inter-tunnel routing policy</label><select name="inter_tunnel_policy"><option value="isolated" {{if eq .Settings.InterTunnelPolicy "isolated"}}selected{{end}}>Isolated (recommended default)</option><option value="groups" {{if eq .Settings.InterTunnelPolicy "groups"}}selected{{end}}>Shared managed group</option><option value="any" {{if eq .Settings.InterTunnelPolicy "any"}}selected{{end}}>Any tunnel</option></select><p class="muted"><strong>Isolated:</strong> blocks all tunnel-to-tunnel traffic. <strong>Shared managed group:</strong> permits traffic when two tunnels share at least one group. <strong>Any tunnel:</strong> permits all active tunnels to communicate. The policy applies across upstreams as well as within one, so tunnels from unrelated providers can reach each other. IPv4 and IPv6 source addresses are preserved; inter-tunnel traffic is never NATed.</p><p><button>Save and apply routing policy</button></p></form><h2>Routing-group assignments</h2><table><thead><tr><th>Tunnel</th><th>Upstream</th><th>Groups</th><th>State</th></tr></thead><tbody>{{range .Tunnels}}<tr><td><a href="/tunnels/{{.ID}}">{{.Label}}</a></td><td>{{upstreamName $.UpstreamNames .UpstreamID}}</td><td>{{range .RoutingGroups}}<span class="tag">{{.}}</span>{{else}}<span class="muted">none</span>{{end}}</td><td>{{if .Enabled}}active{{else}}disabled{{end}}</td></tr>{{else}}<tr><td colspan="4">No tunnels yet.</td></tr>{{end}}</tbody></table>{{template "foot" .}}{{end}}
{{define "upgrade"}}{{template "head" .}}<p><strong>Repository:</strong> {{if .Upgrade.Repository}}{{.Upgrade.Repository}}{{else}}not configured{{end}}<br><strong>Remote:</strong> {{.Upgrade.Remote}}<br><strong>Branch:</strong> {{.Upgrade.Branch}}<br><strong>Current revision:</strong> {{.Upgrade.Revision}}<br><strong>Last upgrade:</strong> {{.Upgrade.State}}{{if .Upgrade.Detail}} — {{.Upgrade.Detail}}{{end}}</p>{{if .Upgrade.Available}}<form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><p>The upgrade service will require a clean checkout, fetch and fast-forward the current branch from <code>origin</code>, run all tests, build and atomically install the binary, then restart the application.</p><button>Pull, test, and deploy latest</button></form>{{else}}<p class="error">Self-upgrade is unavailable. Configure the deployment checkout and systemd upgrade unit.</p>{{end}}{{template "foot" .}}{{end}}
{{define "settings"}}{{template "head" .}}<p class="muted">These preferences apply to the whole deployment. Provider connections, delegated prefixes, and WireGuard interfaces are configured per upstream on the <a href="/upstreams">Upstreams</a> page.</p><form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><div class="row"><div><h2>Clients</h2><label>Default DNS</label><input name="default_dns" value="{{.Settings.DefaultDNS}}"><label>Default IPv4 egress mode</label><select name="v4_mode"><option value="off" {{if and (not .Settings.V4NAT) (not .Settings.V4Warp)}}selected{{end}}>Disabled</option><option value="native" {{if .Settings.V4NAT}}selected{{end}}>Native upstream NAT</option><option value="warp" {{if .Settings.V4Warp}}selected{{end}}>Cloudflare WARP NAT</option></select><p class="muted">Native NAT masquerades a tunnel through the egress interface of its own upstream. Any upstream or tunnel may override this default.</p><label>Internal IPv4 pool</label><input name="v4_pool" value="{{.Settings.V4Pool}}"><p class="muted">One pool serves every upstream; addresses are unique across the deployment.</p></div><div><h2>Configured upstreams</h2>{{range .Upstreams}}<p>{{.Name}} — {{.V6CIDR}} via {{.EgressInterface}} ({{.EffectiveV4Mode}})</p>{{else}}<p class="error">No upstream is configured. <a href="/upstreams/new">Add one</a>.</p>{{end}}</div></div><p><button>Save and apply</button></p></form><h2>Cloudflare WARP account</h2>{{if .Warp.Exists}}<p>Account: {{if .Warp.AccountID}}{{.Warp.AccountID}}{{else}}registered{{end}}<br>Type: {{.Warp.AccountType}}<br>WARP IPv4: {{.Warp.IPv4Address}}<br>Endpoint: {{.Warp.Endpoint}}<br>Created: {{since .Warp.CreatedAt}}</p>{{else}}<p>No WARP account is registered. Create one before selecting Cloudflare WARP NAT.</p>{{end}}<p class="muted">Creating an account contacts Cloudflare's WARP registration API and records acceptance of its terms at the current time. One account serves every upstream that selects WARP egress.</p><form method="post" action="/warp"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="register"><button>{{if .Warp.Exists}}Recreate{{else}}Create{{end}} WARP account</button></form>{{if .Warp.Exists}}<form method="post" action="/warp"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="test"><button>Test WARP outbound IP</button></form>{{end}}{{if .Warp.LastTrace}}<h3>Last WARP trace</h3><p class="muted">Tested {{since .Warp.LastTestAt}}</p><pre>{{.Warp.LastTrace}}</pre>{{end}}<h2>Reset general settings</h2><p>Restores the default IPv4 mode, address pool, DNS, and inter-tunnel policy. Upstreams, their prefixes, interfaces, and keys are preserved, because those describe the deployment rather than a preference.</p><form method="post" action="/settings/reset"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>Reset general settings to defaults</button></form>{{template "foot" .}}{{end}}
{{define "new"}}{{template "head" .}}{{if not .Upstreams}}<p class="error">No upstream is configured. <a href="/upstreams/new">Add an upstream</a> before creating tunnels.</p>{{else}}<form method="get"><label>Upstream</label><select name="upstream_id" onchange="this.form.submit()">{{range .Upstreams}}<option value="{{.ID}}" {{if eq .ID $.Upstream.ID}}selected{{end}}>{{.Name}} — {{.V6CIDR}}</option>{{end}}</select><noscript><button>Select upstream</button></noscript></form><p class="muted">The tunnel is allocated from this upstream's prefix and egresses through {{.Upstream.EgressInterface}}. Changing the selection reloads the allocation sizes it offers.</p><form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="upstream_id" value="{{.Upstream.ID}}"><label>Label</label><input name="label" required><label>Allocation size</label><select name="prefix">{{range .Prefixes}}<option value="{{.}}" {{if eq . $.Upstream.DefaultPrefix}}selected{{end}}>/{{.}}</option>{{end}}</select><label><input type="checkbox" name="generate" checked> Generate client keypair (private key is stored and shown to the admin)</label><label>Client public key (uncheck generate to use)</label><input name="public_key"><label>DNS override</label><input name="dns" placeholder="{{.Settings.DefaultDNS}}"><label>IPv4 egress mode</label><select name="v4_mode"><option value="" selected>Use upstream default</option><option value="off">Disabled</option><option value="native">Native NAT through this upstream</option><option value="warp">Cloudflare WARP NAT</option></select><p class="muted">The upstream's setting remains the default unless this tunnel overrides it.</p><label>Routing groups</label>{{if .RoutingGroups}}<select name="routing_groups" multiple>{{range .RoutingGroups}}<option value="{{.Name}}">{{.Name}}</option>{{end}}</select><p class="muted">Select zero, one, or multiple groups. Use Ctrl/Cmd to select several.</p>{{else}}<p class="muted">No managed groups exist. <a href="/groups">Create a routing group</a> first, or leave this tunnel isolated.</p>{{end}}<label>Monthly upload + download quota (GiB)</label><input type="number" name="quota_gib" value="100" min="1" required><p class="muted">Usage resets on the first day of each calendar month (UTC).</p><p><button>Create and apply</button></p></form>{{end}}{{template "foot" .}}{{end}}
{{define "detail"}}{{template "head" .}}<p><strong>Upstream:</strong> {{if .Upstream.ID}}<a href="/upstreams/{{.Upstream.ID}}">{{.Upstream.Name}}</a> ({{.Upstream.V6CIDR}} via {{.Upstream.EgressInterface}}){{else}}<span class="bad">unassigned</span>{{end}}<br><strong>IPv6 allocation:</strong> {{.Tunnel.V6CIDR}}<br><strong>IPv4:</strong> {{if ne .EffectiveV4Mode "off"}}{{.Tunnel.V4Address}} ({{.EffectiveV4Mode}}){{else}}disabled{{end}}<br><strong>Routing groups:</strong> {{range .Tunnel.RoutingGroups}}<span class="tag">{{.}}</span>{{else}}none{{end}}<br><strong>Monthly traffic:</strong> {{bytes .Tunnel.QuotaUsedBytes}} of {{.Tunnel.QuotaGiB}} GiB ({{.Tunnel.QuotaPeriod}})<br><strong>State:</strong> {{if .Tunnel.QuotaDisabled}}quota reached · {{else if not .Tunnel.Enabled}}disabled · {{end}}{{.Tunnel.Status}}{{if .Tunnel.LastError}} — <span class="bad">{{.Tunnel.LastError}}</span>{{end}}</p><div class="row"><form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="v4-mode"><h2>IPv4 egress</h2><label>Mode for this tunnel</label><select name="v4_mode"><option value="" {{if eq .Tunnel.V4Mode ""}}selected{{end}}>Use upstream default</option><option value="off" {{if eq .Tunnel.V4Mode "off"}}selected{{end}}>Disabled</option><option value="native" {{if eq .Tunnel.V4Mode "native"}}selected{{end}}>Native NAT through this upstream</option><option value="warp" {{if eq .Tunnel.V4Mode "warp"}}selected{{end}}>Cloudflare WARP NAT</option></select><p class="muted">Effective mode: {{.EffectiveV4Mode}}.</p><p><button>Save and apply mode</button></p></form><form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="routing-groups"><h2>Routing groups</h2>{{if .RoutingGroups}}<label>Managed groups</label><select name="routing_groups" multiple>{{range .RoutingGroups}}<option value="{{.Name}}" {{if $.Tunnel.HasRoutingGroup .Name}}selected{{end}}>{{.Name}}</option>{{end}}</select><p class="muted">Select zero, one, or multiple groups. Use Ctrl/Cmd to select several.</p><p><button>Save routing groups</button></p>{{else}}<p class="muted">No managed groups exist. <a href="/groups">Create one</a> to enable grouped routing.</p>{{end}}</form><form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="quota"><h2>Monthly quota</h2><label>Combined upload + download quota (GiB)</label><input type="number" name="quota_gib" value="{{.Tunnel.QuotaGiB}}" min="1" required><p class="muted">Resets automatically each calendar month (UTC).</p><p><button>Save quota</button></p></form></div><h2>Client configuration</h2><pre>{{.Config}}</pre>{{if .Tunnel.PrivateKey}}<h3>Scan configuration</h3><p><img src="/tunnels/{{.Tunnel.ID}}/qr.png" width="320" height="320" alt="QR code containing the WireGuard configuration"></p><p class="muted">The QR code contains the private key and full configuration. Treat it as sensitive.</p>{{else}}<p class="muted">QR code unavailable because the client private key remains client-side.</p>{{end}}<form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="toggle"><button>{{if .Tunnel.Enabled}}Disable{{else}}Enable{{end}} tunnel</button></form><h2>Delete</h2><form method="post" class="danger"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="delete"><p>Deletion immediately removes the peer and route and frees the allocation.</p><button>Delete tunnel</button></form>{{template "foot" .}}{{end}}`
