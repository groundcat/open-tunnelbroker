package broker

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// post drives one authenticated form submission through a handler, standing in
// for the session middleware that normally supplies the user and CSRF token.
func post(t *testing.T, handler http.HandlerFunc, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	form.Set("csrf", "token")
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("X-OTB-User", "admin")
	request.Header.Set("X-OTB-CSRF", "token")
	recorder := httptest.NewRecorder()
	handler(recorder, request)
	return recorder
}

func get(t *testing.T, handler http.HandlerFunc, path string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("X-OTB-User", "admin")
	request.Header.Set("X-OTB-CSRF", "token")
	recorder := httptest.NewRecorder()
	handler(recorder, request)
	return recorder
}

// TestUpstreamPagesManageProviderConnections walks the whole admin flow a new
// deployment follows: add a second provider, see both listed, then edit one.
func TestUpstreamPagesManageProviderConnections(t *testing.T) {
	app, _ := testApp(t)

	created := post(t, app.newUpstream, "/upstreams/new", url.Values{
		"name": {"secondary"}, "v6_cidr": {"2001:db8:7700::/48"}, "mode": {UpstreamRouted},
		"egress_interface": {"ppp0"}, "interface_name": {"wg-secondary"},
		"endpoint_host": {"broker.example.test"}, "endpoint_port": {"51821"},
		"server_address": {"2001:db8:7700::1/64"}, "mtu": {"1420"}, "keepalive": {"25"},
		"min_prefix": {"48"}, "max_prefix": {"64"}, "default_prefix": {"56"},
	})
	if created.Code != http.StatusSeeOther {
		t.Fatalf("creating an upstream returned %d: %s", created.Code, created.Body.String())
	}
	upstreams, err := app.store.Upstreams()
	if err != nil || len(upstreams) != 2 {
		t.Fatalf("second upstream was not persisted: %+v, %v", upstreams, err)
	}

	listing := get(t, app.upstreams, "/upstreams").Body.String()
	for _, expected := range []string{"primary", "secondary", "2001:db8:7700::/48", "wg-secondary", "ppp0"} {
		if !strings.Contains(listing, expected) {
			t.Fatalf("upstream listing is missing %q:\n%s", expected, listing)
		}
	}

	// Both connections must appear as allocation targets on the tunnel form.
	form := get(t, app.newTunnel, "/tunnels/new").Body.String()
	if !containsAll(form, `name="upstream_id"`, "primary", "secondary") {
		t.Fatalf("tunnel form does not offer an upstream choice:\n%s", form)
	}

	// An invalid edit must be reported on the form rather than silently applied.
	var secondary Upstream
	for _, upstream := range upstreams {
		if upstream.Name == "secondary" {
			secondary = upstream
		}
	}
	path := "/upstreams/" + strconv.FormatInt(secondary.ID, 10)
	rejected := post(t, app.upstream, path, url.Values{
		"name": {"secondary"}, "v6_cidr": {"not-a-prefix"}, "mode": {UpstreamRouted},
		"egress_interface": {"ppp0"}, "interface_name": {"wg-secondary"},
		"endpoint_host": {"broker.example.test"}, "endpoint_port": {"51821"},
		"mtu": {"1420"}, "keepalive": {"25"}, "min_prefix": {"48"}, "max_prefix": {"64"}, "default_prefix": {"56"},
	})
	if rejected.Code != http.StatusOK || !strings.Contains(rejected.Body.String(), "must be an IPv6 CIDR") {
		t.Fatalf("an invalid upstream edit was not reported: %d %s", rejected.Code, rejected.Body.String())
	}
	if reloaded, _ := app.store.Upstream(secondary.ID); reloaded.V6CIDR != secondary.V6CIDR {
		t.Fatalf("a rejected edit still changed the upstream: %+v", reloaded)
	}

	saved := post(t, app.upstream, path, url.Values{
		"name": {"renamed"}, "v6_cidr": {secondary.V6CIDR}, "mode": {UpstreamRouted},
		"egress_interface": {"ppp0"}, "interface_name": {"wg-secondary"},
		"endpoint_host": {"broker.example.test"}, "endpoint_port": {"51821"},
		"server_address": {secondary.ServerAddress}, "mtu": {"1420"}, "keepalive": {"25"},
		"min_prefix": {"48"}, "max_prefix": {"64"}, "default_prefix": {"56"}, "v4_mode": {V4ModeOff},
	})
	if saved.Code != http.StatusSeeOther {
		t.Fatalf("a valid upstream edit returned %d: %s", saved.Code, saved.Body.String())
	}
	if reloaded, _ := app.store.Upstream(secondary.ID); reloaded.Name != "renamed" || reloaded.V4Mode != V4ModeOff {
		t.Fatalf("upstream edit was not applied: %+v", reloaded)
	}
}

// The dashboard reports free space per provider, because one deployment-wide
// total would be meaningless across unrelated prefixes.
func TestDashboardReportsPoolStatisticsPerUpstream(t *testing.T) {
	app, _ := testApp(t)
	if _, err := app.CreateTunnel(CreateTunnelInput{Label: "first", Prefix: 56, GenerateKeys: true}, "admin"); err != nil {
		t.Fatal(err)
	}
	body := get(t, app.dashboard, "/").Body.String()
	if !containsAll(body, "primary", "2001:db8:1200::/48", "wg-test via eth0", "first") {
		t.Fatalf("dashboard does not report the upstream and its tunnels:\n%s", body)
	}
	views, err := app.upstreamViews(mustSettings(t, app))
	if err != nil || len(views) != 1 {
		t.Fatalf("unexpected upstream views: %+v, %v", views, err)
	}
	// One /56 covers 256 /64 units and the server's reservation holds one more.
	// The largest remaining block depends on where the random allocation landed,
	// but a /48 minus one /56 always leaves at least a /50 free.
	if views[0].Allocated != 257 || views[0].Largest < 48 || views[0].Largest > 50 {
		t.Fatalf("per-upstream pool statistics are wrong: %+v", views[0])
	}
}

// Every tunnel is rendered with the connection it belongs to, so an admin can
// tell which provider carries it.
func TestTunnelDetailNamesItsUpstream(t *testing.T) {
	app, _ := testApp(t)
	tunnel, err := app.CreateTunnel(CreateTunnelInput{Label: "shown", GenerateKeys: true}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	body := get(t, app.tunnel, "/tunnels/"+strconv.FormatInt(tunnel.ID, 10)).Body.String()
	if !containsAll(body, "Upstream:", "primary", "eth0", tunnel.V6CIDR, "Client configuration") {
		t.Fatalf("tunnel detail does not name its upstream:\n%s", body)
	}
}
