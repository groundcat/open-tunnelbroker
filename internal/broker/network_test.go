//go:build linux

package broker

import (
	"net/netip"
	"testing"
)

func TestAddressIPNetPreservesHostBits(t *testing.T) {
	prefix := netip.MustParsePrefix("2001:db8::1/64")
	if got := addressIPNet(prefix).IP.String(); got != "2001:db8::1" {
		t.Fatalf("address host bits lost: got %s", got)
	}
	if got := prefixIPNet(prefix).IP.String(); got != "2001:db8::" {
		t.Fatalf("route prefix was not masked: got %s", got)
	}
}
