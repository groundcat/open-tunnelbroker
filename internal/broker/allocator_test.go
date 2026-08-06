package broker

import (
	"errors"
	"net/netip"
	"testing"
)

func p(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func TestAllocatePacksLowestFreeSpace(t *testing.T) {
	pool := p("2001:db8::/48")
	used := []netip.Prefix{p("2001:db8::/56"), p("2001:db8:0:100::/56")}
	got, err := Allocate(pool, used, 56)
	if err != nil || got != p("2001:db8:0:200::/56") {
		t.Fatalf("got %s, %v", got, err)
	}
}

func TestAllocateReusesAndCoalesces(t *testing.T) {
	pool := p("2001:db8::/62")
	used := []netip.Prefix{p("2001:db8:0:1::/64"), p("2001:db8:0:2::/64")}
	got, err := Allocate(pool, used, 64)
	if err != nil || got != p("2001:db8::/64") {
		t.Fatalf("got %s, %v", got, err)
	}
	got, err = Allocate(pool, nil, 63)
	if err != nil || got != p("2001:db8::/63") {
		t.Fatalf("coalesced got %s, %v", got, err)
	}
}

func TestAllocateDoesNotContainReservedSmallerBlock(t *testing.T) {
	pool := p("2001:db8:1200::/48")
	used := []netip.Prefix{p("2001:db8:1200::/64")}
	got, err := Allocate(pool, used, 56)
	if err != nil || got != p("2001:db8:1200:100::/56") {
		t.Fatalf("got %s, %v", got, err)
	}
}

func TestAllocateExhaustionAndValidation(t *testing.T) {
	pool := p("2001:db8::/63")
	_, err := Allocate(pool, []netip.Prefix{p("2001:db8::/64"), p("2001:db8:0:1::/64")}, 64)
	if !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("expected exhaustion, got %v", err)
	}
	if _, err = Allocate(pool, nil, 62); err == nil {
		t.Fatal("expected size validation")
	}
	if _, err = Allocate(pool, []netip.Prefix{p("2001:db9::/64")}, 64); err == nil {
		t.Fatal("expected containment validation")
	}
}
