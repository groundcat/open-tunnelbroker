package broker

import (
	"errors"
	"math/big"
	"net/netip"
	"testing"
)

func p(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func chooseIndex(value int64) prefixIndexChooser {
	return func(*big.Int) (*big.Int, error) { return big.NewInt(value), nil }
}

func TestAllocateSelectsAcrossFreePrefixSpace(t *testing.T) {
	pool := p("2001:db8::/48")
	used := []netip.Prefix{p("2001:db8::/56"), p("2001:db8:0:100::/56")}
	lowestFree, err := allocateWithChooser(pool, used, 56, chooseIndex(0))
	if err != nil || lowestFree != p("2001:db8:0:200::/56") {
		t.Fatalf("lowest free prefix: got %s, %v", lowestFree, err)
	}
	highestFree, err := allocateWithChooser(pool, used, 56, func(available *big.Int) (*big.Int, error) {
		return new(big.Int).Sub(available, big.NewInt(1)), nil
	})
	if err != nil || highestFree != p("2001:db8:0:ff00::/56") {
		t.Fatalf("highest free prefix: got %s, %v", highestFree, err)
	}
}

func TestAllocateSupportsEveryIPv6PrefixSize(t *testing.T) {
	pool := p("2001:db8:1200::/48")
	for _, bits := range []int{48, 49, 56, 64, 80, 96, 127, 128} {
		got, err := allocateWithChooser(pool, nil, bits, func(available *big.Int) (*big.Int, error) {
			return new(big.Int).Rsh(available, 1), nil
		})
		if err != nil || got.Bits() != bits || got != got.Masked() || !pool.Contains(got.Addr()) {
			t.Errorf("/%d allocation is invalid: %s, %v", bits, got, err)
		}
	}
}

func TestAllocateNeverOverlapsMixedExistingAllocations(t *testing.T) {
	pool := p("2001:db8:1200::/48")
	used := []netip.Prefix{
		p("2001:db8:1200::/64"),
		p("2001:db8:1200:100::/56"),
		p("2001:db8:1200:8000::/52"),
	}
	for rank := int64(0); rank < 32; rank++ {
		got, err := allocateWithChooser(pool, used, 64, chooseIndex(rank))
		if err != nil {
			t.Fatal(err)
		}
		for _, existing := range used {
			if overlaps(got, existing) {
				t.Fatalf("allocation %s overlaps %s", got, existing)
			}
		}
	}
}

func TestAllocateReusesAllFreeSpaceWithoutFalseExhaustion(t *testing.T) {
	pool := p("2001:db8::/62")
	used := []netip.Prefix{p("2001:db8:0:1::/64"), p("2001:db8:0:2::/64")}
	first, err := allocateWithChooser(pool, used, 64, chooseIndex(0))
	if err != nil || first != p("2001:db8::/64") {
		t.Fatalf("first free prefix: got %s, %v", first, err)
	}
	last, err := allocateWithChooser(pool, used, 64, chooseIndex(1))
	if err != nil || last != p("2001:db8:0:3::/64") {
		t.Fatalf("last free prefix: got %s, %v", last, err)
	}
}

func TestRandomAllocateFillsPoolWithoutCollision(t *testing.T) {
	pool := p("2001:db8:abcd:1200::/56")
	used := make([]netip.Prefix, 0, 256)
	seen := make(map[netip.Prefix]bool, 256)
	for range 256 {
		allocation, err := Allocate(pool, used, 64)
		if err != nil {
			t.Fatalf("allocation %d failed before exhaustion: %v", len(used), err)
		}
		if seen[allocation] || allocation.Bits() != 64 || !pool.Contains(allocation.Addr()) {
			t.Fatalf("invalid or duplicate allocation: %s", allocation)
		}
		seen[allocation] = true
		used = append(used, allocation)
	}
	if _, err := Allocate(pool, used, 64); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("expected exact exhaustion after 256 unique allocations, got %v", err)
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
	if _, err = allocateWithChooser(pool, nil, 64, chooseIndex(2)); err == nil {
		t.Fatal("expected random index validation")
	}
}
