package broker

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
)

var ErrPoolExhausted = errors.New("address pool has no suitably sized free block")

// Allocate returns the lowest available CIDR of prefix bits. Allocations need not
// have been made in buddy order; the free tree is rebuilt from durable allocations.
func Allocate(pool netip.Prefix, used []netip.Prefix, bits int) (netip.Prefix, error) {
	pool = pool.Masked()
	if !pool.Addr().Is6() {
		return netip.Prefix{}, errors.New("pool must be IPv6")
	}
	if bits < pool.Bits() || bits > 128 {
		return netip.Prefix{}, fmt.Errorf("prefix /%d outside pool /%d", bits, pool.Bits())
	}
	clean := make([]netip.Prefix, 0, len(used))
	for _, p := range used {
		p = p.Masked()
		if !p.Addr().Is6() || p.Bits() < pool.Bits() || !pool.Contains(p.Addr()) {
			return netip.Prefix{}, fmt.Errorf("allocation %s is outside %s", p, pool)
		}
		clean = append(clean, p)
	}
	sort.Slice(clean, func(i, j int) bool { return clean[i].Addr().Less(clean[j].Addr()) })
	var search func(netip.Prefix) (netip.Prefix, bool)
	search = func(candidate netip.Prefix) (netip.Prefix, bool) {
		hasDescendant := false
		for _, p := range clean {
			if overlaps(candidate, p) {
				if p == candidate || p.Bits() <= candidate.Bits() {
					return netip.Prefix{}, false
				}
				hasDescendant = true
			}
		}
		if candidate.Bits() == bits {
			if hasDescendant {
				return netip.Prefix{}, false
			}
			return candidate, true
		}
		left, right := split(candidate)
		if got, ok := search(left); ok {
			return got, true
		}
		return search(right)
	}
	if got, ok := search(pool); ok {
		return got, nil
	}
	return netip.Prefix{}, ErrPoolExhausted
}

func overlaps(a, b netip.Prefix) bool { return a.Contains(b.Addr()) || b.Contains(a.Addr()) }

func split(p netip.Prefix) (netip.Prefix, netip.Prefix) {
	n := p.Bits() + 1
	left := netip.PrefixFrom(p.Addr(), n).Masked()
	b := p.Addr().As16()
	bit := n - 1
	b[bit/8] |= 1 << (7 - uint(bit%8))
	return left, netip.PrefixFrom(netip.AddrFrom16(b), n).Masked()
}

func PoolStats(pool netip.Prefix, used []netip.Prefix, maxBits int) (allocated uint64, largest int) {
	largest = -1
	for bits := pool.Bits(); bits <= maxBits; bits++ {
		if _, err := Allocate(pool, used, bits); err == nil {
			largest = bits
			break
		}
	}
	// Report /64-equivalent units, saturating for extremely large pools.
	for _, p := range used {
		if p.Bits() <= 64 {
			shift := 64 - p.Bits()
			if shift >= 64 || ^uint64(0)-allocated < uint64(1)<<shift {
				return ^uint64(0), largest
			}
			allocated += uint64(1) << shift
		}
	}
	return allocated, largest
}
