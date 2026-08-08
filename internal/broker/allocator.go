package broker

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
)

var ErrPoolExhausted = errors.New("address pool has no suitably sized free block")

type prefixIndexChooser func(*big.Int) (*big.Int, error)

// Allocate returns a cryptographically random, correctly aligned free CIDR of
// prefix bits. It chooses uniformly across every available subprefix without
// enumerating the address space, so large IPv6 pools and allocations up to /128
// are supported without biased collision retries.
func Allocate(pool netip.Prefix, used []netip.Prefix, bits int) (netip.Prefix, error) {
	return allocateWithChooser(pool, used, bits, func(available *big.Int) (*big.Int, error) {
		return rand.Int(rand.Reader, available)
	})
}

func allocateWithChooser(pool netip.Prefix, used []netip.Prefix, bits int, choose prefixIndexChooser) (netip.Prefix, error) {
	pool = pool.Masked()
	if !pool.Addr().Is6() {
		return netip.Prefix{}, errors.New("pool must be IPv6")
	}
	if bits < pool.Bits() || bits > 128 {
		return netip.Prefix{}, fmt.Errorf("prefix /%d outside pool /%d", bits, pool.Bits())
	}
	clean := make([]netip.Prefix, 0, len(used))
	for _, prefix := range used {
		prefix = prefix.Masked()
		if !prefix.Addr().Is6() || prefix.Bits() < pool.Bits() || !pool.Contains(prefix.Addr()) {
			return netip.Prefix{}, fmt.Errorf("allocation %s is outside %s", prefix, pool)
		}
		clean = append(clean, prefix)
	}

	available := freePrefixCount(pool, clean, bits)
	if available.Sign() == 0 {
		return netip.Prefix{}, ErrPoolExhausted
	}
	index, err := choose(new(big.Int).Set(available))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("random prefix selection: %w", err)
	}
	if index == nil || index.Sign() < 0 || index.Cmp(available) >= 0 {
		return netip.Prefix{}, errors.New("random prefix selection returned an out-of-range index")
	}
	return freePrefixAt(pool, clean, bits, new(big.Int).Set(index)), nil
}

func freePrefixCount(candidate netip.Prefix, used []netip.Prefix, targetBits int) *big.Int {
	descendants, blocked := overlappingDescendants(candidate, used)
	if blocked || candidate.Bits() == targetBits && len(descendants) > 0 {
		return new(big.Int)
	}
	if len(descendants) == 0 {
		return new(big.Int).Lsh(big.NewInt(1), uint(targetBits-candidate.Bits()))
	}
	left, right := split(candidate)
	return new(big.Int).Add(freePrefixCount(left, descendants, targetBits), freePrefixCount(right, descendants, targetBits))
}

func freePrefixAt(candidate netip.Prefix, used []netip.Prefix, targetBits int, index *big.Int) netip.Prefix {
	descendants, _ := overlappingDescendants(candidate, used)
	if len(descendants) == 0 {
		return prefixAtIndex(candidate, targetBits, index)
	}
	left, right := split(candidate)
	leftCount := freePrefixCount(left, descendants, targetBits)
	if index.Cmp(leftCount) < 0 {
		return freePrefixAt(left, descendants, targetBits, index)
	}
	return freePrefixAt(right, descendants, targetBits, new(big.Int).Sub(index, leftCount))
}

func overlappingDescendants(candidate netip.Prefix, used []netip.Prefix) ([]netip.Prefix, bool) {
	descendants := make([]netip.Prefix, 0, len(used))
	for _, prefix := range used {
		if !overlaps(candidate, prefix) {
			continue
		}
		if prefix.Bits() <= candidate.Bits() {
			return nil, true
		}
		descendants = append(descendants, prefix)
	}
	return descendants, false
}

func prefixAtIndex(parent netip.Prefix, targetBits int, index *big.Int) netip.Prefix {
	base := new(big.Int).SetBytes(parent.Masked().Addr().AsSlice())
	offset := new(big.Int).Lsh(new(big.Int).Set(index), uint(128-targetBits))
	addressBytes := make([]byte, 16)
	new(big.Int).Add(base, offset).FillBytes(addressBytes)
	address, _ := netip.AddrFromSlice(addressBytes)
	return netip.PrefixFrom(address, targetBits).Masked()
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
		if freePrefixCount(pool.Masked(), used, bits).Sign() > 0 {
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
