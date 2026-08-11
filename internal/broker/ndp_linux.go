//go:build linux

package broker

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ndpResponder answers Neighbor Discovery solicitations for delegated prefixes
// on an on-link upstream interface, replacing the per-address
// `ip -6 neigh add proxy` workflow that cannot cover a whole prefix.
//
// An upstream router solicits a delegated address at that address's
// solicited-node multicast group. Those groups depend on the addresses
// downstream clients autoconfigure, so they cannot be predicted and joined in
// advance. The responder therefore reads frames from AF_PACKET in
// all-multicast mode, which sees the solicitations regardless of group
// membership, and writes advertisements back the same way. A kernel BPF filter
// narrows the socket to neighbor solicitations so the process is not woken by
// other traffic.
type ndpResponder struct {
	logger *log.Logger

	// current is read by the packet loop on every frame. It is deliberately
	// atomic rather than mutex-guarded: Configure and Close hold mu while
	// waiting for that loop to finish, so a loop that took mu would deadlock.
	current atomic.Pointer[ndpProxySet]

	mu           sync.Mutex
	upstreamName string
	index        int
	hardware     net.HardwareAddr
	socket       int
	stopped      chan struct{}
	finished     chan struct{}
}

func newNDPResponder(logger *log.Logger) *ndpResponder {
	return &ndpResponder{socket: -1, logger: logger}
}

// Configure brings the responder in line with set, starting, updating, or
// stopping the listener. It is safe to call on every reconciliation.
func (r *ndpResponder) Configure(upstreamInterface string, set ndpProxySet) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if set.empty() || upstreamInterface == "" {
		r.stopLocked()
		return nil
	}
	if r.socket >= 0 && r.upstreamName == upstreamInterface {
		// The read loop consults the address set per packet, so a membership
		// change needs no socket churn.
		r.current.Store(&set)
		return nil
	}
	r.stopLocked()
	link, err := netlink.LinkByName(upstreamInterface)
	if err != nil {
		return fmt.Errorf("neighbor discovery proxy: upstream interface %s: %w", upstreamInterface, err)
	}
	hardware := link.Attrs().HardwareAddr
	if len(hardware) != ethernetAddressLength {
		return fmt.Errorf("neighbor discovery proxy: %s has no Ethernet address, so an on-link upstream cannot be proxied", upstreamInterface)
	}
	socket, err := openNDPSocket(link.Attrs().Index)
	if err != nil {
		return fmt.Errorf("neighbor discovery proxy: %w", err)
	}
	r.current.Store(&set)
	r.upstreamName, r.index, r.hardware, r.socket = upstreamInterface, link.Attrs().Index, hardware, socket
	r.stopped, r.finished = make(chan struct{}), make(chan struct{})
	go r.serve(socket, hardware, r.index, r.stopped, r.finished)
	return nil
}

// Close stops the responder and releases its socket.
func (r *ndpResponder) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopLocked()
}

func (r *ndpResponder) stopLocked() {
	if r.socket < 0 {
		return
	}
	close(r.stopped)
	// The read loop must finish before the descriptor is closed, so that a
	// concurrent receive cannot land on a reused descriptor number. It never
	// takes r.mu, so waiting here while holding it is safe.
	<-r.finished
	_ = unix.Close(r.socket)
	r.socket, r.stopped, r.finished = -1, nil, nil
	r.upstreamName, r.hardware, r.index = "", nil, 0
	r.current.Store(&ndpProxySet{})
}

// state reports the current listener interface and address set for drift checks.
func (r *ndpResponder) state() (string, ndpProxySet, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	set := ndpProxySet{}
	if current := r.current.Load(); current != nil {
		set = *current
	}
	return r.upstreamName, set, r.socket >= 0
}

// openNDPSocket returns a packet socket bound to one interface, filtered to
// neighbor solicitations and placed in all-multicast mode.
func openNDPSocket(index int) (int, error) {
	socket, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_IPV6)))
	if err != nil {
		return -1, fmt.Errorf("open packet socket: %w", err)
	}
	// Every failure past this point must release the descriptor.
	fail := func(err error) (int, error) {
		_ = unix.Close(socket)
		return -1, err
	}
	filter := neighborSolicitationFilter()
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if err = unix.SetsockoptSockFprog(socket, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &program); err != nil {
		return fail(fmt.Errorf("attach neighbor solicitation filter: %w", err))
	}
	if err = unix.Bind(socket, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_IPV6), Ifindex: index}); err != nil {
		return fail(fmt.Errorf("bind packet socket: %w", err))
	}
	// Advertisements this process sends would otherwise be read back.
	if err = unix.SetsockoptInt(socket, unix.SOL_PACKET, unix.PACKET_IGNORE_OUTGOING, 1); err != nil {
		return fail(fmt.Errorf("ignore outgoing frames: %w", err))
	}
	// Solicitations arrive on the solicited-node multicast address of each
	// delegated address, which this host never joins. All-multicast delivers
	// them anyway.
	membership := unix.PacketMreq{Ifindex: int32(index), Type: unix.PACKET_MR_ALLMULTI}
	if err = unix.SetsockoptPacketMreq(socket, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &membership); err != nil {
		return fail(fmt.Errorf("enable all-multicast reception: %w", err))
	}
	// A receive timeout lets the read loop notice a stop request promptly
	// without a second wakeup channel.
	timeout := unix.Timeval{Sec: 1}
	if err = unix.SetsockoptTimeval(socket, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		return fail(fmt.Errorf("set receive timeout: %w", err))
	}
	return socket, nil
}

func htons(value uint16) uint16 { return value<<8 | value>>8 }

// neighborSolicitationFilter builds a BPF program accepting only IPv6 frames
// whose next header is ICMPv6 and whose ICMPv6 type is a neighbor
// solicitation. Offsets are counted from the start of the Ethernet frame.
func neighborSolicitationFilter() []unix.SockFilter {
	const (
		ethertypeOffset  = 12
		nextHeaderOffset = ethernetHeaderLength + 6
		icmpTypeOffset   = ethernetHeaderLength + ipv6HeaderLength
	)
	return []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_ABS, K: ethertypeOffset},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 5, K: unix.ETH_P_IPV6},
		{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, K: nextHeaderOffset},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 3, K: protocolICMPv6},
		{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, K: icmpTypeOffset},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 1, K: icmpv6NeighborSolicitation},
		{Code: unix.BPF_RET | unix.BPF_K, K: 0xffffffff},
		{Code: unix.BPF_RET | unix.BPF_K, K: 0},
	}
}

func (r *ndpResponder) serve(socket int, hardware net.HardwareAddr, index int, stopped <-chan struct{}, finished chan<- struct{}) {
	defer close(finished)
	frame := make([]byte, 1514)
	for {
		select {
		case <-stopped:
			return
		default:
		}
		n, _, err := unix.Recvfrom(socket, frame, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
				continue
			}
			select {
			case <-stopped:
				return
			default:
			}
			r.logger.Printf("neighbor discovery proxy read: %v", err)
			// Back off instead of spinning on a persistent socket error.
			time.Sleep(time.Second)
			continue
		}
		if reply, destination, ok := r.answer(frame[:n], hardware); ok {
			address := &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_IPV6), Ifindex: index, Halen: ethernetAddressLength}
			copy(address.Addr[:], destination)
			if err = unix.Sendto(socket, reply, 0, address); err != nil {
				r.logger.Printf("neighbor discovery proxy write: %v", err)
			}
		}
	}
}

// answer decides whether a received frame deserves a proxy advertisement and
// renders the reply frame together with the Ethernet address to send it to.
func (r *ndpResponder) answer(frame []byte, hardware net.HardwareAddr) ([]byte, net.HardwareAddr, bool) {
	if len(frame) < ethernetHeaderLength {
		return nil, nil, false
	}
	sender := net.HardwareAddr(frame[6:12])
	if hardware.String() == sender.String() {
		// A frame this host sent; never answer it.
		return nil, nil, false
	}
	set := r.current.Load()
	if set == nil {
		return nil, nil, false
	}
	solicitation, err := parseNeighborSolicitation(frame[ethernetHeaderLength:])
	if err != nil || !set.shouldAnswer(solicitation.Target) {
		return nil, nil, false
	}
	reply, err := buildNeighborAdvertisementFrame(solicitation, hardware, sender)
	if err != nil {
		r.logger.Printf("neighbor discovery proxy build: %v", err)
		return nil, nil, false
	}
	return reply, sender, true
}

// buildNeighborAdvertisementFrame renders the full Ethernet frame carrying a
// solicited proxy advertisement back to the solicitor.
func buildNeighborAdvertisementFrame(solicitation neighborSolicitation, hardware, destination net.HardwareAddr) ([]byte, error) {
	if len(hardware) != ethernetAddressLength || len(destination) != ethernetAddressLength {
		return nil, errors.New("neighbor discovery proxying requires Ethernet addresses")
	}
	packet, err := buildNeighborAdvertisement(solicitation.Target, solicitation.Source, hardware)
	if err != nil {
		return nil, err
	}
	frame := make([]byte, ethernetHeaderLength+len(packet))
	copy(frame[0:6], destination)
	copy(frame[6:12], hardware)
	binary.BigEndian.PutUint16(frame[12:14], unix.ETH_P_IPV6)
	copy(frame[ethernetHeaderLength:], packet)
	return frame, nil
}

// ndpProxyManager keeps one responder per egress interface, because several
// unrelated upstreams may each place their prefix on-link on a different
// provider connection. Interfaces that no longer proxy anything are stopped.
type ndpProxyManager struct {
	logger *log.Logger

	mu         sync.Mutex
	responders map[string]*ndpResponder
}

func newNDPProxyManager(logger *log.Logger) *ndpProxyManager {
	return &ndpProxyManager{logger: logger, responders: map[string]*ndpResponder{}}
}

// Configure reconciles the running listeners with the desired per-interface
// address sets. It is safe to call on every reconciliation.
func (m *ndpProxyManager) Configure(sets map[string]ndpProxySet) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var firstErr error
	for name, responder := range m.responders {
		if set, ok := sets[name]; !ok || set.empty() {
			responder.Close()
			delete(m.responders, name)
		}
	}
	for name, set := range sets {
		if set.empty() || name == "" {
			continue
		}
		responder, ok := m.responders[name]
		if !ok {
			responder = newNDPResponder(m.logger)
			m.responders[name] = responder
		}
		if err := responder.Configure(name, set); err != nil {
			// One failing interface must not stop the others from being
			// configured, so the first error is reported after the whole sweep.
			if firstErr == nil {
				firstErr = err
			}
			responder.Close()
			delete(m.responders, name)
		}
	}
	return firstErr
}

// Close stops every listener.
func (m *ndpProxyManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, responder := range m.responders {
		responder.Close()
		delete(m.responders, name)
	}
}

// states reports the address set running on each interface, for drift checks.
func (m *ndpProxyManager) states() map[string]ndpProxySet {
	m.mu.Lock()
	defer m.mu.Unlock()
	running := make(map[string]ndpProxySet, len(m.responders))
	for name, responder := range m.responders {
		if _, set, up := responder.state(); up {
			running[name] = set
		}
	}
	return running
}

// upstreamLocalAddresses reports the IPv6 addresses configured on an egress
// interface. They must never be proxied, because the kernel already answers for
// them; in on-link mode the provider-assigned host address sits inside the
// delegated prefix, so this is what keeps the host itself reachable.
func upstreamLocalAddresses(upstreamInterface string) ([]netip.Addr, error) {
	link, err := netlink.LinkByName(upstreamInterface)
	if err != nil {
		return nil, err
	}
	addresses, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return nil, err
	}
	local := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		if parsed, ok := netip.AddrFromSlice(address.IP); ok {
			local = append(local, parsed.Unmap())
		}
	}
	return local, nil
}
