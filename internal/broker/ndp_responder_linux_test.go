//go:build linux

package broker

import (
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"testing"
)

// TestResponderAnswersConcurrentlyWithMembershipChanges exercises the packet
// path against concurrent reconfiguration. It needs no privileges because
// answer() is the whole decision, and it would deadlock or race if the address
// set were guarded by the same mutex Configure holds while stopping the loop.
func TestResponderAnswersConcurrentlyWithMembershipChanges(t *testing.T) {
	responder := newNDPResponder(log.New(io.Discard, "", 0))
	hardware, err := net.ParseMAC("52:54:00:aa:bb:cc")
	if err != nil {
		t.Fatal(err)
	}
	router := netip.MustParseAddr("2001:db8:1200:416::1")
	client := netip.MustParseAddr("2001:db8:1200:416:1::5")
	upstream := Upstream{ID: 1, V6CIDR: "2001:db8:1200:416::/64", Mode: UpstreamOnLink}
	populated := ndpProxySetFor(upstream, []Tunnel{{ID: 1, V6CIDR: "2001:db8:1200:416::/64", Enabled: true}}, nil)
	responder.current.Store(&populated)

	frame := solicitationFrame(t, router, client, "52:54:00:11:22:33")
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			set := populated
			if i%2 == 0 {
				set = ndpProxySet{}
			}
			responder.current.Store(&set)
		}
	}()
	go func() {
		defer wg.Done()
		// The answers themselves are timing-dependent; what matters is that
		// concurrent decisions neither race nor block.
		for i := 0; i < 200; i++ {
			responder.answer(frame, hardware)
		}
	}()
	wg.Wait()

	// With the populated set stored last, the decision must be a clean yes.
	responder.current.Store(&populated)
	reply, destination, ok := responder.answer(frame, hardware)
	if !ok {
		t.Fatal("a solicitation for a delegated address was not answered")
	}
	if destination.String() != "52:54:00:11:22:33" {
		t.Fatalf("reply is addressed to %s, not the solicitor", destination)
	}
	// The reply must be a well-formed Ethernet frame from this host.
	if got := net.HardwareAddr(reply[6:12]).String(); got != hardware.String() {
		t.Fatalf("reply frame source is %s, not the proxying host", got)
	}
	if net.HardwareAddr(reply[0:6]).String() != destination.String() {
		t.Fatal("reply frame destination does not match the solicitor")
	}
	if reply[12] != 0x86 || reply[13] != 0xdd {
		t.Fatalf("reply is not an IPv6 frame: %#x%x", reply[12], reply[13])
	}
	if reply[ethernetHeaderLength+ipv6HeaderLength] != icmpv6NeighborAdvertisement {
		t.Fatal("reply does not carry a neighbor advertisement")
	}

	// An emptied set must stop answering, which is how a disabled or deleted
	// tunnel stops attracting traffic.
	empty := ndpProxySet{}
	responder.current.Store(&empty)
	if _, _, ok = responder.answer(frame, hardware); ok {
		t.Fatal("an emptied proxy set still answered")
	}
	// Close on a responder that never opened a socket must be a safe no-op.
	responder.Close()
}

func TestResponderIgnoresItsOwnFrames(t *testing.T) {
	responder := newNDPResponder(log.New(io.Discard, "", 0))
	hardware, err := net.ParseMAC("52:54:00:aa:bb:cc")
	if err != nil {
		t.Fatal(err)
	}
	upstream := Upstream{ID: 1, V6CIDR: "2001:db8:1200:416::/64", Mode: UpstreamOnLink}
	set := ndpProxySetFor(upstream, []Tunnel{{ID: 1, V6CIDR: "2001:db8:1200:416::/64", Enabled: true}}, nil)
	responder.current.Store(&set)

	// A frame whose source is this host's own Ethernet address must never be
	// answered, or the proxy would reply to itself.
	own := solicitationFrame(t, netip.MustParseAddr("2001:db8:1200:416::1"), netip.MustParseAddr("2001:db8:1200:416:1::5"), hardware.String())
	if _, _, ok := responder.answer(own, hardware); ok {
		t.Fatal("the responder answered a frame it had sent")
	}
	// A runt frame must be rejected rather than panicking on a short slice.
	if _, _, ok := responder.answer([]byte{1, 2, 3}, hardware); ok {
		t.Fatal("a truncated frame was answered")
	}
}

// solicitationFrame wraps a neighbor solicitation in an Ethernet header, as it
// would arrive on the wire.
func solicitationFrame(t *testing.T, source, target netip.Addr, sender string) []byte {
	t.Helper()
	senderHardware, err := net.ParseMAC(sender)
	if err != nil {
		t.Fatal(err)
	}
	packet := buildSolicitation(source, target)
	frame := make([]byte, ethernetHeaderLength+len(packet))
	// Solicitations are sent to the target's solicited-node multicast MAC.
	copy(frame[0:6], []byte{0x33, 0x33, 0xff, 0x00, 0x00, 0x05})
	copy(frame[6:12], senderHardware)
	frame[12], frame[13] = 0x86, 0xdd
	copy(frame[ethernetHeaderLength:], packet)
	return frame
}
