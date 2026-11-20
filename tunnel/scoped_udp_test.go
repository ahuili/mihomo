package tunnel

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

type scopedUDPTestConn struct {
	C.PacketConn
	closes int32
}

func (pc *scopedUDPTestConn) Close() error { atomic.AddInt32(&pc.closes, 1); return nil }

func TestScopedUDPRevocationOwnsLateAndPublishedSockets(t *testing.T) {
	for _, late := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		s := &scopedUDPSession{ctx: ctx, cancel: cancel, sender: newPacketSender()}
		pc := new(scopedUDPTestConn)
		if late {
			s.stop()
		}
		if s.publish(pc) == late {
			t.Fatalf("unexpected publication, late=%v", late)
		}
		s.stop()
		if got := atomic.LoadInt32(&pc.closes); got != 1 {
			t.Fatalf("close count %d, late=%v", got, late)
		}
	}
}

type scopedUDPTestPacket struct {
	C.PacketAdapter
	drops int32
}

func (p *scopedUDPTestPacket) Drop() { atomic.AddInt32(&p.drops, 1) }

func TestScopedUDPSenderConcurrentCloseReleasesEveryDatagram(t *testing.T) {
	s := newPacketSender()
	start := make(chan struct{})
	var wg sync.WaitGroup
	packets := make([]scopedUDPTestPacket, senderCapacity*2)
	for i := range packets {
		wg.Add(1)
		go func(p *scopedUDPTestPacket) {
			defer wg.Done()
			<-start
			s.Send(p)
		}(&packets[i])
	}
	close(start)
	s.Close()
	wg.Wait()
	for i := range packets {
		if got := atomic.LoadInt32(&packets[i].drops); got != 1 {
			t.Fatalf("packet %d released %d times", i, got)
		}
	}
}

type scopedUDPBlockedConn struct {
	scopedUDPTestConn
	writing chan struct{}
	closed  chan struct{}
	release chan struct{}
}

func (pc *scopedUDPBlockedConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	close(pc.writing)
	<-pc.closed
	<-pc.release
	return 0, net.ErrClosed
}
func (pc *scopedUDPBlockedConn) Close() error {
	close(pc.closed)
	return pc.scopedUDPTestConn.Close()
}

func (pc *scopedUDPBlockedConn) SetReadDeadline(time.Time) error { return nil }
func (pc *scopedUDPBlockedConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	<-pc.closed
	return nil, nil, nil, net.ErrClosed
}

type scopedUDPWritablePacket struct {
	scopedUDPTestPacket
	m C.Metadata
}

func (p *scopedUDPWritablePacket) Metadata() *C.Metadata { return &p.m }
func (p *scopedUDPWritablePacket) Data() []byte          { return []byte{1} }

func TestScopedUDPSealWaitsForActiveWrite(t *testing.T) {
	registry := loadScopeRegistry("")
	ctx, cancel := context.WithCancel(context.Background())
	p := new(scopedUDPWritablePacket)
	s := &scopedUDPSession{ctx: ctx, cancel: cancel, sender: newPacketSender()}
	pc := &scopedUDPBlockedConn{writing: make(chan struct{}), closed: make(chan struct{})}

	pc.release = make(chan struct{})
	p.m.DstIP = netip.MustParseAddr("192.0.2.10")
	p.m.DstPort = 42
	s.sender.AddMapping(&p.m, &p.m)
	f, _, _ := registry.Enter("/fixture/target", "", true, s.stop)
	go s.run(p, scopedUDPKey{path: "/fixture/target"}, f, func(context.Context, C.PacketAdapter, C.PacketSender, func(string) bool, *netip.AddrPort) (C.PacketConn, C.WriteBackProxy, error) {
		return pc, nil, nil
	})
	s.sender.Send(p)
	<-pc.writing
	result := make(chan error, 1)
	go func() {
		_, err := registry.seal(context.Background(), "fixture", ScopeSubjects{Paths: []string{"/fixture/target"}})
		result <- err
	}()
	<-pc.closed
	if _, _, ok := registry.Enter("/fixture/target", "", true, nil); ok {
		t.Fatal("target opened during drain")
	}
	other, _, ok := registry.Enter("/fixture/ordinary", "", true, nil)
	if !ok {
		t.Fatal("unrelated traffic blocked")
	}
	other.Done()
	select {
	case <-result:
		t.Fatal("premature drain acknowledgement")
	default:
	}
	close(pc.release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&p.drops) != 1 {
		t.Fatal("writer did not release packet")
	}
}

func TestScopedUDPSealWaitsForLateDialAndPreservesNewAssociation(t *testing.T) {
	registry := loadScopeRegistry("")
	ctx, cancel := context.WithCancel(context.Background())
	s := &scopedUDPSession{ctx: ctx, cancel: cancel, sender: newPacketSender()}
	f, _, _ := registry.Enter("/fixture/target", "", true, s.stop)
	key := scopedUDPKey{path: "/fixture/target", local: "fixture-late-dial"}
	scopedUDPTable.Lock()
	scopedUDPTable.sessions[key] = s
	scopedUDPTable.Unlock()
	defer func() { scopedUDPTable.Lock(); delete(scopedUDPTable.sessions, key); scopedUDPTable.Unlock() }()
	started, release := make(chan struct{}), make(chan struct{})
	pc := new(scopedUDPTestConn)
	p := new(scopedUDPTestPacket)
	s.sender.Send(p)
	go s.run(p, key, f, func(ctx context.Context, _ C.PacketAdapter, _ C.PacketSender, _ func(string) bool, _ *netip.AddrPort) (C.PacketConn, C.WriteBackProxy, error) {
		close(started)
		<-ctx.Done()
		<-release
		return pc, nil, nil
	})
	<-started
	result := make(chan error, 1)
	go func() {
		_, err := registry.seal(context.Background(), "fixture", ScopeSubjects{Paths: []string{key.path}})
		result <- err
	}()
	<-ctx.Done()
	select {
	case <-result:
		t.Fatal("pending dial omitted from drain")
	default:
	}
	replacement := new(scopedUDPSession)
	scopedUDPTable.Lock()
	scopedUDPTable.sessions[key] = replacement
	scopedUDPTable.Unlock()
	close(release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&pc.closes) != 1 || atomic.LoadInt32(&p.drops) != 1 {
		t.Fatal("late dial or queued datagram was not released")
	}
	scopedUDPTable.Lock()
	got := scopedUDPTable.sessions[key]
	scopedUDPTable.Unlock()
	if got != replacement {
		t.Fatal("old cleanup deleted a newer association")
	}
}
