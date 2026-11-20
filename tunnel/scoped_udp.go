package tunnel

import (
	"context"
	"net/netip"
	"sync"

	"github.com/metacubex/mihomo/component/process"
	C "github.com/metacubex/mihomo/constant"
)

// Keep scoped TUN associations separate from the listener NAT table (which is
// also used by tproxy to look up its local sockets).
type scopedUDPKey struct {
	local, path, host, destination string
}

var scopedUDPTable = struct {
	sync.Mutex
	sessions map[scopedUDPKey]*scopedUDPSession
}{sessions: make(map[scopedUDPKey]*scopedUDPSession)}

type scopedUDPSession struct {
	ctx      context.Context
	cancel   context.CancelFunc
	sender   C.PacketSender
	stopOnce sync.Once
	mu       sync.Mutex
	pc       C.PacketConn
}

func scopedPacketIdentity(metadata *C.Metadata) string {
	path, err := process.FindUniqueSocketPath(process.UDP, metadata.SrcIP.Unmap(), int(metadata.SrcPort))
	if err != nil {
		return ""
	}
	return path
}

func handleScopedUDP(packet C.PacketAdapter, prepared *C.Metadata, path string) {
	key := scopedUDPKey{packet.Key(), path, prepared.RuleHost(), packet.Metadata().RemoteAddress()}
	// Admission happens even on cache hits. The persistent registration on the
	// association covers queued packets and the interval before a dial returns.
	pass, _, allowed := scopedFlows.Enter(path, key.host, true, nil)
	if !allowed {
		packet.Drop()
		return
	}
	defer pass.Done()

	scopedUDPTable.Lock()
	s := scopedUDPTable.sessions[key]
	if s != nil {
		scopedUDPTable.Unlock()
		s.sender.Send(packet)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	s = &scopedUDPSession{ctx: ctx, cancel: cancel, sender: newPacketSender()}
	if sniffingEnable && snifferDispatcher.Enable() {
		s.sender = snifferDispatcher.UDPSniff(packet, s.sender)
	}
	flow, _, allowed := scopedFlows.Enter(path, key.host, true, s.stop)
	if !allowed {
		scopedUDPTable.Unlock()
		s.stop()
		packet.Drop()
		return
	}
	scopedUDPTable.sessions[key] = s
	scopedUDPTable.Unlock()
	go s.run(packet, key, flow, dialUDPAssociation)
	s.sender.Send(packet)
}

func (s *scopedUDPSession) stop() {
	s.stopOnce.Do(func() {
		s.cancel()
		s.sender.Close()
		s.mu.Lock()
		pc := s.pc
		s.mu.Unlock()
		if pc != nil {
			_ = pc.Close()
		}
	})
}

// publish races with revocation. Either the revoker owns Close or the late
// dial result is closed here before any writer starts.
func (s *scopedUDPSession) publish(pc C.PacketConn) bool {
	s.mu.Lock()
	if s.ctx.Err() == nil {
		s.pc = pc
		s.mu.Unlock()
		return true
	}
	s.mu.Unlock()
	_ = pc.Close()
	return false
}

type udpAssociationDial func(context.Context, C.PacketAdapter, C.PacketSender, func(string) bool, *netip.AddrPort) (C.PacketConn, C.WriteBackProxy, error)

func (s *scopedUDPSession) run(packet C.PacketAdapter, key scopedUDPKey, flow *scopeFlow, dial udpAssociationDial) {
	var sniffFlow *scopeFlow
	defer func() {
		s.stop()
		scopedUDPTable.Lock()
		if scopedUDPTable.sessions[key] == s {
			delete(scopedUDPTable.sessions, key)
		}
		scopedUDPTable.Unlock()
		if sniffFlow != nil {
			sniffFlow.Done()
		}
		flow.Done()
	}()

	admit := func(host string) bool {
		if host == key.host {
			return true
		}
		var allowed bool
		sniffFlow, _, allowed = scopedFlows.Enter(key.path, host, true, s.stop)
		return allowed
	}
	var oAddrPort netip.AddrPort
	pc, writeBack, err := dial(s.ctx, packet, s.sender, admit, &oAddrPort)
	if err != nil || !s.publish(pc) {
		return
	}
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		readUDPReplies(writeBack, pc, s.sender, oAddrPort)
		s.stop()
	}()
	s.sender.Process(pc, writeBack)
	s.stop()
	<-readDone
}
