package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

	C "github.com/metacubex/mihomo/constant"
)

// Pin the concrete adapter. A selector could subsequently choose a different
// outbound without another drain. The caller owns exit verification.
func scopedOutbound(name string) C.Proxy {
	configMux.RLock()
	defer configMux.RUnlock()
	p := proxies[name]
	if p == nil || p.Type() != C.Http {
		return nil
	}
	return p
}

type scopedTCP struct {
	mu      sync.Mutex
	in      net.Conn
	out     io.Closer
	cancel  context.CancelFunc
	stopped bool
}

func (s *scopedTCP) stop() {
	s.mu.Lock()
	s.stopped = true
	out := s.out
	s.mu.Unlock()
	s.cancel()
	_ = s.in.Close()
	if out != nil {
		_ = out.Close()
	}
}
func (s *scopedTCP) attach(out io.Closer) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return false
	}
	s.out = out
	return true
}
func ScopedRoutingEnabled() bool { return scopedRoutingEnabled }
func SealScope(ctx context.Context, id string, subjects ScopeSubjects) (string, error) {
	return scopedFlows.seal(ctx, id, subjects)
}
func AuthorizeScope(id, token, name string) error {
	if scopedOutbound(name) == nil {
		return errors.New("a concrete HTTP relay is required")
	}
	return scopedFlows.authorize(id, token, name)
}
