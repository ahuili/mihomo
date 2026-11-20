package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Scoped routing is opt-in for the lifetime of a core. Its private checkpoint
// stores only the subjects. An authorization from an earlier boot is never loaded.
var scopeFile = os.Getenv("MIHOMO_SCOPE_FILE")
var scopedRoutingEnabled = scopeFile != ""
var scopedFlows = loadScopeRegistry(scopeFile)

type ScopeSubjects struct {
	Paths []string `json:"paths"`
	Hosts []string `json:"hosts"`
}
type scopeRule struct {
	subjects ScopeSubjects
	token    string
	drained  bool
	outbound string
}
type scopeRegistry struct {
	mu      sync.Mutex
	file    string
	loadErr error
	rules   map[string]*scopeRule
	flows   map[*scopeFlow]struct{}
}
type scopeFlow struct {
	registry   *scopeRegistry
	path, host string
	stop       func()
	stopOnce   sync.Once
	done       chan struct{}
}

func (f *scopeFlow) Done() {
	r := f.registry
	r.mu.Lock()
	delete(r.flows, f)
	close(f.done)
	r.mu.Unlock()
}
func cleanScopeHost(host string) string { return strings.ToLower(strings.TrimSuffix(host, ".")) }
func (s ScopeSubjects) matches(path, host string) bool {
	if path == "" && len(s.Paths) != 0 {
		return true
	}
	for _, p := range s.Paths {
		if p == path {
			return true
		}
	}
	for _, h := range s.Hosts {
		if h == host {
			return true
		}
	}
	return false
}
func (s ScopeSubjects) validate() error {
	if len(s.Paths)+len(s.Hosts) == 0 || len(s.Paths) > 256 || len(s.Hosts) > 256 {
		return errors.New("invalid scope size")
	}
	for _, p := range s.Paths {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || len(p) > 4096 || strings.ContainsRune(p, 0) {
			return errors.New("invalid executable path")
		}
	}
	for _, h := range s.Hosts {
		if h == "" || len(h) > 253 || cleanScopeHost(h) != h || strings.ContainsAny(h, " /:*?#\t\r\n") {
			return errors.New("expected an exact normalized hostname")
		}
	}
	return nil
}
func loadScopeRegistry(file string) *scopeRegistry {
	r := &scopeRegistry{file: file, rules: make(map[string]*scopeRule), flows: make(map[*scopeFlow]struct{})}
	if file != "" {
		r.loadErr = r.restore()
	}
	return r
}
func (r *scopeRegistry) restore() error {
	d, err := os.Lstat(filepath.Dir(r.file))
	if err != nil || !filepath.IsAbs(r.file) || !d.IsDir() || d.Mode().Perm()&0077 != 0 {
		return errors.New("scope checkpoint requires a private directory")
	}
	fi, err := os.Lstat(r.file)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0077 != 0 || fi.Size() > 4<<20 {
		return errors.New("invalid scope checkpoint")
	}
	data, err := os.ReadFile(r.file)
	if err != nil {
		return err
	}
	var saved map[string]ScopeSubjects
	if err = json.Unmarshal(data, &saved); err != nil || saved == nil || len(saved) > 128 {
		return errors.New("invalid saved scopes")
	}
	for id, s := range saved {
		if id == "" || len(id) > 128 || s.validate() != nil {
			return errors.New("invalid saved scope")
		}
		r.rules[id] = &scopeRule{subjects: s}
	}
	return nil
}
func (r *scopeRegistry) persist() error {
	if r.file == "" {
		return nil
	}
	saved := make(map[string]ScopeSubjects, len(r.rules))
	for id, rule := range r.rules {
		saved[id] = rule.subjects
	}
	data, err := json.Marshal(saved)
	if err != nil {
		return err
	}
	if len(data) > 4<<20 {
		return errors.New("scope checkpoint too large")
	}
	dir := filepath.Dir(r.file)
	f, err := os.CreateTemp(dir, ".scopes-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), r.file); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func (r *scopeRegistry) Enter(path, host string, udp bool, stop func()) (*scopeFlow, string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.loadErr != nil {
		return nil, "", false
	}
	host = cleanScopeHost(host)
	outbound := ""
	for _, rule := range r.rules {
		if !rule.subjects.matches(path, host) {
			continue
		}
		if udp || !rule.drained || rule.outbound == "" || (path == "" && len(rule.subjects.Paths) > 0) || (outbound != "" && outbound != rule.outbound) {
			return nil, "", false
		}
		outbound = rule.outbound
	}
	f := &scopeFlow{registry: r, path: path, host: host, stop: stop, done: make(chan struct{})}
	r.flows[f] = struct{}{}
	return f, outbound, true
}

// Seal installs the closed policy before any old flow is interrupted. Returning
// a token means that every matching handler present at that instant has exited.
func (r *scopeRegistry) seal(ctx context.Context, id string, s ScopeSubjects) (string, error) {
	if id == "" || len(id) > 128 {
		return "", errors.New("invalid scope ID")
	}
	if err := s.validate(); err != nil {
		return "", err
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	rule := &scopeRule{subjects: s, token: hex.EncodeToString(nonce[:])}
	r.mu.Lock()
	if r.loadErr != nil {
		r.mu.Unlock()
		return "", errors.New("scope checkpoint unavailable")
	}
	prev := r.rules[id]
	if prev == nil && len(r.rules) >= 128 {
		r.mu.Unlock()
		return "", errors.New("scope limit reached")
	}
	if prev != nil && !equalScope(prev.subjects, s) {
		r.mu.Unlock()
		return "", errors.New("a scope ID is bound to its original subjects")
	}
	r.rules[id] = rule
	var old []*scopeFlow
	for f := range r.flows {
		if s.matches(f.path, f.host) {
			old = append(old, f)
		}
	}
	err := r.persist()
	r.mu.Unlock()
	for _, f := range old {
		if f.stop != nil {
			go f.stopOnce.Do(f.stop)
		}
	}
	if err != nil {
		return "", fmt.Errorf("closing scope: %w", err)
	}
	for _, f := range old {
		select {
		case <-f.done:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rules[id] != rule {
		return "", errors.New("scope changed while draining")
	}
	rule.drained = true
	return rule.token, nil
}
func equalScope(a, b ScopeSubjects) bool {
	return strings.Join(a.Paths, "\x00") == strings.Join(b.Paths, "\x00") && strings.Join(a.Hosts, "\x00") == strings.Join(b.Hosts, "\x00")
}
func (r *scopeRegistry) authorize(id, token, outbound string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.rules[id]
	if s == nil || !s.drained || token == "" || s.token != token || outbound == "" {
		return errors.New("a current drain acknowledgment is required")
	}
	if s.outbound != "" && s.outbound != outbound {
		return errors.New("seal before changing outbound")
	}
	s.outbound = outbound
	return nil
}

// Forget is an explicit return to normal policy. A sealed generation ensures
// the caller cannot remove a scope that has since been reopened or replaced.
func (r *scopeRegistry) forget(id, token string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.rules[id]
	if s == nil || !s.drained || s.outbound != "" || token == "" || s.token != token {
		return errors.New("a closed and drained scope is required")
	}
	delete(r.rules, id)
	if err := r.persist(); err != nil {
		r.rules[id] = s
		return err
	}
	return nil
}
func ForgetScope(id, token string) error { return scopedFlows.forget(id, token) }
