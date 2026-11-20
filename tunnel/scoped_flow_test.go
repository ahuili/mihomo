package tunnel

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestScopedProofLifetime(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "scopes.json")
	r := loadScopeRegistry(file)
	s := ScopeSubjects{Paths: []string{"/fixture/tool"}, Hosts: []string{"fixed.example.test"}}
	stopping := make(chan struct{})
	old, _, _ := r.Enter("/fixture/tool", "", false, func() { close(stopping) })
	other, _, _ := r.Enter("/fixture/other", "", false, nil)
	defer other.Done()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := r.seal(ctx, "one", s); result <- err }()
	select {
	case <-stopping:
	case <-time.After(time.Second):
		t.Fatal("target was not stopped")
	}
	cancel()
	if <-result == nil {
		t.Fatal("unconfirmed termination was acknowledged")
	}
	if _, _, ok := r.Enter("/fixture/tool", "", false, nil); ok {
		t.Fatal("timed-out seal opened")
	}
	old.Done()
	token, err := r.seal(context.Background(), "one", s)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.authorize("one", token, "fixed"); err != nil {
		t.Fatal(err)
	}
	f, name, ok := r.Enter("/fixture/other", "FIXED.EXAMPLE.TEST.", false, nil)
	if !ok || name != "fixed" {
		t.Fatal("hostname scope not active")
	}
	f.Done()
	if _, _, ok := r.Enter("", "", false, nil); ok {
		t.Fatal("unattributed admitted with path protection")
	}
	if _, _, ok := r.Enter("/fixture/tool", "", true, nil); ok {
		t.Fatal("protected UDP admitted")
	}
	r = loadScopeRegistry(file)
	if r.loadErr != nil || r.authorize("one", token, "fixed") == nil {
		t.Fatal("restored an old authorization")
	}
	if _, _, ok := r.Enter("/fixture/tool", "", false, nil); ok {
		t.Fatal("restored scope started open")
	}
	fresh, err := r.seal(context.Background(), "one", s)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.forget("one", fresh); err != nil {
		t.Fatal(err)
	}
	r = loadScopeRegistry(file)
	free, name, ok := r.Enter("/fixture/tool", "", false, nil)
	if !ok || name != "" {
		t.Fatal("explicit removal was lost")
	}
	free.Done()
}
