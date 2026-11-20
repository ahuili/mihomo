package route

import (
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/tunnel"
)

func decodeScope(w http.ResponseWriter, r *http.Request, v any) bool {
	body := http.MaxBytesReader(w, r.Body, 128<<10)
	defer body.Close()
	d := json.NewDecoder(body)
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		http.Error(w, "invalid policy request", http.StatusBadRequest)
		return false
	}
	return true
}

func scopeRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", func(w http.ResponseWriter, r *http.Request) { render.JSON(w, r, tunnel.RoutingScopeReport()) })
	r.Put("/{id}/seal", func(w http.ResponseWriter, r *http.Request) {
		var subjects tunnel.ScopeSubjects
		if !decodeScope(w, r, &subjects) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		token, err := tunnel.SealScope(ctx, chi.URLParam(r, "id"), subjects)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		render.JSON(w, r, map[string]string{"token": token})
	})
	r.Put("/{id}/authorize", func(w http.ResponseWriter, r *http.Request) {
		var p struct {
			Token    string `json:"token"`
			Outbound string `json:"outbound"`
		}
		if !decodeScope(w, r, &p) {
			return
		}
		if err := tunnel.AuthorizeScope(chi.URLParam(r, "id"), p.Token, p.Outbound); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		render.NoContent(w, r)
	})
	r.Delete("/{id}", func(w http.ResponseWriter, r *http.Request) {
		var p struct {
			Token string `json:"token"`
		}
		if !decodeScope(w, r, &p) {
			return
		}
		if err := tunnel.ForgetScope(chi.URLParam(r, "id"), p.Token); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		render.NoContent(w, r)
	})
	return r
}
