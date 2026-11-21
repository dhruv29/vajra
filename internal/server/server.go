// Package server is the read-only HTTP API and web interface over saved runs.
//
// It is meant for the operator's own machine: it listens on loopback only,
// every API call needs the token printed at start-up, and requests whose Host
// header is not the address it was started on are refused, which stops a web
// page elsewhere from reaching it through DNS rebinding.
package server

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strings"

	"github.com/dhruv29/vajra/internal/app"
	"github.com/dhruv29/vajra/internal/store"
)

const (
	tokenBytes   = 32
	bearerPrefix = "Bearer "

	contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
		"connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

//go:embed web
var webFiles embed.FS

var reportTypes = map[string]string{
	"html": "text/html; charset=utf-8",
	"md":   "text/markdown; charset=utf-8",
	"json": "application/json",
}

// NewToken returns a random access token.
func NewToken() (string, error) {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("server: token: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// LoopbackAddr checks that addr ("host:port") names a loopback interface and
// returns the Host header values a browser will send for it.
func LoopbackAddr(addr string) ([]string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("server: listen address %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, fmt.Errorf("server: %q is not a loopback address; the interface is for this machine only", host)
	}
	return []string{net.JoinHostPort(host, port), "localhost:" + port, "127.0.0.1:" + port, "[::1]:" + port}, nil
}

type handler struct {
	store *store.Store
	token string
	hosts map[string]bool
	mux   *http.ServeMux
}

// New builds the HTTP handler. allowedHosts are the Host header values to
// accept, as returned by LoopbackAddr.
func New(st *store.Store, token string, allowedHosts []string) (http.Handler, error) {
	if st == nil || len(token) < tokenBytes || len(allowedHosts) == 0 {
		return nil, errors.New("server: a store, a token and at least one allowed host are required")
	}
	static, err := fs.Sub(webFiles, "web")
	if err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}
	h := &handler{store: st, token: token, hosts: map[string]bool{}, mux: http.NewServeMux()}
	for _, host := range allowedHosts {
		h.hosts[strings.ToLower(host)] = true
	}
	h.mux.HandleFunc("GET /api/runs", h.listRuns)
	h.mux.HandleFunc("GET /api/runs/{id}", h.getRun)
	h.mux.HandleFunc("GET /api/runs/{id}/report", h.getReport)
	h.mux.Handle("GET /", http.FileServerFS(static))
	return h, nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	header := w.Header()
	header.Set("Content-Security-Policy", contentSecurityPolicy)
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Cross-Origin-Resource-Policy", "same-origin")

	if !h.hosts[strings.ToLower(r.Host)] {
		writeError(w, http.StatusForbidden, "this interface answers only on the address it was started on")
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		header.Set("Cache-Control", "no-store")
		if !h.authorized(r) {
			header.Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "a valid access token is required")
			return
		}
	}
	h.mux.ServeHTTP(w, r)
}

func (h *handler) authorized(r *http.Request) bool {
	given, ok := strings.CutPrefix(r.Header.Get("Authorization"), bearerPrefix)
	return ok && subtle.ConstantTimeCompare([]byte(given), []byte(h.token)) == 1
}

func (h *handler) listRuns(w http.ResponseWriter, _ *http.Request) {
	runs, err := h.store.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "the saved runs could not be read")
		return
	}
	writeJSON(w, http.StatusOK, runs)
}

func (h *handler) getRun(w http.ResponseWriter, r *http.Request) {
	run, err := h.store.Get(r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (h *handler) getReport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	contentType, ok := reportTypes[format]
	if !ok {
		writeError(w, http.StatusBadRequest, "format must be html, md or json")
		return
	}
	run, err := h.store.Get(r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	body, err := app.Render(run, format)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "the report could not be rendered")
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="vajra-%s.%s"`, run.ID, format))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "no such run")
	case errors.Is(err, store.ErrBadID):
		writeError(w, http.StatusBadRequest, "the run ID is malformed")
	default:
		writeError(w, http.StatusInternalServerError, "the run could not be read")
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
