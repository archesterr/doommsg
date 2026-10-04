// Package api implements the public HTTP API of the relay server.
//
// Accounts are bound to an Ed25519 identity key generated on the client.
// There are no passwords: a client proves ownership by signing a
// single-use, server-issued challenge and receives a bearer token whose
// SHA-256 hash is all the server stores.
package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/time/rate"

	"github.com/archesterr/doommsg/server/internal/config"
	"github.com/archesterr/doommsg/server/internal/hub"
	"github.com/archesterr/doommsg/server/internal/metrics"
	"github.com/archesterr/doommsg/server/internal/ratelimit"
	"github.com/archesterr/doommsg/server/internal/store"
	"github.com/archesterr/doommsg/server/internal/turn"
	"github.com/archesterr/doommsg/server/internal/validate"
)

// Domain-separation prefixes for every signature the server verifies.
// They must match the client byte for byte (web/src/crypto/protocol.ts).
const (
	ctxIdentityDH = "DoomMsg/v1/identity-dh"
	ctxSignedPre  = "DoomMsg/v1/signed-prekey"
	ctxRegister   = "DoomMsg/v1/register"
	ctxAuth       = "DoomMsg/v1/auth"

	challengeTTL    = 2 * time.Minute
	maxBodyBytes    = 256 << 10
	maxOTKsPerCall  = 100
	Version         = "0.1.0"
	tokenBytes      = 32
	challengeLength = 32
)

type Server struct {
	cfg   *config.Config
	store *store.Store
	hub   *hub.Hub
	turn  *turn.Issuer
	log   *slog.Logger

	ipLimiter       *ratelimit.Limiter
	authLimiter     *ratelimit.Limiter
	registerLimiter *ratelimit.Limiter
	bundleLimiter   *ratelimit.Limiter
	wsOrigins       []string
}

type ctxKey struct{}

type principal struct {
	id       int64
	username string
	token    []byte // hash
}

func New(cfg *config.Config, st *store.Store, log *slog.Logger) *Server {
	s := &Server{
		cfg:   cfg,
		store: st,
		log:   log,
		turn: &turn.Issuer{
			Secret: []byte(cfg.TURNSecret),
			URLs:   cfg.TURNURLs,
			STUN:   cfg.STUNURLs,
			TTL:    cfg.TURNTTL,
		},
		ipLimiter:       ratelimit.New(rate.Limit(15), 60),
		authLimiter:     ratelimit.New(rate.Every(6*time.Second), 20),
		registerLimiter: ratelimit.New(rate.Every(10*time.Minute), 5),
		bundleLimiter:   ratelimit.New(rate.Every(2*time.Second), 30),
	}
	for _, o := range cfg.AllowedOrigins {
		if u, err := url.Parse(o); err == nil && u.Host != "" {
			s.wsOrigins = append(s.wsOrigins, u.Host)
		}
	}
	s.hub = hub.New(hub.Options{
		Store:      st,
		Auth:       s.authenticate,
		MailboxTTL: cfg.MailboxTTL,
		MailboxMax: cfg.MailboxMax,
		Logger:     log,
	})
	return s
}

func (s *Server) Hub() *hub.Hub { return s.hub }

// Sweep evicts idle rate-limiter state.
func (s *Server) Sweep() {
	s.ipLimiter.Sweep()
	s.authLimiter.Sweep()
	s.registerLimiter.Sweep()
	s.bundleLimiter.Sweep()
	s.hub.Sweep()
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /readyz", s.ready)

	mux.HandleFunc("GET /api/v1/info", s.info)
	mux.HandleFunc("POST /api/v1/register", s.limited(s.registerLimiter, "register", s.register))
	mux.HandleFunc("POST /api/v1/auth/challenge", s.limited(s.authLimiter, "auth", s.challenge))
	mux.HandleFunc("POST /api/v1/auth/verify", s.limited(s.authLimiter, "auth", s.verify))
	mux.HandleFunc("POST /api/v1/auth/logout", s.authed(s.logout))
	mux.HandleFunc("GET /api/v1/users/{username}", s.authed(s.identity))
	mux.HandleFunc("POST /api/v1/users/{username}/bundle", s.authed(s.bundle))
	mux.HandleFunc("GET /api/v1/keys", s.authed(s.keyStatus))
	mux.HandleFunc("PUT /api/v1/keys/signed", s.authed(s.putSignedPreKey))
	mux.HandleFunc("POST /api/v1/keys/one-time", s.authed(s.addOneTimePreKeys))
	mux.HandleFunc("GET /api/v1/turn", s.authed(s.turnCredentials))
	mux.HandleFunc("DELETE /api/v1/account", s.authed(s.deleteAccount))
	mux.HandleFunc("GET /api/v1/ws", s.websocket)

	return s.middleware(mux)
}

// ---- middleware -----------------------------------------------------------

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController and the WebSocket upgrade reach the
// underlying writer (it needs http.Hijacker).
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")

		if origin := r.Header.Get("Origin"); origin != "" && s.originAllowed(origin) {
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Vary", "Origin")
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
			h.Set("Access-Control-Max-Age", "600")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}

		if !strings.HasPrefix(r.URL.Path, "/api/v1/ws") && !s.ipLimiter.Allow(s.clientIP(r)) {
			metrics.RateLimited.WithLabelValues("ip").Inc()
			writeErr(w, http.StatusTooManyRequests, "rate_limited")
			return
		}

		sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic", "err", rec, "path", r.URL.Path)
				writeErr(sw, http.StatusInternalServerError, "internal")
			}
			route := r.Pattern
			if route == "" {
				route = "unmatched"
			}
			metrics.HTTPRequests.WithLabelValues(route, strconv.Itoa(sw.code)).Inc()
			metrics.HTTPDuration.WithLabelValues(route).Observe(time.Since(start).Seconds())
		}()
		r.Body = http.MaxBytesReader(sw, r.Body, maxBodyBytes)
		next.ServeHTTP(sw, r)
	})
}

func (s *Server) originAllowed(origin string) bool {
	for _, o := range s.cfg.AllowedOrigins {
		if strings.EqualFold(o, origin) {
			return true
		}
	}
	return false
}

// clientIP returns the address used for rate limiting. Behind a trusted
// reverse proxy it is the right-most X-Forwarded-For entry (the one the
// proxy itself appended); anything to its left is client-controlled.
func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) limited(l *ratelimit.Limiter, name string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !l.Allow(s.clientIP(r)) {
			metrics.RateLimited.WithLabelValues(name).Inc()
			writeErr(w, http.StatusTooManyRequests, "rate_limited")
			return
		}
		h(w, r)
	}
}

func (s *Server) authed(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || raw == "" {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		hash := hashToken(raw)
		id, name, err := s.store.SessionUser(r.Context(), hash)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		ctx := context.WithValue(r.Context(), ctxKey{}, principal{id: id, username: name, token: hash})
		h(w, r.WithContext(ctx))
	}
}

func me(r *http.Request) principal { return r.Context().Value(ctxKey{}).(principal) }

func (s *Server) authenticate(ctx context.Context, token string) (int64, string, error) {
	return s.store.SessionUser(ctx, hashToken(token))
}

func hashToken(t string) []byte {
	h := sha256.Sum256([]byte(t))
	return h[:]
}

// ---- handlers -------------------------------------------------------------

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "db_unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) info(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"name":                 "DoomMsg",
		"version":              Version,
		"registrationRequired": s.cfg.RegistrationCode != "",
		"turn":                 len(s.cfg.TURNURLs) > 0,
	})
}

type signedPreKeyJSON struct {
	KeyID int64  `json:"keyId"`
	Pub   string `json:"pub"`
	Sig   string `json:"sig"`
}

type oneTimePreKeyJSON struct {
	KeyID int64  `json:"keyId"`
	Pub   string `json:"pub"`
}

type registerReq struct {
	Username         string              `json:"username"`
	SigKey           string              `json:"sigKey"`
	DHKey            string              `json:"dhKey"`
	DHKeySig         string              `json:"dhKeySig"`
	RegisterSig      string              `json:"registerSig"`
	SignedPreKey     signedPreKeyJSON    `json:"signedPreKey"`
	OneTimePreKeys   []oneTimePreKeyJSON `json:"oneTimePreKeys"`
	RegistrationCode string              `json:"registrationCode,omitempty"`
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var req registerReq
	if !decode(w, r, &req) {
		return
	}
	if s.cfg.RegistrationCode != "" &&
		subtle.ConstantTimeCompare([]byte(req.RegistrationCode), []byte(s.cfg.RegistrationCode)) != 1 {
		writeErr(w, http.StatusForbidden, "bad_registration_code")
		return
	}
	if !validate.Username(req.Username) {
		writeErr(w, http.StatusBadRequest, "bad_username")
		return
	}
	sigKey, err1 := validate.Key32(req.SigKey)
	dhKey, err2 := validate.Key32(req.DHKey)
	dhSig, err3 := validate.Sig64(req.DHKeySig)
	regSig, err4 := validate.Sig64(req.RegisterSig)
	if err := errors.Join(err1, err2, err3, err4); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_keys")
		return
	}
	pk := ed25519.PublicKey(sigKey)
	if !ed25519.Verify(pk, concat(ctxIdentityDH, dhKey), dhSig) ||
		!ed25519.Verify(pk, concat(ctxRegister, []byte(req.Username)), regSig) {
		writeErr(w, http.StatusBadRequest, "bad_signature")
		return
	}
	spk, ok := s.parseSignedPreKey(w, pk, req.SignedPreKey)
	if !ok {
		return
	}
	otks, ok := parseOTKs(w, req.OneTimePreKeys)
	if !ok {
		return
	}

	_, err := s.store.CreateUser(r.Context(), store.User{
		Username: req.Username, SigKey: sigKey, DHKey: dhKey, DHKeySig: dhSig,
	}, spk, otks)
	if errors.Is(err, store.ErrExists) {
		writeErr(w, http.StatusConflict, "username_taken")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	metrics.Registrations.Inc()
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) parseSignedPreKey(w http.ResponseWriter, pk ed25519.PublicKey, in signedPreKeyJSON) (store.SignedPreKey, bool) {
	pub, err1 := validate.Key32(in.Pub)
	sig, err2 := validate.Sig64(in.Sig)
	if errors.Join(err1, err2) != nil || in.KeyID < 0 {
		writeErr(w, http.StatusBadRequest, "bad_signed_prekey")
		return store.SignedPreKey{}, false
	}
	if !ed25519.Verify(pk, concat(ctxSignedPre, pub), sig) {
		writeErr(w, http.StatusBadRequest, "bad_signature")
		return store.SignedPreKey{}, false
	}
	return store.SignedPreKey{KeyID: in.KeyID, Pub: pub, Sig: sig}, true
}

func parseOTKs(w http.ResponseWriter, in []oneTimePreKeyJSON) ([]store.OneTimePreKey, bool) {
	if len(in) > maxOTKsPerCall {
		writeErr(w, http.StatusBadRequest, "too_many_prekeys")
		return nil, false
	}
	out := make([]store.OneTimePreKey, 0, len(in))
	for _, k := range in {
		pub, err := validate.Key32(k.Pub)
		if err != nil || k.KeyID < 0 {
			writeErr(w, http.StatusBadRequest, "bad_one_time_prekey")
			return nil, false
		}
		out = append(out, store.OneTimePreKey{KeyID: k.KeyID, Pub: pub})
	}
	return out, true
}

func (s *Server) challenge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
	}
	if !decode(w, r, &req) {
		return
	}
	if !validate.Username(req.Username) {
		writeErr(w, http.StatusBadRequest, "bad_username")
		return
	}
	// A challenge is issued even for unknown usernames so the endpoint
	// cannot be used to enumerate accounts.
	c := make([]byte, challengeLength)
	if _, err := rand.Read(c); err != nil {
		s.internal(w, err)
		return
	}
	if err := s.store.CreateChallenge(r.Context(), c, req.Username, challengeTTL); err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"challenge": validate.B64(c)})
}

func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username  string `json:"username"`
		Challenge string `json:"challenge"`
		Signature string `json:"signature"`
	}
	if !decode(w, r, &req) {
		return
	}
	c, err1 := validate.Key32(req.Challenge)
	sig, err2 := validate.Sig64(req.Signature)
	if errors.Join(err1, err2) != nil || !validate.Username(req.Username) {
		writeErr(w, http.StatusBadRequest, "bad_request")
		return
	}
	ok, err := s.store.ConsumeChallenge(r.Context(), c, req.Username)
	if err != nil {
		s.internal(w, err)
		return
	}
	u, err := s.store.UserByName(r.Context(), req.Username)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internal(w, err)
		return
	}
	if !ok || u == nil || !ed25519.Verify(ed25519.PublicKey(u.SigKey), concat(ctxAuth, c), sig) {
		writeErr(w, http.StatusUnauthorized, "bad_credentials")
		return
	}

	tok := make([]byte, tokenBytes)
	if _, err := rand.Read(tok); err != nil {
		s.internal(w, err)
		return
	}
	token := validate.B64(tok)
	exp, err := s.store.CreateSession(r.Context(), hashToken(token), u.ID, s.cfg.SessionTTL)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "expiresAt": exp.UnixMilli()})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteSession(r.Context(), me(r).token); err != nil {
		s.internal(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func identityJSON(u *store.User) map[string]any {
	return map[string]any{
		"username": u.Username,
		"sigKey":   validate.B64(u.SigKey),
		"dhKey":    validate.B64(u.DHKey),
		"dhKeySig": validate.B64(u.DHKeySig),
	}
}

func (s *Server) identity(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("username")
	if !validate.Username(name) {
		writeErr(w, http.StatusBadRequest, "bad_username")
		return
	}
	u, err := s.store.UserByName(r.Context(), name)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no_such_user")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, identityJSON(u))
}

func (s *Server) bundle(w http.ResponseWriter, r *http.Request) {
	// Bundles consume one-time prekeys, so throttle per requesting account
	// to stop a single user from draining someone else's supply.
	if !s.bundleLimiter.Allow(me(r).username) {
		metrics.RateLimited.WithLabelValues("bundle").Inc()
		writeErr(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	name := r.PathValue("username")
	if !validate.Username(name) {
		writeErr(w, http.StatusBadRequest, "bad_username")
		return
	}
	b, err := s.store.TakeBundle(r.Context(), name)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no_such_user")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	out := identityJSON(&b.User)
	out["signedPreKey"] = signedPreKeyJSON{KeyID: b.SignedPreKey.KeyID, Pub: validate.B64(b.SignedPreKey.Pub), Sig: validate.B64(b.SignedPreKey.Sig)}
	if b.OneTime != nil {
		out["oneTimePreKey"] = oneTimePreKeyJSON{KeyID: b.OneTime.KeyID, Pub: validate.B64(b.OneTime.Pub)}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) keyStatus(w http.ResponseWriter, r *http.Request) {
	n, err := s.store.CountOneTimePreKeys(r.Context(), me(r).id)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"oneTimePreKeys": n, "max": store.MaxOneTimePreKeys})
}

func (s *Server) putSignedPreKey(w http.ResponseWriter, r *http.Request) {
	var req signedPreKeyJSON
	if !decode(w, r, &req) {
		return
	}
	u, err := s.store.UserByName(r.Context(), me(r).username)
	if err != nil {
		s.internal(w, err)
		return
	}
	spk, ok := s.parseSignedPreKey(w, ed25519.PublicKey(u.SigKey), req)
	if !ok {
		return
	}
	if err := s.store.SetSignedPreKey(r.Context(), u.ID, spk); err != nil {
		s.internal(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) addOneTimePreKeys(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Keys []oneTimePreKeyJSON `json:"keys"`
	}
	if !decode(w, r, &req) {
		return
	}
	otks, ok := parseOTKs(w, req.Keys)
	if !ok {
		return
	}
	if err := s.store.AddOneTimePreKeys(r.Context(), me(r).id, otks); err != nil {
		writeErr(w, http.StatusBadRequest, "prekey_limit")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) turnCredentials(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.turn.Issue(me(r).username, time.Now()))
}

func (s *Server) deleteAccount(w http.ResponseWriter, r *http.Request) {
	p := me(r)
	if err := s.store.DeleteUser(r.Context(), p.id); err != nil {
		s.internal(w, err)
		return
	}
	s.hub.Disconnect(p.id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) websocket(w http.ResponseWriter, r *http.Request) {
	if !s.authLimiter.Allow(s.clientIP(r)) {
		metrics.RateLimited.WithLabelValues("ws_connect").Inc()
		writeErr(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	// Long-lived connection: lift the server-wide read/write deadlines. The
	// hub enforces its own per-frame timeouts and keepalive pings instead.
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// Empty means same-origin only (Origin host must equal Host).
		OriginPatterns: s.wsOrigins,
	})
	if err != nil {
		return // Accept already wrote the HTTP error
	}
	// The connection outlives the request handler's deadlines; detach from
	// them but keep cancellation on server shutdown via the hub.
	s.hub.Accept(context.WithoutCancel(r.Context()), ws)
}

// ---- helpers --------------------------------------------------------------

func concat(prefix string, b []byte) []byte {
	out := make([]byte, 0, len(prefix)+len(b))
	out = append(out, prefix...)
	return append(out, b...)
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		writeErr(w, http.StatusUnsupportedMediaType, "json_required")
		return false
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, http.StatusRequestEntityTooLarge, "too_large")
		} else {
			writeErr(w, http.StatusBadRequest, "bad_json")
		}
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "bad_json")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *Server) internal(w http.ResponseWriter, err error) {
	s.log.Error("internal error", "err", err)
	writeErr(w, http.StatusInternalServerError, "internal")
}
