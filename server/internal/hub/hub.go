// Package hub relays end-to-end encrypted envelopes between connected
// clients over WebSockets.
//
// The hub never interprets payloads: they are opaque ciphertext produced by
// the clients' Double Ratchet sessions. Durable envelopes are written to the
// mailbox before delivery and removed only when the recipient acks them, so
// a message survives server restarts and client disconnects. Ephemeral
// envelopes (typing indicators, call signalling) are delivered only to
// online recipients and never touch the disk.
package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/time/rate"

	"github.com/archesterr/doommsg/server/internal/metrics"
	"github.com/archesterr/doommsg/server/internal/ratelimit"
	"github.com/archesterr/doommsg/server/internal/store"
	"github.com/archesterr/doommsg/server/internal/validate"
)

const (
	MaxFrameBytes   = 128 << 10 // largest inbound frame
	MaxPayloadBytes = 96 << 10  // largest envelope payload
	maxAckIDs       = 500
	maxClientIDLen  = 64
	authTimeout     = 10 * time.Second
	writeTimeout    = 10 * time.Second
	pingInterval    = 25 * time.Second
	outBuffer       = 512
	flushPage       = 200
)

// Authenticator resolves a bearer token to its session.
type Authenticator func(ctx context.Context, token string) (Session, error)

// Session is the login a connection was authenticated with.
type Session struct {
	UserID    int64
	Username  string
	TokenHash []byte    // identifies the session to DisconnectSession
	ExpiresAt time.Time // the connection is closed when it passes
}

type Options struct {
	Store      *store.Store
	Auth       Authenticator
	MailboxTTL time.Duration
	Mailbox    store.MailboxLimits
	Logger     *slog.Logger
}

type Hub struct {
	opt        Options
	limiter    *ratelimit.Limiter
	ackLimiter *ratelimit.Limiter

	mu     sync.Mutex
	conns  map[int64]*conn
	closed bool
}

type conn struct {
	ws       *websocket.Conn
	userID   int64
	username string
	session  []byte
	expires  time.Time
	out      chan frame // live frames; when it is full the client is too slow
	backlog  chan frame // mailbox flush; unbuffered, it waits for the writer
	cancel   context.CancelFunc
	once     sync.Once
}

// frame is the union of all frames on the wire. Unused fields are omitted.
type frame struct {
	Type     string  `json:"type"`
	Token    string  `json:"token,omitempty"`
	ID       string  `json:"id,omitempty"`
	SID      int64   `json:"sid,omitempty"`
	To       string  `json:"to,omitempty"`
	From     string  `json:"from,omitempty"`
	Payload  string  `json:"payload,omitempty"`
	Eph      bool    `json:"eph,omitempty"`
	TS       int64   `json:"ts,omitempty"`
	IDs      []int64 `json:"ids,omitempty"`
	Code     string  `json:"code,omitempty"`
	Username string  `json:"username,omitempty"`
}

func New(opt Options) *Hub {
	return &Hub{
		opt: opt,
		// Generous enough for ICE candidate bursts, tight enough to stop floods.
		limiter: ratelimit.New(rate.Limit(20), 120),
		// Acks have their own bucket: each one is capped at maxAckIDs and
		// only deletes the caller's own envelopes.
		ackLimiter: ratelimit.New(rate.Limit(50), 1000),
		conns:      make(map[int64]*conn),
	}
}

// Sweep evicts idle rate-limiter state.
func (h *Hub) Sweep() {
	h.limiter.Sweep()
	h.ackLimiter.Sweep()
}

func (h *Hub) lookup(userID int64) *conn {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.conns[userID]
}

// Online reports whether a user currently has a live connection.
func (h *Hub) Online(userID int64) bool { return h.lookup(userID) != nil }

// Disconnect closes a user's connection (e.g. after account deletion).
func (h *Hub) Disconnect(userID int64) {
	if c := h.lookup(userID); c != nil {
		go c.close(websocket.StatusPolicyViolation, "session ended")
	}
}

// DisconnectSession closes a user's connection if it was authenticated
// with the session identified by tokenHash (e.g. after logout).
func (h *Hub) DisconnectSession(userID int64, tokenHash []byte) {
	if c := h.lookup(userID); c != nil && bytes.Equal(c.session, tokenHash) {
		go c.close(websocket.StatusPolicyViolation, "session ended")
	}
}

// Close disconnects everyone; used on graceful shutdown.
func (h *Hub) Close() {
	h.mu.Lock()
	h.closed = true
	conns := make([]*conn, 0, len(h.conns))
	for _, c := range h.conns {
		conns = append(conns, c)
	}
	h.mu.Unlock()
	var wg sync.WaitGroup
	for _, c := range conns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.close(websocket.StatusGoingAway, "server shutting down")
		}()
	}
	wg.Wait()
}

// Accept upgrades the request and serves the connection until it closes.
func (h *Hub) Accept(ctx context.Context, ws *websocket.Conn) {
	ws.SetReadLimit(MaxFrameBytes)
	log := h.opt.Logger

	// The first frame must authenticate. Tokens are never put in URLs so
	// they do not end up in proxy access logs.
	actx, cancelAuth := context.WithTimeout(ctx, authTimeout)
	var f frame
	err := readJSON(actx, ws, &f)
	cancelAuth()
	if err != nil || f.Type != "auth" || f.Token == "" {
		ws.Close(websocket.StatusPolicyViolation, "auth required")
		return
	}
	sess, err := h.opt.Auth(ctx, f.Token)
	if err != nil {
		writeJSON(ctx, ws, frame{Type: "error", Code: "unauthorized"})
		ws.Close(websocket.StatusPolicyViolation, "unauthorized")
		return
	}
	userID, username := sess.UserID, sess.Username

	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	c := &conn{
		ws: ws, userID: userID, username: username, session: sess.TokenHash, expires: sess.ExpiresAt,
		out: make(chan frame, outBuffer), backlog: make(chan frame), cancel: cancel,
	}

	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		ws.Close(websocket.StatusGoingAway, "server shutting down")
		return
	}
	// One live connection per account: the client enforces a single active
	// tab, and a newer connection replaces an older one.
	old := h.conns[userID]
	h.conns[userID] = c
	h.mu.Unlock()
	if old != nil {
		// Close waits for the peer's close handshake; don't block on it.
		go old.close(websocket.StatusPolicyViolation, "replaced")
	}
	metrics.WSConnections.Inc()
	log.Debug("ws connected")

	var wg sync.WaitGroup
	defer func() {
		h.mu.Lock()
		if h.conns[userID] == c {
			delete(h.conns, userID)
		}
		h.mu.Unlock()
		metrics.WSConnections.Dec()
		c.close(websocket.StatusNormalClosure, "")
		wg.Wait()
	}()

	// A logout between Auth and the registration above could not find this
	// connection to close it; check the session again now that it can.
	if _, err := h.opt.Auth(cctx, f.Token); err != nil {
		c.close(websocket.StatusPolicyViolation, "session ended")
		return
	}

	// Written before the writer starts, so it precedes every other frame.
	if err := writeJSON(cctx, ws, frame{Type: "ready", Username: username}); err != nil {
		return
	}
	wg.Go(func() { c.writeLoop(cctx) })
	// The mailbox drains alongside the read loop, so acks are applied (and
	// pongs received) while a large backlog is still being sent.
	wg.Go(func() {
		if err := h.flush(cctx, c); err != nil && cctx.Err() == nil {
			log.Warn("mailbox flush failed", "err", err)
			c.close(websocket.StatusInternalError, "sync failed")
		}
	})

	for {
		var in frame
		if err := readJSON(cctx, ws, &in); err != nil {
			return
		}
		if in.Type == "ack" {
			// Over their bucket, acks are delayed rather than dropped: a
			// lost ack leaves the envelope queued, to be delivered again.
			if err := h.ackLimiter.Wait(cctx, username); err != nil {
				return
			}
		} else if !h.limiter.Allow(username) {
			metrics.RateLimited.WithLabelValues("ws").Inc()
			c.send(frame{Type: "error", Code: "rate_limited", ID: in.ID})
			continue
		}
		switch in.Type {
		case "send":
			h.handleSend(cctx, c, in)
		case "ack":
			if len(in.IDs) > maxAckIDs {
				c.send(frame{Type: "error", Code: "too_many_ids"})
				continue
			}
			if err := h.opt.Store.Ack(cctx, userID, in.IDs); err != nil {
				log.Warn("ack failed", "err", err)
			}
		case "ping":
			c.send(frame{Type: "pong"})
		default:
			c.send(frame{Type: "error", Code: "unknown_type"})
		}
	}
}

func (h *Hub) handleSend(ctx context.Context, c *conn, in frame) {
	kind := "stored"
	if in.Eph {
		kind = "ephemeral"
	}
	fail := func(code string) {
		metrics.EnvelopesRelayed.WithLabelValues(kind, code).Inc()
		c.send(frame{Type: "error", Code: code, ID: in.ID})
	}
	switch {
	case in.ID == "" || len(in.ID) > maxClientIDLen:
		fail("bad_id")
		return
	case !validate.Username(in.To) || in.To == c.username:
		fail("bad_recipient")
		return
	case in.Payload == "" || len(in.Payload) > MaxPayloadBytes:
		fail("bad_payload")
		return
	}

	rcpt, err := h.opt.Store.UserByName(ctx, in.To)
	if errors.Is(err, store.ErrNotFound) {
		fail("no_such_user")
		return
	}
	if err != nil {
		fail("internal")
		return
	}

	if in.Eph {
		target := h.lookup(rcpt.ID)
		if target == nil {
			fail("offline")
			return
		}
		ts := time.Now().UnixMilli()
		target.send(frame{Type: "msg", From: c.username, Payload: in.Payload, Eph: true, TS: ts})
		metrics.EnvelopesRelayed.WithLabelValues(kind, "ok").Inc()
		c.send(frame{Type: "sent", ID: in.ID, TS: ts})
		return
	}

	sid, at, err := h.opt.Store.Enqueue(ctx, rcpt.ID, c.username, []byte(in.Payload), h.opt.MailboxTTL, h.opt.Mailbox)
	if errors.Is(err, store.ErrMailboxFul) {
		fail("mailbox_full")
		return
	}
	if err != nil {
		h.opt.Logger.Error("enqueue failed", "err", err)
		fail("internal")
		return
	}
	metrics.EnvelopesRelayed.WithLabelValues(kind, "ok").Inc()
	c.send(frame{Type: "sent", ID: in.ID, SID: sid, TS: at.UnixMilli()})
	// Look the recipient up only now that the envelope is committed: a
	// connection registered before this point gets it live, and a later one
	// finds it in its mailbox flush.
	if target := h.lookup(rcpt.ID); target != nil {
		target.send(frame{Type: "msg", SID: sid, From: c.username, Payload: in.Payload, TS: at.UnixMilli()})
	}
}

// flush delivers every queued envelope to a freshly connected client,
// then "synced". The backlog waits for the writer instead of filling the
// live buffer, so a large mailbox drains at the pace the client reads.
// Envelopes that also arrive live during the flush are de-duplicated by
// the client using their server id.
func (h *Hub) flush(ctx context.Context, c *conn) error {
	var after int64
	for {
		envs, err := h.opt.Store.Pending(ctx, c.userID, after, flushPage)
		if err != nil {
			return err
		}
		for _, e := range envs {
			f := frame{Type: "msg", SID: e.ID, From: e.Sender, Payload: string(e.Payload), TS: e.CreatedAt.UnixMilli()}
			if err := c.sendBacklog(ctx, f); err != nil {
				return err
			}
			after = e.ID
		}
		if len(envs) < flushPage {
			return c.sendBacklog(ctx, frame{Type: "synced"})
		}
	}
}

func (c *conn) sendBacklog(ctx context.Context, f frame) error {
	select {
	case c.backlog <- f:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *conn) send(f frame) {
	select {
	case c.out <- f:
	default:
		// Slow consumer. Durable envelopes stay in the mailbox and will be
		// re-delivered on reconnect, so dropping the connection is safe.
		go c.close(websocket.StatusTryAgainLater, "too slow")
	}
}

func (c *conn) writeLoop(ctx context.Context) {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()
	expiry := time.NewTimer(time.Until(c.expires))
	defer expiry.Stop()
	for {
		var f frame
		select {
		case <-ctx.Done():
			return
		case f = <-c.out:
		case f = <-c.backlog:
		case <-expiry.C:
			c.close(websocket.StatusPolicyViolation, "session expired")
			return
		case <-ticker.C:
			pctx, cancel := context.WithTimeout(ctx, writeTimeout)
			err := c.ws.Ping(pctx)
			cancel()
			if err != nil {
				c.close(websocket.StatusGoingAway, "ping timeout")
				return
			}
			continue
		}
		if err := writeJSON(ctx, c.ws, f); err != nil {
			c.close(websocket.StatusGoingAway, "write failed")
			return
		}
	}
}

func (c *conn) close(code websocket.StatusCode, reason string) {
	c.once.Do(func() {
		// Send the close frame first so the peer learns why; cancelling the
		// context first would tear the socket down without one.
		c.ws.Close(code, reason)
		c.cancel()
	})
}

func readJSON(ctx context.Context, ws *websocket.Conn, v any) error {
	typ, data, err := ws.Read(ctx)
	if err != nil {
		return err
	}
	if typ != websocket.MessageText {
		return errors.New("binary frames not supported")
	}
	return json.Unmarshal(data, v)
}

func writeJSON(ctx context.Context, ws *websocket.Conn, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	return ws.Write(wctx, websocket.MessageText, data)
}
