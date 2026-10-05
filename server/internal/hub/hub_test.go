package hub

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/time/rate"

	"github.com/archesterr/doommsg/server/internal/ratelimit"
	"github.com/archesterr/doommsg/server/internal/store"
)

// Acks beyond their own limit are delayed, not dropped: dropping one
// would leave the envelope queued and get it delivered again.
func TestAcksOverLimitAreDelayed(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	bob, err := st.CreateUser(ctx,
		store.User{Username: "bob", SigKey: []byte{1}, DHKey: []byte{2}, DHKeySig: []byte{3}},
		store.SignedPreKey{KeyID: 1, Pub: []byte{4}, Sig: []byte{5}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	const n = 30
	lim := store.MailboxLimits{Max: 1000, MaxBytes: 1 << 20}
	for range n {
		if _, _, err := st.Enqueue(ctx, bob, "alice", []byte("x"), time.Hour, lim); err != nil {
			t.Fatal(err)
		}
	}

	h := New(Options{
		Store: st,
		Auth: func(context.Context, string) (Session, error) {
			return Session{UserID: bob, Username: "bob", ExpiresAt: time.Now().Add(time.Hour)}, nil
		},
		MailboxTTL: time.Hour,
		Mailbox:    lim,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	h.ackLimiter = ratelimit.New(rate.Limit(100), 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ws, err := websocket.Accept(w, r, nil); err == nil {
			h.Accept(context.WithoutCancel(r.Context()), ws)
		}
	}))
	t.Cleanup(func() { h.Close(); srv.Close() })

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	if err := writeJSON(ctx, ws, frame{Type: "auth", Token: "t"}); err != nil {
		t.Fatal(err)
	}
	for {
		var f frame
		if err := readJSON(ctx, ws, &f); err != nil {
			t.Fatal(err)
		}
		if f.Type == "synced" {
			break
		}
		if f.Type == "msg" {
			if err := writeJSON(ctx, ws, frame{Type: "ack", IDs: []int64{f.SID}}); err != nil {
				t.Fatal(err)
			}
		}
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		envs, err := st.Pending(context.Background(), bob, 0, n)
		if err != nil {
			t.Fatal(err)
		}
		if len(envs) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d envelopes still queued", len(envs), n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
