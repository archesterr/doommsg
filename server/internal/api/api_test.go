package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/archesterr/doommsg/server/internal/config"
	"github.com/archesterr/doommsg/server/internal/hub"
	"github.com/archesterr/doommsg/server/internal/store"
	"github.com/archesterr/doommsg/server/internal/validate"
)

type testEnv struct {
	t      *testing.T
	srv    *httptest.Server
	api    *Server
	dbPath string
}

func newEnv(t *testing.T, mutate func(*config.Config)) *testEnv {
	t.Helper()
	return newEnvAt(t, ":memory:", mutate)
}

// newFileEnv is newEnv with a database file that tests can also open
// directly (see openDB).
func newFileEnv(t *testing.T, mutate func(*config.Config)) *testEnv {
	t.Helper()
	return newEnvAt(t, filepath.Join(t.TempDir(), "doommsg.db"), mutate)
}

func newEnvAt(t *testing.T, dbPath string, mutate func(*config.Config)) *testEnv {
	t.Helper()
	cfg := &config.Config{
		SessionTTL:      time.Hour,
		MailboxTTL:      time.Hour,
		MailboxMax:      100,
		MailboxMaxBytes: 64 << 20,
		TURNTTL:         time.Hour,
	}
	if mutate != nil {
		mutate(cfg)
	}
	st, err := store.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	a := New(cfg, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(func() { a.Hub().Close(); srv.Close() })
	return &testEnv{t: t, srv: srv, api: a, dbPath: dbPath}
}

// openDB opens a second connection pool to a newFileEnv database.
func (e *testEnv) openDB() *sql.DB {
	e.t.Helper()
	db, err := sql.Open("sqlite", "file:"+e.dbPath+"?_pragma=busy_timeout(10000)")
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { db.Close() })
	return db
}

type account struct {
	name  string
	sig   ed25519.PrivateKey
	token string
}

func randKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return validate.B64(b)
}

func sign(k ed25519.PrivateKey, prefix string, msg []byte) string {
	return validate.B64(ed25519.Sign(k, concat(prefix, msg)))
}

func (e *testEnv) do(method, path, token string, body any) (int, map[string]any) {
	e.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (e *testEnv) registerReq(name string, sig ed25519.PrivateKey, otks int) map[string]any {
	pub := sig.Public().(ed25519.PublicKey)
	dh := make([]byte, 32)
	rand.Read(dh)
	spk := make([]byte, 32)
	rand.Read(spk)
	keys := []map[string]any{}
	for i := 0; i < otks; i++ {
		keys = append(keys, map[string]any{"keyId": i + 1, "pub": randKey()})
	}
	return map[string]any{
		"username":       name,
		"sigKey":         validate.B64(pub),
		"dhKey":          validate.B64(dh),
		"dhKeySig":       sign(sig, ctxIdentityDH, dh),
		"registerSig":    sign(sig, ctxRegister, []byte(name)),
		"signedPreKey":   map[string]any{"keyId": 1, "pub": validate.B64(spk), "sig": sign(sig, ctxSignedPre, spk)},
		"oneTimePreKeys": keys,
	}
}

func (e *testEnv) newAccount(name string, otks int) *account {
	e.t.Helper()
	_, sig, _ := ed25519.GenerateKey(rand.Reader)
	if code, body := e.do("POST", "/api/v1/register", "", e.registerReq(name, sig, otks)); code != http.StatusCreated {
		e.t.Fatalf("register %s: %d %v", name, code, body)
	}
	a := &account{name: name, sig: sig}
	a.token = e.login(a)
	return a
}

func (e *testEnv) login(a *account) string {
	e.t.Helper()
	code, ch := e.do("POST", "/api/v1/auth/challenge", "", map[string]any{"username": a.name})
	if code != 200 {
		e.t.Fatalf("challenge: %d", code)
	}
	c, _ := validate.Key32(ch["challenge"].(string))
	code, v := e.do("POST", "/api/v1/auth/verify", "", map[string]any{
		"username": a.name, "challenge": ch["challenge"], "signature": sign(a.sig, ctxAuth, c),
	})
	if code != 200 {
		e.t.Fatalf("verify: %d %v", code, v)
	}
	return v["token"].(string)
}

func TestRegisterValidation(t *testing.T) {
	e := newEnv(t, nil)
	_, sig, _ := ed25519.GenerateKey(rand.Reader)

	bad := e.registerReq("Bad Name", sig, 0)
	if code, _ := e.do("POST", "/api/v1/register", "", bad); code != http.StatusBadRequest {
		t.Fatalf("bad username accepted: %d", code)
	}

	forged := e.registerReq("alice", sig, 0)
	forged["dhKey"] = randKey() // signature no longer matches
	if code, _ := e.do("POST", "/api/v1/register", "", forged); code != http.StatusBadRequest {
		t.Fatalf("forged dh key accepted: %d", code)
	}

	unknown := e.registerReq("alice", sig, 0)
	unknown["extra"] = true
	if code, _ := e.do("POST", "/api/v1/register", "", unknown); code != http.StatusBadRequest {
		t.Fatalf("unknown field accepted: %d", code)
	}

	e.newAccount("alice", 0)
	if code, _ := e.do("POST", "/api/v1/register", "", e.registerReq("alice", sig, 0)); code != http.StatusConflict {
		t.Fatalf("duplicate username: %d", code)
	}
}

func TestRegistrationCode(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.RegistrationCode = "s3cret" })
	_, sig, _ := ed25519.GenerateKey(rand.Reader)
	req := e.registerReq("bob", sig, 0)
	if code, _ := e.do("POST", "/api/v1/register", "", req); code != http.StatusForbidden {
		t.Fatalf("missing code: %d", code)
	}
	req["registrationCode"] = "s3cret"
	if code, _ := e.do("POST", "/api/v1/register", "", req); code != http.StatusCreated {
		t.Fatalf("valid code: %d", code)
	}
}

func TestAuthChallengeIsSingleUseAndBound(t *testing.T) {
	e := newEnv(t, nil)
	a := e.newAccount("alice", 0)
	e.newAccount("mallory", 0)

	_, ch := e.do("POST", "/api/v1/auth/challenge", "", map[string]any{"username": "alice"})
	c, _ := validate.Key32(ch["challenge"].(string))
	body := map[string]any{"username": "alice", "challenge": ch["challenge"], "signature": sign(a.sig, ctxAuth, c)}
	if code, _ := e.do("POST", "/api/v1/auth/verify", "", body); code != 200 {
		t.Fatalf("first use: %d", code)
	}
	if code, _ := e.do("POST", "/api/v1/auth/verify", "", body); code != http.StatusUnauthorized {
		t.Fatalf("replayed challenge accepted: %d", code)
	}

	// A challenge issued for alice cannot be redeemed as mallory.
	_, ch = e.do("POST", "/api/v1/auth/challenge", "", map[string]any{"username": "alice"})
	c, _ = validate.Key32(ch["challenge"].(string))
	body = map[string]any{"username": "mallory", "challenge": ch["challenge"], "signature": sign(a.sig, ctxAuth, c)}
	if code, _ := e.do("POST", "/api/v1/auth/verify", "", body); code != http.StatusUnauthorized {
		t.Fatalf("cross-user challenge accepted: %d", code)
	}

	// Unknown users still get a challenge (no enumeration).
	if code, _ := e.do("POST", "/api/v1/auth/challenge", "", map[string]any{"username": "nobody"}); code != 200 {
		t.Fatalf("unknown user challenge: %d", code)
	}

	if code, _ := e.do("GET", "/api/v1/keys", "garbage", nil); code != http.StatusUnauthorized {
		t.Fatalf("bad token accepted: %d", code)
	}
	if code, _ := e.do("POST", "/api/v1/auth/logout", a.token, nil); code != http.StatusNoContent {
		t.Fatalf("logout: %d", code)
	}
	if code, _ := e.do("GET", "/api/v1/keys", a.token, nil); code != http.StatusUnauthorized {
		t.Fatalf("token valid after logout: %d", code)
	}
}

func TestBundleConsumesOneTimePreKeys(t *testing.T) {
	e := newEnv(t, nil)
	a := e.newAccount("alice", 0)
	e.newAccount("bob", 2)

	seen := map[float64]bool{}
	for i := 0; i < 2; i++ {
		code, b := e.do("POST", "/api/v1/users/bob/bundle", a.token, nil)
		if code != 200 {
			t.Fatalf("bundle: %d", code)
		}
		otk, ok := b["oneTimePreKey"].(map[string]any)
		if !ok {
			t.Fatalf("bundle %d missing one-time prekey", i)
		}
		id := otk["keyId"].(float64)
		if seen[id] {
			t.Fatalf("one-time prekey %v handed out twice", id)
		}
		seen[id] = true
	}
	_, b := e.do("POST", "/api/v1/users/bob/bundle", a.token, nil)
	if _, ok := b["oneTimePreKey"]; ok {
		t.Fatal("expected exhausted one-time prekeys")
	}
	if _, ok := b["signedPreKey"]; !ok {
		t.Fatal("signed prekey missing")
	}
	if code, _ := e.do("POST", "/api/v1/users/nobody/bundle", a.token, nil); code != http.StatusNotFound {
		t.Fatalf("unknown user: %d", code)
	}
}

func (e *testEnv) dial(token string) *websocket.Conn {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	url := "ws" + strings.TrimPrefix(e.srv.URL, "http") + "/api/v1/ws"
	ws, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: http.Header{"Origin": {e.srv.URL}}})
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { ws.CloseNow() })
	send(e.t, ws, frame{"type": "auth", "token": token})
	if f := recv(e.t, ws); f["type"] != "ready" {
		e.t.Fatalf("expected ready, got %v", f)
	}
	return ws
}

type frame map[string]any

func send(t *testing.T, ws *websocket.Conn, f frame) {
	t.Helper()
	b, _ := json.Marshal(f)
	if err := ws.Write(context.Background(), websocket.MessageText, b); err != nil {
		t.Fatal(err)
	}
}

func recv(t *testing.T, ws *websocket.Conn) frame {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, b, err := ws.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var f frame
	json.Unmarshal(b, &f)
	return f
}

// expectClose reads until the server closes ws and checks the status.
func expectClose(t *testing.T, ws *websocket.Conn, want websocket.StatusCode, within time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), within)
	defer cancel()
	for {
		if _, _, err := ws.Read(ctx); err != nil {
			if got := websocket.CloseStatus(err); got != want {
				t.Fatalf("close status %v, want %v: %v", got, want, err)
			}
			return
		}
	}
}

// fill queues n envelopes for username in a newFileEnv database and
// returns the recipient's id. It inserts them in one transaction, since
// going through Enqueue one by one is slow under the race detector.
func (e *testEnv) fill(username string, n int, payload string) int64 {
	e.t.Helper()
	u, err := e.api.store.UserByName(context.Background(), username)
	if err != nil {
		e.t.Fatal(err)
	}
	tx, err := e.openDB().Begin()
	if err != nil {
		e.t.Fatal(err)
	}
	defer tx.Rollback()
	now := time.Now()
	for range n {
		if _, err := tx.Exec(
			`INSERT INTO mailbox (recipient_id, sender, payload, created_at, expires_at) VALUES (?, 'alice', ?, ?, ?)`,
			u.ID, []byte(payload), now.UnixMilli(), now.Add(time.Hour).Unix()); err != nil {
			e.t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		e.t.Fatal(err)
	}
	return u.ID
}

// waitMailbox waits until the user with id uid has want queued envelopes.
func (e *testEnv) waitMailbox(uid int64, want int) {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		envs, err := e.api.store.Pending(context.Background(), uid, 0, 1<<20)
		if err != nil {
			e.t.Fatal(err)
		}
		if len(envs) == want {
			return
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("mailbox holds %d envelopes, want %d", len(envs), want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestRelayStoreAndForward(t *testing.T) {
	e := newEnv(t, nil)
	alice := e.newAccount("alice", 0)
	bob := e.newAccount("bob", 0)

	aw := e.dial(alice.token)
	if f := recv(t, aw); f["type"] != "synced" {
		t.Fatalf("expected synced, got %v", f)
	}

	// Bob is offline: durable messages are queued, ephemeral ones refused.
	send(t, aw, frame{"type": "send", "id": "m1", "to": "bob", "payload": "ciphertext-1"})
	if f := recv(t, aw); f["type"] != "sent" || f["id"] != "m1" || f["sid"] == nil {
		t.Fatalf("unexpected %v", f)
	}
	send(t, aw, frame{"type": "send", "id": "e1", "to": "bob", "payload": "ring", "eph": true})
	if f := recv(t, aw); f["type"] != "error" || f["code"] != "offline" {
		t.Fatalf("ephemeral to offline user: %v", f)
	}

	// Bob connects and receives the queued message with an authenticated sender.
	bw := e.dial(bob.token)
	f := recv(t, bw)
	if f["type"] != "msg" || f["from"] != "alice" || f["payload"] != "ciphertext-1" {
		t.Fatalf("queued delivery: %v", f)
	}
	sid := f["sid"]
	if f := recv(t, bw); f["type"] != "synced" {
		t.Fatalf("expected synced, got %v", f)
	}
	send(t, bw, frame{"type": "ack", "ids": []any{sid}})

	// Live delivery, both durable and ephemeral.
	send(t, aw, frame{"type": "send", "id": "m2", "to": "bob", "payload": "ciphertext-2"})
	recv(t, aw)
	if f := recv(t, bw); f["payload"] != "ciphertext-2" {
		t.Fatalf("live delivery: %v", f)
	}
	send(t, aw, frame{"type": "send", "id": "e2", "to": "bob", "payload": "ring", "eph": true})
	recv(t, aw)
	if f := recv(t, bw); f["payload"] != "ring" || f["eph"] != true {
		t.Fatalf("ephemeral delivery: %v", f)
	}

	// Reconnect: only the unacked message is redelivered.
	bw.Close(websocket.StatusNormalClosure, "")
	bw = e.dial(bob.token)
	if f := recv(t, bw); f["payload"] != "ciphertext-2" {
		t.Fatalf("redelivery: %v", f)
	}
	if f := recv(t, bw); f["type"] != "synced" {
		t.Fatalf("expected synced, got %v", f)
	}

	// Validation.
	send(t, aw, frame{"type": "send", "id": "x", "to": "alice", "payload": "self"})
	if f := recv(t, aw); f["code"] != "bad_recipient" {
		t.Fatalf("self-send: %v", f)
	}
	send(t, aw, frame{"type": "send", "id": "y", "to": "ghost", "payload": "p"})
	if f := recv(t, aw); f["code"] != "no_such_user" {
		t.Fatalf("unknown recipient: %v", f)
	}
}

func TestWebSocketRejectsBadAuthAndForeignOrigin(t *testing.T) {
	e := newEnv(t, nil)
	url := "ws" + strings.TrimPrefix(e.srv.URL, "http") + "/api/v1/ws"
	ctx := context.Background()

	if _, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{
		HTTPHeader: http.Header{"Origin": {"https://evil.example"}},
	}); err == nil {
		t.Fatal("cross-origin websocket accepted")
	}

	ws, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: http.Header{"Origin": {e.srv.URL}}})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	send(t, ws, frame{"type": "auth", "token": "nope"})
	if f := recv(t, ws); f["code"] != "unauthorized" {
		t.Fatalf("bad token: %v", f)
	}
}

func TestNewConnectionReplacesOld(t *testing.T) {
	e := newEnv(t, nil)
	a := e.newAccount("alice", 0)
	first := e.dial(a.token)
	recv(t, first) // synced
	second := e.dial(a.token)
	recv(t, second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := first.Read(ctx)
	if websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("old connection not replaced: %v", err)
	}
}

// A backlog far larger than the live send buffer drains in one connection,
// with "synced" after the last envelope, and acks sent while it drains are
// applied.
func TestLargeBacklogSyncs(t *testing.T) {
	e := newFileEnv(t, nil)
	bob := e.newAccount("bob", 0)
	const n = 1500
	uid := e.fill("bob", n, strings.Repeat("A", 2000))

	bw := e.dial(bob.token)
	var got, batch []any
	for {
		f := recv(t, bw)
		if f["type"] == "synced" {
			break
		}
		if f["type"] != "msg" {
			t.Fatalf("after %d envelopes: unexpected %v", len(got), f)
		}
		got = append(got, f["sid"])
		if batch = append(batch, f["sid"]); len(batch) == 100 {
			send(t, bw, frame{"type": "ack", "ids": batch})
			batch = nil
		}
	}
	if len(got) != n {
		t.Fatalf("synced after %d of %d envelopes", len(got), n)
	}
	send(t, bw, frame{"type": "ack", "ids": batch})
	e.waitMailbox(uid, 0)
}

// Envelopes sent while a backlog drains reach the recipient once, live,
// and not a second time at the end of the flush.
func TestFlushSkipsEnvelopesDeliveredLive(t *testing.T) {
	e := newFileEnv(t, func(c *config.Config) { c.MailboxMax = 10000 })
	carol := e.newAccount("carol", 0)
	bob := e.newAccount("bob", 0)
	const backlog, live = 600, 20
	e.fill("bob", backlog, strings.Repeat("A", 2000)) // from alice

	aw := e.dial(carol.token)
	recv(t, aw) // synced
	bw := e.dial(bob.token)
	first := recv(t, bw) // the flush has started
	if first["type"] != "msg" {
		t.Fatalf("expected the backlog, got %v", first)
	}
	for i := range live {
		send(t, aw, frame{"type": "send", "id": fmt.Sprint("m", i), "to": "bob", "payload": "live"})
		if f := recv(t, aw); f["type"] != "sent" {
			t.Fatalf("send %d: %v", i, f)
		}
	}

	seen := map[any]int{first["sid"]: 1}
	synced := false
	for !synced || len(seen) < backlog+live {
		f := recv(t, bw)
		switch f["type"] {
		case "synced":
			synced = true
		case "msg":
			seen[f["sid"]]++
		default:
			t.Fatalf("unexpected %v", f)
		}
	}
	for sid, n := range seen {
		if n > 1 {
			t.Errorf("envelope %v delivered %d times", sid, n)
		}
	}
	if len(seen) != backlog+live {
		t.Fatalf("got %d envelopes, want %d", len(seen), backlog+live)
	}
}

// Acks are not charged to the send limiter: a client that acks a backlog
// one envelope at a time, far past the send burst, loses none of them.
func TestAcksAreNotRateLimited(t *testing.T) {
	e := newFileEnv(t, nil)
	bob := e.newAccount("bob", 0)
	uid := e.fill("bob", 300, "x")

	bw := e.dial(bob.token)
	for {
		f := recv(t, bw)
		if f["type"] == "synced" {
			break
		}
		send(t, bw, frame{"type": "ack", "ids": []any{f["sid"]}})
	}
	e.waitMailbox(uid, 0)

	// Everything else is still limited.
	const pings = 200
	for range pings {
		send(t, bw, frame{"type": "ping"})
	}
	limited := 0
	for range pings {
		if f := recv(t, bw); f["code"] == "rate_limited" {
			limited++
		} else if f["type"] != "pong" {
			t.Fatalf("unexpected %v", f)
		}
	}
	if limited == 0 {
		t.Fatal("ping flood was not rate limited")
	}
}

// A recipient who connects while a send is still waiting to commit gets
// the envelope live once it commits; it was not in the mailbox flush.
func TestLiveDeliveryWhileEnqueueWaits(t *testing.T) {
	e := newFileEnv(t, nil)
	alice := e.newAccount("alice", 0)
	bob := e.newAccount("bob", 0)
	aw := e.dial(alice.token)
	recv(t, aw) // synced

	// Hold the write lock so alice's send blocks inside Enqueue.
	ctx := context.Background()
	lock, err := e.openDB().Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if _, err := lock.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	send(t, aw, frame{"type": "send", "id": "m1", "to": "bob", "payload": "hello"})
	time.Sleep(300 * time.Millisecond) // until the send waits on the lock

	bw := e.dial(bob.token)
	if f := recv(t, bw); f["type"] != "synced" {
		t.Fatalf("expected synced, got %v", f)
	}
	if _, err := lock.ExecContext(ctx, "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	if f := recv(t, aw); f["type"] != "sent" {
		t.Fatalf("expected sent, got %v", f)
	}
	if f := recv(t, bw); f["type"] != "msg" || f["payload"] != "hello" {
		t.Fatalf("live delivery: %v", f)
	}
}

func TestLogoutClosesThatSessionsWebSocket(t *testing.T) {
	e := newEnv(t, nil)
	alice := e.newAccount("alice", 0)
	e.newAccount("bob", 0)
	other := e.login(alice)
	aw := e.dial(alice.token)
	recv(t, aw) // synced

	// Ending another session of the same account leaves this one alone.
	if code, _ := e.do("POST", "/api/v1/auth/logout", other, nil); code != http.StatusNoContent {
		t.Fatalf("logout: %d", code)
	}
	send(t, aw, frame{"type": "send", "id": "m1", "to": "bob", "payload": "p"})
	if f := recv(t, aw); f["type"] != "sent" {
		t.Fatalf("expected sent, got %v", f)
	}

	if code, _ := e.do("POST", "/api/v1/auth/logout", alice.token, nil); code != http.StatusNoContent {
		t.Fatalf("logout: %d", code)
	}
	expectClose(t, aw, websocket.StatusPolicyViolation, 5*time.Second)
}

func TestSessionExpiryClosesWebSocket(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.SessionTTL = 3 * time.Second })
	alice := e.newAccount("alice", 0)
	aw := e.dial(alice.token)
	recv(t, aw) // synced
	expectClose(t, aw, websocket.StatusPolicyViolation, 6*time.Second)
}

// One sender cannot fill a mailbox and lock everyone else out of it.
func TestMailboxSenderShare(t *testing.T) {
	e := newEnv(t, nil) // MailboxMax 100: one sender may queue 10
	alice := e.newAccount("alice", 0)
	carol := e.newAccount("carol", 0)
	e.newAccount("bob", 0)
	aw := e.dial(alice.token)
	recv(t, aw) // synced

	big := strings.Repeat("A", hub.MaxPayloadBytes)
	sent := 0
	for i := range 100 {
		send(t, aw, frame{"type": "send", "id": fmt.Sprint(i), "to": "bob", "payload": big})
		f := recv(t, aw)
		if f["code"] == "mailbox_full" {
			break
		}
		if f["type"] != "sent" {
			t.Fatalf("unexpected %v", f)
		}
		sent++
	}
	if sent != 10 {
		t.Fatalf("one sender queued %d envelopes, want 10", sent)
	}

	cw := e.dial(carol.token)
	recv(t, cw) // synced
	send(t, cw, frame{"type": "send", "id": "c1", "to": "bob", "payload": "hi"})
	if f := recv(t, cw); f["type"] != "sent" {
		t.Fatalf("other sender locked out: %v", f)
	}
}

func TestDeleteAccount(t *testing.T) {
	e := newEnv(t, nil)
	a := e.newAccount("alice", 3)
	b := e.newAccount("bob", 0)
	if code, _ := e.do("DELETE", "/api/v1/account", a.token, nil); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := e.do("GET", "/api/v1/users/alice", b.token, nil); code != http.StatusNotFound {
		t.Fatalf("deleted user still visible: %d", code)
	}
	if code, _ := e.do("GET", "/api/v1/keys", a.token, nil); code != http.StatusUnauthorized {
		t.Fatalf("session survived deletion: %d", code)
	}
}

func TestTURNCredentials(t *testing.T) {
	e := newEnv(t, func(c *config.Config) {
		c.TURNSecret = strings.Repeat("x", 32)
		c.TURNURLs = []string{"turn:turn.example:3478"}
	})
	a := e.newAccount("alice", 0)
	code, body := e.do("GET", "/api/v1/turn", a.token, nil)
	if code != 200 {
		t.Fatalf("turn: %d", code)
	}
	servers := body["iceServers"].([]any)
	if len(servers) != 1 {
		t.Fatalf("servers: %v", servers)
	}
	s := servers[0].(map[string]any)
	if !strings.HasSuffix(s["username"].(string), ":alice") || s["credential"] == "" {
		t.Fatalf("bad credential: %v", s)
	}
}

func TestPreKeyReplenishmentLimits(t *testing.T) {
	e := newEnv(t, nil)
	a := e.newAccount("alice", 0)
	keys := make([]map[string]any, 0, 100)
	for i := 0; i < 100; i++ {
		keys = append(keys, map[string]any{"keyId": i, "pub": randKey()})
	}
	for i := 0; i < 5; i++ {
		for j := range keys {
			keys[j]["keyId"] = i*100 + j
		}
		if code, body := e.do("POST", "/api/v1/keys/one-time", a.token, map[string]any{"keys": keys}); code != http.StatusNoContent {
			t.Fatalf("batch %d: %d %v", i, code, body)
		}
	}
	if code, _ := e.do("POST", "/api/v1/keys/one-time", a.token, map[string]any{"keys": keys[:1]}); code != http.StatusBadRequest {
		t.Fatalf("exceeded max prekeys: %d", code)
	}
	_, st := e.do("GET", "/api/v1/keys", a.token, nil)
	if st["oneTimePreKeys"].(float64) != store.MaxOneTimePreKeys {
		t.Fatalf("count: %v", st)
	}

	// A signed prekey must be signed by the account's identity key.
	pub := make([]byte, 32)
	rand.Read(pub)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	body := map[string]any{"keyId": 2, "pub": validate.B64(pub), "sig": sign(other, ctxSignedPre, pub)}
	if code, _ := e.do("PUT", "/api/v1/keys/signed", a.token, body); code != http.StatusBadRequest {
		t.Fatalf("foreign-signed prekey accepted: %d", code)
	}
	body["sig"] = sign(a.sig, ctxSignedPre, pub)
	if code, _ := e.do("PUT", "/api/v1/keys/signed", a.token, body); code != http.StatusNoContent {
		t.Fatalf("rotate signed prekey: %d", code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	e := newEnv(t, nil)
	resp, err := http.Get(e.srv.URL + "/api/v1/info")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for h, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"Cache-Control":          "no-store",
		"X-Frame-Options":        "DENY",
	} {
		if got := resp.Header.Get(h); got != want {
			t.Errorf("%s = %q, want %q", h, got, want)
		}
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("unexpected CORS header %q", got)
	}
	_ = fmt.Sprint()
}
