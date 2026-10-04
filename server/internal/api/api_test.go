package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/archesterr/doommsg/server/internal/config"
	"github.com/archesterr/doommsg/server/internal/store"
	"github.com/archesterr/doommsg/server/internal/validate"
)

type testEnv struct {
	t   *testing.T
	srv *httptest.Server
	api *Server
}

func newEnv(t *testing.T, mutate func(*config.Config)) *testEnv {
	t.Helper()
	cfg := &config.Config{
		SessionTTL: time.Hour,
		MailboxTTL: time.Hour,
		MailboxMax: 100,
		TURNTTL:    time.Hour,
	}
	if mutate != nil {
		mutate(cfg)
	}
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	a := New(cfg, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(func() { a.Hub().Close(); srv.Close() })
	return &testEnv{t: t, srv: srv, api: a}
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
