# DoomMsg

Private messenger with end-to-end encrypted chat, voice calls and video calls.
English and Persian (فارسی, full RTL) UI. Self-hosted, small, and built so the
server **cannot** read messages or listen to calls.

> **فارسی:** DoomMsg یک پیام‌رسان خصوصی با رمزنگاری سرتاسری برای پیام، تماس صوتی
> و تماس تصویری است. کلیدها فقط روی دستگاه کاربر ساخته و نگهداری می‌شوند و سرور
> تنها متن رمزشده را جابه‌جا می‌کند. رابط کاربری به‌طور کامل از فارسی و راست‌به‌چپ،
> اعداد فارسی و تقویم شمسی پشتیبانی می‌کند.

## Features

- **End-to-end encryption**: X3DH key agreement and the Double Ratchet (the
  Signal protocol design), built on audited `@noble` primitives. You get
  forward secrecy and post-compromise security.
- **Voice and HD video calls**: WebRTC with DTLS-SRTP. Call setup travels
  inside the encrypted channel, so the server can't intercept calls. Calls
  include mute, camera on/off, upgrading a voice call to video, front/back
  camera switching, ICE-restart recovery and a connection-quality indicator.
- **No phone number or email**: an account is a username bound to an identity
  key that never leaves the device. Login is challenge-response with no
  password, and the session token is kept in memory only.
- **Safety numbers**: 60-digit numbers you compare out of band to rule out a
  man-in-the-middle. The app warns you when a contact's key changes.
- **Disappearing messages**, delete-for-everyone, replies, typing indicators,
  and delivery and read receipts (you can turn these off).
- **Encrypted at rest**: local data is sealed with a non-extractable
  WebCrypto key.
- **Persian and English**: full RTL layout, Persian digits, Solar Hijri dates
  and the Vazirmatn font. Everything is bundled locally, with no CDNs and no
  trackers.
- **Built for operations**: distroless non-root image (about 28 MB), SQLite
  with no other dependencies, Prometheus metrics, health and readiness probes,
  JSON logs, graceful shutdown and rate limiting. Image registries are
  configurable so you can build from internal mirrors.

## Architecture

```
  Browser (PWA)                            Server side
 ┌──────────────────────────┐     TLS     ┌──────────────┐    ┌─────────────────────┐
 │ React UI (EN/FA)         │◀──────────▶│ Caddy        │──▶│ doommsg-server (Go) │
 │ X3DH + Double Ratchet    │  HTTPS/WSS  │ static + TLS │    │ • key directory     │
 │ IndexedDB (AES-GCM)      │             └──────────────┘    │ • ciphertext relay  │
 │ WebRTC (DTLS-SRTP)       │                                  │ • SQLite mailbox    │
 └───────────┬──────────────┘                                  └─────────────────────┘
             │  SRTP (encrypted media, P2P or relayed)
             ▼
        ┌─────────┐
        │ coturn  │  sees only encrypted packets; short-lived HMAC credentials
        └─────────┘
```

The server stores public keys, a SHA-256 hash of each session token, and
opaque envelopes, which it deletes once the recipient acknowledges them. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the protocol and
[SECURITY.md](SECURITY.md) for the threat model.

```
server/   Go relay: API, WebSocket hub, SQLite store, TURN credentials
web/      React + TypeScript client: crypto/, storage/, net/, calls/, i18n/, ui/
deploy/   docker-compose (Caddy + server + coturn), coturn config, .env example
```

## Quick start (development)

Requirements: Go 1.26+ and Node 22+.

```bash
make dev-server         # relay on :8080
make dev-web            # client on http://localhost:5173 (proxies /api)
```

Open two browser profiles (or a normal and a private window), create two
users and start chatting. Each window must be a separate browser profile,
because a profile can only have one active DoomMsg tab.

```bash
make test               # Go tests (-race) + crypto/storage/i18n unit tests
make e2e                # Playwright: 2 browsers, encrypted chat + video call
make lint
```

## Production deployment

```bash
cd deploy
cp .env.example .env    # set DOMAIN, TURN_EXTERNAL_IP, TURN secret (openssl rand -base64 48)
docker compose up -d --build
```

Open these ports: `80/tcp` and `443/tcp+udp` for Caddy (automatic Let's
Encrypt certificates), and `3478/tcp+udp` plus `49160-49200/udp` for TURN.

coturn is pinned to `172.30.0.10` on a `172.30.0.0/24` bridge network. That
lets it relay between two relayed clients through its own address while it
still refuses every other private address. If the subnet clashes with one
already in use on the host, change it in `docker-compose.yml` (the network,
coturn's address and the `--external-ip` suffix) and in `allowed-peer-ip` in
`coturn/turnserver.conf`.

To keep a server private, set `DOOMMSG_REGISTRATION_CODE`. New accounts then
need that invitation code.

### Server configuration

| Variable | Default | Purpose |
|---|---|---|
| `DOOMMSG_LISTEN` | `:8080` | API / WebSocket listener |
| `DOOMMSG_METRICS_LISTEN` | `127.0.0.1:9090` | `/metrics` + `/healthz` (empty disables it) |
| `DOOMMSG_DB` | `doommsg.db` | SQLite path |
| `DOOMMSG_TRUST_PROXY` | `false` | Use the right-most `X-Forwarded-For` for rate limiting |
| `DOOMMSG_ALLOWED_ORIGINS` | *(same-origin)* | Extra allowed browser origins |
| `DOOMMSG_REGISTRATION_CODE` | *(open)* | Invitation code required to register |
| `DOOMMSG_TURN_SECRET` | | coturn `static-auth-secret` (≥ 32 chars) |
| `DOOMMSG_TURN_URLS` / `DOOMMSG_STUN_URLS` | | ICE servers handed to clients |
| `DOOMMSG_TURN_TTL` | `12h` | TURN credential lifetime |
| `DOOMMSG_SESSION_TTL` | `720h` | Session token lifetime |
| `DOOMMSG_MAILBOX_TTL` | `720h` | How long undelivered envelopes are kept |
| `DOOMMSG_MAILBOX_MAX` | `10000` | Queued envelopes per recipient |
| `DOOMMSG_LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` |

**Endpoints:** `GET /healthz` (liveness), `GET /readyz` (checks the
database), `GET /metrics` (Prometheus, on the metrics listener).

**Metrics:** `doommsg_ws_connections`, `doommsg_envelopes_total{kind,outcome}`,
`doommsg_http_requests_total{route,code}`,
`doommsg_http_request_duration_seconds`, `doommsg_rate_limited_total` and
`doommsg_registrations_total`. Metrics never carry usernames.

**Backups:** the only state is the SQLite file in the `server-data` volume.
Use `sqlite3 doommsg.db ".backup out.db"` while the server is running. Losing
it costs public keys and messages not yet delivered. Message history lives
only on users' devices.

## Roadmap

- Group chats (sender keys / MLS) and encrypted attachments, voice notes and images
- Multi-device linking and an encrypted backup and restore
- Web Push notifications (the payload is only a wake-up signal) and native mobile wrappers
- Sealed sender, to hide the sender from the server
- Horizontal scaling: Postgres plus Redis pub/sub between relay replicas
- An external cryptographic audit

## License

Not yet specified. Add a `LICENSE` before distributing.
