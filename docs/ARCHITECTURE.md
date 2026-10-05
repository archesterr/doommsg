# Architecture and protocol

## Components

| Path | Role |
|---|---|
| `server/internal/api` | REST API: registration, challenge-response auth, key directory, TURN credentials |
| `server/internal/hub` | WebSocket relay: store-and-forward mailbox plus ephemeral delivery |
| `server/internal/store` | SQLite (WAL, `secure_delete`), migrations, purge |
| `web/src/crypto` | X3DH, Double Ratchet, session layer, padding, safety numbers |
| `web/src/storage` | IndexedDB, encrypted at rest; key store |
| `web/src/net` | REST client and resilient WebSocket transport |
| `web/src/state/messenger.ts` | Messaging engine: content protocol, receipts, timers, identity checks |
| `web/src/calls` | WebRTC call manager ("perfect negotiation") and synthesised tones |

## Registration and login

1. The client generates an identity (Ed25519 `IK_sig`, X25519 `IK_dh`), a
   signed prekey and 100 one-time prekeys.
2. `POST /api/v1/register` sends the public keys with these signatures:
   - `Sign(IK_sig, "DoomMsg/v1/identity-dh" ‖ IK_dh)`
   - `Sign(IK_sig, "DoomMsg/v1/register" ‖ username)`
   - `Sign(IK_sig, "DoomMsg/v1/signed-prekey" ‖ SPK)`
3. To log in, the client calls `POST /auth/challenge` and gets 32 random bytes,
   valid for 2 minutes and usable once. It then sends
   `Sign(IK_sig, "DoomMsg/v1/auth" ‖ challenge)` to `POST /auth/verify` and
   gets a bearer token. The server stores only `SHA-256(token)`.

## Session setup (X3DH)

Alice fetches Bob's bundle with `POST /users/bob/bundle`, which atomically
consumes one one-time prekey. She checks both signatures, then computes:

```
DH1 = DH(IK_dh_A, SPK_B)   DH2 = DH(EK_A, IK_dh_B)   DH3 = DH(EK_A, SPK_B)   [DH4 = DH(EK_A, OPK_B)]
SK  = HKDF-SHA256(salt=0³², ikm=0xFF³² ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4], info="DoomMsg/v1/x3dh")
AD  = IK_sig_A ‖ IK_dh_A ‖ IK_sig_B ‖ IK_dh_B
```

Alice keeps attaching the X3DH parameters (`x` below) to every message until
Bob replies. If both sides start a session at the same time, both sessions are
kept, and whichever one successfully decrypts gets promoted.

The sender identity in `x` is not trusted on its own. Bob checks it against
his pinned key only after the message decrypts, because only then is it
authenticated. A session is never promoted if it is bound to a different
identity than the current one. A prekey message whose base key belongs to an
existing session is rejected as a replay.

Deleting a chat removes its history and the contact, but keeps the ratchet
session, which the peer is still using. If the peer writes again, their
message is checked against the directory as a first contact and the chat
comes back. A blocked contact is kept, hidden from the chat list, so that
deleting the chat doesn't lift the block. The client only sends on a session
bound to the contact's pinned key. If the contact is added again with a
different key, a new session is started; the old one is not re-trusted.

## Double Ratchet

- `KDF_RK`: `HKDF(salt=RK, ikm=DH_out, info="DoomMsg/v1/ratchet") → RK', CK`
- `KDF_CK`: `MK = HMAC(CK, 0x01)`, `CK' = HMAC(CK, 0x02)`
- Encryption: `HKDF(MK, info="DoomMsg/v1/message-keys") → key(32) ‖ nonce(24)`,
  XChaCha20-Poly1305 with `AD ‖ header`
- Header: `DHs(32) ‖ PN(u32be) ‖ N(u32be)`, authenticated but not encrypted

## Wire envelope (all the server sees)

```json
{ "v": 1,
  "h": { "d": "<ratchet pub b64url>", "p": 3, "n": 0 },
  "c": "<ciphertext b64url>",
  "x": { "s": "<IK_sig>", "i": "<IK_dh>", "e": "<EK>", "k": 7, "o": 42 } }
```

## Inner content protocol (encrypted)

Before encryption, plaintext is JSON padded to 256-byte buckets:

| `t` | Meaning | Transport |
|---|---|---|
| `text` | Message (`id`, `body`, `exp`, `reply`) | stored |
| `receipt` | `delivered` / `read` for message ids | stored |
| `timer` | Disappearing-message setting | stored |
| `delete` | Delete for everyone; only the original sender can do this | stored |
| `typing` | Typing indicator | ephemeral |
| `call` | `offer` / `answer` / `ice` / `renegotiate` / `hangup` / `decline` / `busy` / `ringing` | ephemeral |

## Relay semantics

- Durable envelopes are written to the mailbox **before** delivery and
  deleted only when the recipient sends an `ack`, so delivery is
  at-least-once. Clients drop duplicates by the server id (`sid`, which is
  persisted before the ack) and by the message id.
- Each mailbox is capped by envelope count (`DOOMMSG_MAILBOX_MAX`) and by
  total bytes (`DOOMMSG_MAILBOX_MAX_BYTES`). A single sender may fill at most a
  tenth of a mailbox, so one account cannot lock everyone else out of it.
- On reconnect, the backlog drains alongside the read loop at the speed the
  client reads it. Acks are applied while the backlog is still being sent,
  and `synced` follows the last envelope that was queued when the
  connection registered. Envelopes queued after that are delivered live,
  and the backlog doesn't send them again.
- Ephemeral envelopes are delivered only to online recipients and are never
  written to disk. A send to an offline user fails with `offline`.
- Each account has one live connection. A newer connection replaces the
  older one, and the client uses a Web Lock so only one tab is active.
  Logging out closes the WebSocket that used that session. A connection also
  closes when its session expires.
- Rate limits: per IP for HTTP, tighter limits for auth and registration,
  bundle fetches limited per requester, and WebSocket frames limited per user.
  Acks have their own larger bucket. Acks over that limit are delayed, not
  dropped.

## Calls

1. The caller sends an `offer` (SDP) through the ratchet. The callee replies
   with `ringing`, and then with `answer` when the user accepts.
2. ICE candidates trickle through the encrypted channel and are buffered
   until the remote description is set.
3. Media is DTLS-SRTP, peer to peer when possible and relayed through TURN
   otherwise, or always relayed when "Always relay calls" is on. The DTLS
   fingerprints arrive only through the authenticated E2EE channel, so the
   relay cannot carry out a man-in-the-middle attack.
4. Mid-call renegotiation (turning on the camera, ICE restart) uses the
   perfect-negotiation pattern, with the callee as the polite peer.

## Scaling notes

A single relay instance comfortably holds tens of thousands of WebSocket
connections. To scale out horizontally:

- Replace SQLite with Postgres. The store layer is a single package.
- Fan out live deliveries between replicas over Redis pub/sub, keyed by
  recipient.
- Keep the mailbox as the source of truth. The reconnect flush already makes
  delivery idempotent.
