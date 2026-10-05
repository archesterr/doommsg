# Security

## Reporting a vulnerability

Please do **not** open a public issue. Use GitHub's private vulnerability
reporting ("Security" → "Report a vulnerability") on this repository. We aim
to acknowledge within 72 hours.

## Status

DoomMsg's protocol follows the published Signal specifications (X3DH, Double
Ratchet) and uses audited primitives (`@noble/curves`, `@noble/hashes`,
`@noble/ciphers`, Go's standard library). **No independent audit of this
implementation has been done yet.** Until one is, treat it as
pre-production for high-risk use.

## Threat model

### What is protected

| Asset | Against | How |
|---|---|---|
| Message content | Server, network, TURN operator | X3DH + Double Ratchet, XChaCha20-Poly1305 with associated data that binds both identities |
| Past messages after a key leak | Device compromise later on | Forward secrecy: message keys are deleted after use and every ratchet step uses fresh DH |
| Future messages after a leak | Transient compromise | Post-compromise security through the DH ratchet |
| Call audio and video | Server, TURN, network | DTLS-SRTP. Fingerprints are exchanged only through the E2EE channel, so the server cannot substitute its own keys |
| Message length | Server | Plaintext is padded to 256-byte buckets before encryption |
| Identity | Impersonation by the server | Safety numbers, plus warnings when a key changes |
| Local data at rest | Disk theft, copied browser profiles | AES-256-GCM under a non-extractable WebCrypto key, with the record id bound as AAD |
| Login | Credential theft and replay | No passwords. Single-use, 2-minute challenges signed with the Ed25519 identity key. Only token hashes are stored server-side, and tokens are never persisted on the client |
| TURN abuse | SSRF and open relaying | Short-lived HMAC credentials, peers denied for private, loopback and link-local ranges (except coturn's own relay address, so two relayed clients can reach each other), quotas |
| Web client | XSS | Strict CSP with no inline script or style, Trusted Types (`'none'`), no `innerHTML` (enforced by lint), React escaping. Messages are always rendered as text |

### What is *not* protected (known limitations)

- **Metadata.** The relay knows who messages whom, when, and the padded
  sizes. It also learns IP addresses unless clients use Tor or a VPN. Sealed
  sender is on the roadmap. Logs are minimal: Caddy access logs are off and
  the relay doesn't log message routing.
- **Trust on first use.** Until you compare safety numbers, a malicious
  server could hand out a fake key the first time two users connect. Verify
  safety numbers for sensitive contacts.
- **Web delivery.** A web app is only as trustworthy as the server that
  serves its JavaScript. Someone who controls the web server could ship a
  backdoored client. Self-host it, pin the deployment, or package the client
  natively (roadmap).
- **Compromised device.** Malware or a malicious browser extension running
  in the page can read what you can read. The non-extractable key stops
  someone *copying* the key material, but not someone *using* it inside a
  live, compromised session.
- **Peer IP addresses.** Direct P2P calls reveal your IP address to the
  person you call. Turn on *Settings → Always relay calls* to route through
  TURN instead.
- **One device per account, no backup.** If you wipe the browser's data, the
  identity is gone. This is deliberate for now; multi-device support is on
  the roadmap.

## Cryptographic details

- Identity: an Ed25519 signing key plus an X25519 DH key. The DH key is
  signed by the signing key.
- Prekeys: a signed prekey rotated every 7 days (old ones are kept for 30
  days for messages still in flight), and 100 one-time prekeys refilled below
  25. The server hands out each one-time prekey at most once, and bundle
  fetches are rate-limited per requester.
- KDFs: HKDF-SHA-256 with versioned, domain-separated labels
  (`DoomMsg/v1/...`), and HMAC-SHA-256 chain keys.
- AEAD: XChaCha20-Poly1305. The key and nonce are derived per message from a
  single-use message key.
- At most 1000 skipped message keys per step and 2000 stored.
  Decryption is transactional, so a forged message can never corrupt
  session state.
- A peer's claimed identity is trusted only after its first message
  decrypts, and every later send and receive is checked against the pinned
  key. Messages are only sent on a session bound to the key the user is
  shown. A session bound to another key, for example after a chat is
  deleted and the contact added again, is abandoned rather than re-trusted. A replayed prekey message is rejected while the session it created is
  still among the last four kept for that contact. As in X3DH, a replay of an
  initial message sent without a one-time prekey is not detectable after
  that. Such a replay can only resend an old message and briefly switch the
  conversation to a stale session, which recovers with the peer's next
  message. It never reveals plaintext or keys.
- Every signature carries a domain-separation prefix, and the server checks
  each one. The prefixes are defined in `server/internal/api/api.go` and
  `web/src/crypto/protocol.ts`.

## Hardening checklist for operators

- Always run behind TLS. The provided Caddy config handles this and sends
  HSTS.
- Set `DOOMMSG_REGISTRATION_CODE` for private communities.
- Use a long random `DOOMMSG_TURN_SECRET` and rotate it periodically.
- Keep `DOOMMSG_METRICS_LISTEN` off the public network.
- Keep images up to date. Dependabot is configured for Go, npm, Actions and
  Docker.
