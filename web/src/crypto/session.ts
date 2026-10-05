// Session layer: turns X3DH + Double Ratchet into "encrypt to user" /
// "decrypt from user", handling session setup, simultaneous initiation and
// the wire envelope format. The server only ever sees these envelopes.

import { b64, equal, unb64, unb64n } from './bytes';
import { pad, unpad } from './padding';
import type { Identity, KeyPair, PublicIdentity } from './protocol';
import { decrypt, encrypt, initAlice, initBob, type Header, type RatchetState } from './ratchet';
import { initiate, respond, type PreKeyBundle } from './x3dh';

export interface Session {
  state: RatchetState;
  /** Canonical b64 of the X3DH ephemeral key that created the session. */
  baseKey: string;
  peer: PublicIdentity;
  /** Set on initiator sessions until the peer has answered. */
  pending?: { ek: string; spk: number; opk?: number };
}

export interface SessionRecord {
  current?: Session;
  /** Older sessions kept briefly for messages still in flight. */
  previous: Session[];
}

export interface KeyStore {
  identity(): Promise<Identity>;
  signedPreKey(id: number): Promise<KeyPair | undefined>;
  oneTimePreKey(id: number): Promise<KeyPair | undefined>;
  removeOneTimePreKey(id: number): Promise<void>;
  loadSession(peer: string): Promise<SessionRecord | undefined>;
  saveSession(peer: string, rec: SessionRecord): Promise<void>;
  deleteSession(peer: string): Promise<void>;
}

export interface SessionHooks {
  fetchBundle(peer: string): Promise<PreKeyBundle>;
  /**
   * Called with the identity a session is bound to whenever that session is
   * about to be used: a verified bundle before initiating, a peer-initiated
   * session once its first message has decrypted, and an existing session
   * on every send and receive. The identity is always authenticated for the
   * session. Throw to refuse it: nothing is persisted and the error is
   * passed through unchanged.
   */
  checkIdentity(peer: string, identity: PublicIdentity): Promise<void>;
  /**
   * The identity the user currently trusts for `peer`, if any. A session
   * bound to another identity is not sent on: a new one is started from the
   * peer's current bundle instead.
   */
  trustedIdentity?(peer: string): PublicIdentity | undefined;
}

const MAX_PREVIOUS = 3;
const VERSION = 1;

interface WireEnvelope {
  v: number;
  h: { d: string; p: number; n: number };
  c: string;
  x?: { s: string; i: string; e: string; k: number; o?: number };
}

/** A decoded envelope. */
interface Envelope {
  header: Header;
  ct: Uint8Array;
  x?: { peer: PublicIdentity; ek: Uint8Array; baseKey: string; spk: number; opk?: number };
}

export class DecryptError extends Error {}

/** Serialises async work per key so ratchet state is never raced. */
class KeyedMutex {
  private tails = new Map<string, Promise<unknown>>();
  run<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.tails.get(key) ?? Promise.resolve();
    const next = prev.then(fn, fn);
    const tail = next.catch(() => undefined);
    this.tails.set(key, tail);
    void tail.then(() => {
      if (this.tails.get(key) === tail) this.tails.delete(key);
    });
    return next;
  }
}

export class SessionCipher {
  private lock = new KeyedMutex();

  constructor(
    private store: KeyStore,
    private hooks: SessionHooks,
  ) {}

  hasSession(peer: string): Promise<boolean> {
    return this.store.loadSession(peer).then((r) => !!r?.current);
  }

  reset(peer: string): Promise<void> {
    return this.lock.run(peer, () => this.store.deleteSession(peer));
  }

  encrypt(peer: string, plaintext: Uint8Array): Promise<string> {
    return this.lock.run(peer, async () => {
      const rec = (await this.store.loadSession(peer)) ?? { previous: [] };
      // Only ever send to the identity the user is shown (and may verify).
      // A session bound to another one (say the chat was deleted and the
      // contact added again with a new key) is abandoned, not re-trusted.
      const trusted = this.hooks.trustedIdentity?.(peer);
      if (rec.current && trusted && !sameIdentity(rec.current.peer, trusted)) rec.current = undefined;
      if (rec.current) await this.hooks.checkIdentity(peer, rec.current.peer);
      else {
        const s = await this.startSession(peer);
        // Sessions with any other identity are dead, as on the receiving side.
        rec.previous = rec.previous.filter((p) => sameIdentity(p.peer, s.peer)).slice(0, MAX_PREVIOUS);
        rec.current = s;
      }
      const s = rec.current;
      const { header, ciphertext } = encrypt(s.state, pad(plaintext));
      const env: WireEnvelope = {
        v: VERSION,
        h: { d: b64(header.dh), p: header.pn, n: header.n },
        c: b64(ciphertext),
      };
      if (s.pending) {
        const me = await this.store.identity();
        env.x = { s: b64(me.sig.pub), i: b64(me.dh.pub), e: s.pending.ek, k: s.pending.spk, o: s.pending.opk };
      }
      await this.store.saveSession(peer, rec);
      return JSON.stringify(env);
    });
  }

  decrypt(peer: string, payload: string): Promise<Uint8Array> {
    return this.lock.run(peer, async () => {
      const { header, ct, x } = parseEnvelope(payload);
      const rec = (await this.store.loadSession(peer)) ?? { previous: [] };
      const sessions = [rec.current, ...rec.previous].filter((s): s is Session => !!s);

      // Messages on an existing session (including resent prekey messages).
      // An older session bound to another identity than the current one is
      // never revived: that would silently undo an identity change.
      const candidates = sessions.filter(
        (s) => (!x || s.baseKey === x.baseKey) && (!rec.current || sameIdentity(s.peer, rec.current.peer)),
      );
      for (const s of candidates) {
        let result: ReturnType<typeof decrypt>;
        try {
          result = decrypt(s.state, header, ct);
        } catch {
          continue; // decrypt is pure: any failure means "not this session"
        }
        const plaintext = unpadded(result.plaintext);
        await this.hooks.checkIdentity(peer, s.peer);
        s.state = result.state;
        delete s.pending; // the peer evidently has this session
        promote(rec, s);
        await this.store.saveSession(peer, rec);
        return plaintext;
      }
      if (!x) throw new DecryptError('no session can decrypt this message');
      // The session this message started exists but rejected it above: it is
      // a replay. Without a one-time prekey it would otherwise set up the
      // same session again and displace the live one.
      if (sessions.some((s) => s.baseKey === x.baseKey)) throw new DecryptError('duplicate prekey message');

      // A new session initiated by the peer.
      const me = await this.store.identity();
      const spk = await this.store.signedPreKey(x.spk);
      if (!spk) throw new DecryptError('unknown signed prekey');
      let opk: KeyPair | undefined;
      if (x.opk !== undefined) {
        opk = await this.store.oneTimePreKey(x.opk);
        if (!opk) throw new DecryptError('one-time prekey already used');
      }
      let result: ReturnType<typeof decrypt>;
      try {
        const { sk, ad } = respond(me, spk, opk, x.peer, x.ek);
        result = decrypt(initBob(sk, spk, ad), header, ct);
      } catch {
        throw new DecryptError('prekey message failed to decrypt');
      }
      const plaintext = unpadded(result.plaintext);
      // Only now is the claimed identity authenticated (DH1 uses it and the
      // AD binds it), so this is the earliest point it may be trusted.
      await this.hooks.checkIdentity(peer, x.peer);
      // Sessions with any other identity are dead: never fall back to them.
      rec.previous = sessions.filter((s) => sameIdentity(s.peer, x.peer)).slice(0, MAX_PREVIOUS);
      rec.current = { state: result.state, baseKey: x.baseKey, peer: x.peer };
      await this.store.saveSession(peer, rec);
      if (x.opk !== undefined) await this.store.removeOneTimePreKey(x.opk);
      return plaintext;
    });
  }

  private async startSession(peer: string): Promise<Session> {
    const bundle = await this.hooks.fetchBundle(peer);
    const me = await this.store.identity();
    const x = initiate(me, bundle); // verifies the bundle's signatures first
    const identity = { sigKey: bundle.sigKey, dhKey: bundle.dhKey };
    await this.hooks.checkIdentity(peer, identity);
    return {
      state: initAlice(x.sk, x.signedPreKeyPub, x.ad),
      baseKey: b64(x.ephemeralPub),
      peer: identity,
      pending: { ek: b64(x.ephemeralPub), spk: x.signedPreKeyId, opk: x.oneTimePreKeyId },
    };
  }
}

function sameIdentity(a: PublicIdentity, b: PublicIdentity): boolean {
  return equal(a.sigKey, b.sigKey) && equal(a.dhKey, b.dhKey);
}

/** Strips padding; a bad pad on an authenticated message is still the message's fault. */
function unpadded(plaintext: Uint8Array): Uint8Array {
  try {
    return unpad(plaintext);
  } catch {
    throw new DecryptError('invalid padding');
  }
}

function promote(rec: SessionRecord, s: Session): void {
  if (rec.current === s) return;
  rec.previous = rec.previous.filter((p) => p !== s);
  if (rec.current) rec.previous.unshift(rec.current);
  rec.current = s;
  rec.previous = rec.previous.slice(0, MAX_PREVIOUS);
}

function isUint(n: unknown): n is number {
  return typeof n === 'number' && Number.isInteger(n) && n >= 0 && n <= 0xffffffff;
}

function parseEnvelope(payload: string): Envelope {
  let env: WireEnvelope;
  try {
    env = JSON.parse(payload) as WireEnvelope;
  } catch {
    throw new DecryptError('malformed envelope');
  }
  if (
    !env ||
    env.v !== VERSION ||
    typeof env.c !== 'string' ||
    !env.h ||
    typeof env.h.d !== 'string' ||
    !isUint(env.h.p) ||
    !isUint(env.h.n)
  ) {
    throw new DecryptError('malformed envelope');
  }
  let header: Header;
  let ct: Uint8Array;
  try {
    header = { dh: unb64n(env.h.d, 32, 'header.dh'), pn: env.h.p, n: env.h.n };
    ct = unb64(env.c);
  } catch {
    throw new DecryptError('malformed envelope');
  }
  if (!env.x) return { header, ct };
  const x = env.x;
  if (
    typeof x.s !== 'string' ||
    typeof x.i !== 'string' ||
    typeof x.e !== 'string' ||
    !isUint(x.k) ||
    (x.o !== undefined && !isUint(x.o))
  ) {
    throw new DecryptError('malformed prekey envelope');
  }
  try {
    const ek = unb64n(x.e, 32, 'x.e');
    return {
      header,
      ct,
      x: {
        peer: { sigKey: unb64n(x.s, 32, 'x.s'), dhKey: unb64n(x.i, 32, 'x.i') },
        ek,
        // Re-encoded, so that a differently spelled copy of the same key
        // (base64 tolerates junk in the unused low bits) still matches.
        baseKey: b64(ek),
        spk: x.k,
        opk: x.o,
      },
    };
  } catch {
    throw new DecryptError('malformed prekey envelope');
  }
}
