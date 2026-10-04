// Session layer: turns X3DH + Double Ratchet into "encrypt to user" /
// "decrypt from user", handling session setup, simultaneous initiation and
// the wire envelope format. The server only ever sees these envelopes.

import { b64, unb64, unb64n } from './bytes';
import { pad, unpad } from './padding';
import type { Identity, KeyPair, PublicIdentity } from './protocol';
import { decrypt, encrypt, initAlice, initBob, RatchetError, type Header, type RatchetState } from './ratchet';
import { initiate, respond, type PreKeyBundle } from './x3dh';

export interface Session {
  state: RatchetState;
  /** b64 of the X3DH ephemeral key that created the session. */
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
   * Called whenever a peer identity is about to be trusted for a new
   * session. Throw to refuse it.
   */
  checkIdentity(peer: string, identity: PublicIdentity): Promise<void>;
}

const MAX_PREVIOUS = 3;
const VERSION = 1;

interface WireEnvelope {
  v: number;
  h: { d: string; p: number; n: number };
  c: string;
  x?: { s: string; i: string; e: string; k: number; o?: number };
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
      if (!rec.current) rec.current = await this.startSession(peer);
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
      const env = parseEnvelope(payload);
      const header: Header = { dh: unb64n(env.h.d, 32, 'header.dh'), pn: env.h.p, n: env.h.n };
      const ct = unb64(env.c);
      const rec = (await this.store.loadSession(peer)) ?? { previous: [] };
      const sessions = [rec.current, ...rec.previous].filter((s): s is Session => !!s);

      // Messages on an existing session (including resent prekey messages).
      const candidates = env.x ? sessions.filter((s) => s.baseKey === env.x!.e) : sessions;
      for (const s of candidates) {
        try {
          const { state, plaintext } = decrypt(s.state, header, ct);
          s.state = state;
          delete s.pending; // the peer evidently has this session
          promote(rec, s);
          await this.store.saveSession(peer, rec);
          return unpad(plaintext);
        } catch (e) {
          if (!(e instanceof RatchetError)) throw e;
        }
      }
      if (!env.x) throw new DecryptError('no session can decrypt this message');

      // A new session initiated by the peer.
      const peerId: PublicIdentity = {
        sigKey: unb64n(env.x.s, 32, 'x.s'),
        dhKey: unb64n(env.x.i, 32, 'x.i'),
      };
      await this.hooks.checkIdentity(peer, peerId);
      const me = await this.store.identity();
      const spk = await this.store.signedPreKey(env.x.k);
      if (!spk) throw new DecryptError('unknown signed prekey');
      let opk: KeyPair | undefined;
      if (env.x.o !== undefined) {
        opk = await this.store.oneTimePreKey(env.x.o);
        if (!opk) throw new DecryptError('one-time prekey already used');
      }
      const ek = unb64n(env.x.e, 32, 'x.e');
      const { sk, ad } = respond(me, spk, opk, peerId, ek);
      let result: ReturnType<typeof decrypt>;
      try {
        result = decrypt(initBob(sk, spk, ad), header, ct);
      } catch (e) {
        if (e instanceof RatchetError) throw new DecryptError('prekey message failed to decrypt');
        throw e;
      }
      const session: Session = { state: result.state, baseKey: env.x.e, peer: peerId };
      if (rec.current) rec.previous.unshift(rec.current);
      rec.current = session;
      rec.previous = rec.previous.slice(0, MAX_PREVIOUS);
      await this.store.saveSession(peer, rec);
      if (env.x.o !== undefined) await this.store.removeOneTimePreKey(env.x.o);
      return unpad(result.plaintext);
    });
  }

  private async startSession(peer: string): Promise<Session> {
    const bundle = await this.hooks.fetchBundle(peer);
    await this.hooks.checkIdentity(peer, { sigKey: bundle.sigKey, dhKey: bundle.dhKey });
    const me = await this.store.identity();
    const x = initiate(me, bundle);
    return {
      state: initAlice(x.sk, x.signedPreKeyPub, x.ad),
      baseKey: b64(x.ephemeralPub),
      peer: { sigKey: bundle.sigKey, dhKey: bundle.dhKey },
      pending: { ek: b64(x.ephemeralPub), spk: x.signedPreKeyId, opk: x.oneTimePreKeyId },
    };
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

function parseEnvelope(payload: string): WireEnvelope {
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
  if (env.x) {
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
  }
  return env;
}
