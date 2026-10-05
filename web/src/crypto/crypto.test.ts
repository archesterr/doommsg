import { describe, expect, it } from 'vitest';
import { b64, equal, fromUtf8, random, unb64, utf8 } from './bytes';
import { pad, unpad } from './padding';
import { LABEL, newDHKeyPair, newIdentity, sign, type Identity, type KeyPair, type PublicIdentity } from './protocol';
import { decrypt, encrypt, initAlice, initBob, MAX_SKIP, RatchetError } from './ratchet';
import { safetyNumber } from './safety';
import { DecryptError, SessionCipher, type KeyStore, type SessionRecord } from './session';
import { BundleVerificationError, initiate, respond, type PreKeyBundle } from './x3dh';

describe('bytes', () => {
  it('round-trips base64url', () => {
    for (const n of [0, 1, 2, 3, 31, 32, 33, 1000]) {
      const b = crypto.getRandomValues(new Uint8Array(n));
      expect(equal(unb64(b64(b)), b)).toBe(true);
    }
    expect(() => unb64('not base64!')).toThrow();
  });
});

describe('padding', () => {
  it('pads to 256-byte buckets and round-trips', () => {
    for (const n of [0, 1, 254, 255, 256, 1000]) {
      const b = crypto.getRandomValues(new Uint8Array(n));
      const p = pad(b);
      expect(p.length % 256).toBe(0);
      expect(p.length).toBeGreaterThan(n);
      expect(equal(unpad(p), b)).toBe(true);
    }
    expect(() => unpad(new Uint8Array(16))).toThrow();
  });
});

interface Party {
  name: string;
  id: Identity;
  spk: KeyPair & { keyId: number };
  opks: Map<number, KeyPair>;
}

function party(name: string, opkCount = 3): Party {
  const opks = new Map<number, KeyPair>();
  for (let i = 1; i <= opkCount; i++) opks.set(i, newDHKeyPair());
  return { name, id: newIdentity(), spk: { ...newDHKeyPair(), keyId: 7 }, opks };
}

function bundleOf(p: Party, withOpk = true): PreKeyBundle {
  const first = withOpk ? [...p.opks.entries()][0] : undefined;
  return {
    sigKey: p.id.sig.pub,
    dhKey: p.id.dh.pub,
    dhKeySig: p.id.dhSig,
    signedPreKey: { keyId: p.spk.keyId, pub: p.spk.pub, sig: sign(p.id.sig.priv, LABEL.signedPreKey, p.spk.pub) },
    oneTimePreKey: first ? { keyId: first[0], pub: first[1].pub } : undefined,
  };
}

describe('x3dh', () => {
  it('derives the same secret on both sides, with and without a one-time prekey', () => {
    for (const withOpk of [true, false]) {
      const alice = party('alice');
      const bob = party('bob');
      const b = bundleOf(bob, withOpk);
      const a = initiate(alice.id, b);
      const r = respond(
        bob.id,
        bob.spk,
        withOpk ? bob.opks.get(b.oneTimePreKey!.keyId) : undefined,
        { sigKey: alice.id.sig.pub, dhKey: alice.id.dh.pub },
        a.ephemeralPub,
      );
      expect(equal(a.sk, r.sk)).toBe(true);
      expect(equal(a.ad, r.ad)).toBe(true);
    }
  });

  it('rejects bundles with forged signatures', () => {
    const alice = party('alice');
    const bob = party('bob');
    const mallory = party('mallory');
    const forgedSpk = bundleOf(bob);
    forgedSpk.signedPreKey.pub = mallory.spk.pub;
    expect(() => initiate(alice.id, forgedSpk)).toThrow(BundleVerificationError);
    const forgedDh = bundleOf(bob);
    forgedDh.dhKey = mallory.id.dh.pub;
    expect(() => initiate(alice.id, forgedDh)).toThrow(BundleVerificationError);
  });
});

describe('double ratchet', () => {
  function pair() {
    const sk = crypto.getRandomValues(new Uint8Array(32));
    const ad = crypto.getRandomValues(new Uint8Array(128));
    const bobSpk = newDHKeyPair();
    return { a: initAlice(sk, bobSpk.pub, ad), b: initBob(sk, bobSpk, ad) };
  }

  it('exchanges messages in both directions across many ratchet steps', () => {
    let { a, b } = pair();
    for (let round = 0; round < 10; round++) {
      for (let i = 0; i < 3; i++) {
        const m = encrypt(a, utf8(`a${round}.${i}`));
        const r = decrypt(b, m.header, m.ciphertext);
        b = r.state;
        expect(fromUtf8(r.plaintext)).toBe(`a${round}.${i}`);
      }
      const m = encrypt(b, utf8(`b${round}`));
      const r = decrypt(a, m.header, m.ciphertext);
      a = r.state;
      expect(fromUtf8(r.plaintext)).toBe(`b${round}`);
    }
  });

  it('handles out-of-order and cross-chain delayed messages', () => {
    let { a, b } = pair();
    const m1 = encrypt(a, utf8('1'));
    const m2 = encrypt(a, utf8('2'));
    const m3 = encrypt(a, utf8('3'));
    let r = decrypt(b, m3.header, m3.ciphertext);
    b = r.state;
    expect(fromUtf8(r.plaintext)).toBe('3');
    // Bob replies, Alice ratchets, sends on a new chain.
    const reply = encrypt(b, utf8('reply'));
    a = decrypt(a, reply.header, reply.ciphertext).state;
    const m4 = encrypt(a, utf8('4'));
    r = decrypt(b, m4.header, m4.ciphertext);
    b = r.state;
    // Old-chain messages still decrypt from stored skipped keys.
    r = decrypt(b, m1.header, m1.ciphertext);
    b = r.state;
    expect(fromUtf8(r.plaintext)).toBe('1');
    r = decrypt(b, m2.header, m2.ciphertext);
    b = r.state;
    expect(fromUtf8(r.plaintext)).toBe('2');
    expect(b.skipped.length).toBe(0);
  });

  it('rejects replays, tampering and excessive skips without corrupting state', () => {
    const p = pair();
    const a = p.a;
    let b = p.b;
    const m1 = encrypt(a, utf8('hello'));
    b = decrypt(b, m1.header, m1.ciphertext).state;
    expect(() => decrypt(b, m1.header, m1.ciphertext)).toThrow(RatchetError);

    const m2 = encrypt(a, utf8('world'));
    const tampered = m2.ciphertext.slice();
    tampered[0] ^= 1;
    expect(() => decrypt(b, m2.header, tampered)).toThrow(RatchetError);
    expect(() => decrypt(b, { ...m2.header, n: m2.header.n + 1 }, m2.ciphertext)).toThrow(RatchetError);
    // State unaffected by the failures above.
    expect(fromUtf8(decrypt(b, m2.header, m2.ciphertext).plaintext)).toBe('world');

    expect(() => decrypt(b, { ...m2.header, n: MAX_SKIP + 10 }, m2.ciphertext)).toThrow(/too many skipped/);
  });

  it('uses fresh keys for every message (forward secrecy smoke test)', () => {
    const { a } = pair();
    const m1 = encrypt(a, utf8('same'));
    const m2 = encrypt(a, utf8('same'));
    expect(b64(m1.ciphertext)).not.toBe(b64(m2.ciphertext));
  });
});

class MemoryStore implements KeyStore {
  sessions = new Map<string, SessionRecord>();
  constructor(public p: Party) {}
  async identity() {
    return this.p.id;
  }
  async signedPreKey(id: number) {
    return id === this.p.spk.keyId ? this.p.spk : undefined;
  }
  async oneTimePreKey(id: number) {
    return this.p.opks.get(id);
  }
  async removeOneTimePreKey(id: number) {
    this.p.opks.delete(id);
  }
  async loadSession(peer: string) {
    // Round-trip through structuredClone, like a real persistent store.
    const r = this.sessions.get(peer);
    return r ? structuredClone(r) : undefined;
  }
  async saveSession(peer: string, rec: SessionRecord) {
    this.sessions.set(peer, structuredClone(rec));
  }
  async deleteSession(peer: string) {
    this.sessions.delete(peer);
  }
}

function cipherFor(
  p: Party,
  directory: Map<string, Party>,
  checkIdentity: (peer: string, id: PublicIdentity) => Promise<void> = async () => {},
) {
  const store = new MemoryStore(p);
  const cipher = new SessionCipher(store, {
    fetchBundle: async (peer) => {
      const target = directory.get(peer)!;
      const b = bundleOf(target, target.opks.size > 0);
      return b;
    },
    checkIdentity,
  });
  return { store, cipher };
}

const pub = (p: Party): PublicIdentity => ({ sigKey: p.id.sig.pub, dhKey: p.id.dh.pub });
const sameIdentity = (a: PublicIdentity, b: PublicIdentity) => equal(a.sigKey, b.sigKey) && equal(a.dhKey, b.dhKey);

/**
 * A checkIdentity hook with the app's semantics: trust on first use, and a
 * different identity later is re-pinned (unverified) and recorded.
 */
function pinning() {
  const pins = new Map<string, PublicIdentity>();
  const events: string[] = [];
  const check = async (peer: string, id: PublicIdentity) => {
    const pinned = pins.get(peer);
    if (pinned && sameIdentity(pinned, id)) return;
    events.push(pinned ? 'changed' : 'tofu');
    pins.set(peer, id);
  };
  return { pins, events, check };
}

/** The identity the user is shown for `peer` is the one their messages go to. */
async function expectBound(store: MemoryStore, peer: string, pins: Map<string, PublicIdentity>) {
  const rec = await store.loadSession(peer);
  expect(sameIdentity(rec!.current!.peer, pins.get(peer)!)).toBe(true);
}

describe('session cipher', () => {
  it('establishes a session from the first message and converses', async () => {
    const alice = party('alice');
    const bob = party('bob');
    const dir = new Map([
      ['alice', alice],
      ['bob', bob],
    ]);
    const A = cipherFor(alice, dir);
    const B = cipherFor(bob, dir);

    const e1 = await A.cipher.encrypt('bob', utf8('hi bob'));
    const e2 = await A.cipher.encrypt('bob', utf8('second'));
    expect(JSON.parse(e1).x).toBeDefined();
    expect(fromUtf8(await B.cipher.decrypt('alice', e1))).toBe('hi bob');
    expect(fromUtf8(await B.cipher.decrypt('alice', e2))).toBe('second');
    expect(bob.opks.size).toBe(2); // one-time prekey consumed exactly once

    const r = await B.cipher.encrypt('alice', utf8('hi alice'));
    expect(JSON.parse(r).x).toBeUndefined();
    expect(fromUtf8(await A.cipher.decrypt('bob', r))).toBe('hi alice');

    // After a reply, Alice stops sending prekey envelopes.
    const e3 = await A.cipher.encrypt('bob', utf8('third'));
    expect(JSON.parse(e3).x).toBeUndefined();
    expect(fromUtf8(await B.cipher.decrypt('alice', e3))).toBe('third');

    // Replay of the initial prekey message is rejected.
    await expect(B.cipher.decrypt('alice', e1)).rejects.toThrow(DecryptError);
  });

  it('converges after simultaneous initiation', async () => {
    const alice = party('alice');
    const bob = party('bob');
    const dir = new Map([
      ['alice', alice],
      ['bob', bob],
    ]);
    const A = cipherFor(alice, dir);
    const B = cipherFor(bob, dir);

    const fromA = await A.cipher.encrypt('bob', utf8('a1'));
    const fromB = await B.cipher.encrypt('alice', utf8('b1'));
    expect(fromUtf8(await B.cipher.decrypt('alice', fromA))).toBe('a1');
    expect(fromUtf8(await A.cipher.decrypt('bob', fromB))).toBe('b1');

    for (let i = 0; i < 3; i++) {
      const x = await A.cipher.encrypt('bob', utf8(`a${i + 2}`));
      expect(fromUtf8(await B.cipher.decrypt('alice', x))).toBe(`a${i + 2}`);
      const y = await B.cipher.encrypt('alice', utf8(`b${i + 2}`));
      expect(fromUtf8(await A.cipher.decrypt('bob', y))).toBe(`b${i + 2}`);
    }
  });

  it('recovers when a peer reinstalls and starts a fresh session', async () => {
    const alice = party('alice');
    const bob = party('bob');
    const dir = new Map([
      ['alice', alice],
      ['bob', bob],
    ]);
    const A = cipherFor(alice, dir);
    const B = cipherFor(bob, dir);
    await B.cipher.decrypt('alice', await A.cipher.encrypt('bob', utf8('before')));

    await A.cipher.reset('bob'); // Alice lost her session state
    const fresh = await A.cipher.encrypt('bob', utf8('after'));
    expect(fromUtf8(await B.cipher.decrypt('alice', fresh))).toBe('after');
    const back = await B.cipher.encrypt('alice', utf8('welcome back'));
    expect(fromUtf8(await A.cipher.decrypt('bob', back))).toBe('welcome back');
  });

  it('rejects messages from an impostor claiming another identity', async () => {
    const alice = party('alice');
    const bob = party('bob');
    const mallory = party('mallory');
    const dir = new Map([
      ['alice', alice],
      ['bob', bob],
      ['mallory', mallory],
    ]);
    const M = cipherFor(mallory, dir);
    const B = cipherFor(bob, dir);
    const env = JSON.parse(await M.cipher.encrypt('bob', utf8('i am alice')));
    // Mallory swaps in Alice's public identity but cannot do Alice's DH.
    env.x.s = b64(alice.id.sig.pub);
    env.x.i = b64(alice.id.dh.pub);
    await expect(B.cipher.decrypt('alice', JSON.stringify(env))).rejects.toThrow(DecryptError);
  });

  it('serialises concurrent operations on the same peer', async () => {
    const alice = party('alice', 1);
    const bob = party('bob', 1);
    const dir = new Map([
      ['alice', alice],
      ['bob', bob],
    ]);
    const A = cipherFor(alice, dir);
    const B = cipherFor(bob, dir);
    const envs = await Promise.all(Array.from({ length: 20 }, (_, i) => A.cipher.encrypt('bob', utf8(String(i)))));
    const out = await Promise.all(envs.map((e) => B.cipher.decrypt('alice', e)));
    expect(out.map(fromUtf8)).toEqual(Array.from({ length: 20 }, (_, i) => String(i)));
  });

  it('reports malformed and hostile envelopes as DecryptError', async () => {
    const alice = party('alice');
    const bob = party('bob');
    const dir = new Map([
      ['alice', alice],
      ['bob', bob],
    ]);
    const A = cipherFor(alice, dir);
    const bobPins = pinning();
    const B = cipherFor(bob, dir, bobPins.check);
    const first = JSON.parse(await A.cipher.encrypt('bob', utf8('first')));
    const zero = b64(new Uint8Array(32)); // a low-order point
    for (const mutate of [
      (e: typeof first) => (e.h.d = '!!'),
      (e: typeof first) => (e.c = 'a'),
      (e: typeof first) => (e.x.e = 'AAAA'),
      (e: typeof first) => (e.x.i = zero),
      (e: typeof first) => (e.x.e = zero),
      (e: typeof first) => (e.h.d = zero),
    ]) {
      const env = structuredClone(first);
      mutate(env);
      await expect(B.cipher.decrypt('alice', JSON.stringify(env))).rejects.toThrow(DecryptError);
    }
    expect(bobPins.events).toEqual([]);
    expect(await B.cipher.hasSession('alice')).toBe(false);
    expect(bob.opks.size).toBe(3);

    expect(fromUtf8(await B.cipher.decrypt('alice', JSON.stringify(first)))).toBe('first');
    const next = JSON.parse(await A.cipher.encrypt('bob', utf8('next')));
    delete next.x;
    next.h.d = zero; // on an existing session
    await expect(B.cipher.decrypt('alice', JSON.stringify(next))).rejects.toThrow(DecryptError);
  });
});

describe('session identity binding', () => {
  it('only trusts the identity in a prekey message once the message decrypts', async () => {
    const alice = party('alice');
    const bob = party('bob');
    const mallory = party('mallory');
    const dir = new Map([
      ['alice', alice],
      ['bob', bob],
    ]);
    const A = cipherFor(alice, dir);
    const bobPins = pinning();
    const B = cipherFor(bob, dir, bobPins.check);
    const M = cipherFor(mallory, dir);
    expect(fromUtf8(await B.cipher.decrypt('alice', await A.cipher.encrypt('bob', utf8('hello'))))).toBe('hello');
    expect(fromUtf8(await A.cipher.decrypt('bob', await B.cipher.encrypt('alice', utf8('hi'))))).toBe('hi');
    expect(bobPins.events).toEqual(['tofu']);

    // The server delivers Mallory's genuine session as "alice": accepted, but flagged.
    expect(fromUtf8(await B.cipher.decrypt('alice', await M.cipher.encrypt('bob', utf8('mitm'))))).toBe('mitm');
    expect(bobPins.events).toEqual(['tofu', 'changed']);

    // A junk prekey message claiming Alice's real identity must not re-pin
    // it, or Bob's safety number would match Alice's while he talks to Mallory.
    const junk = {
      v: 1,
      h: { d: b64(newDHKeyPair().pub), p: 0, n: 0 },
      c: b64(random(300)),
      x: { s: b64(alice.id.sig.pub), i: b64(alice.id.dh.pub), e: b64(newDHKeyPair().pub), k: bob.spk.keyId },
    };
    await expect(B.cipher.decrypt('alice', JSON.stringify(junk))).rejects.toThrow(DecryptError);
    expect(bobPins.events).toEqual(['tofu', 'changed']);
    const sn = (id: PublicIdentity) => safetyNumber({ username: 'bob', identity: pub(bob) }, { username: 'alice', identity: id });
    const shown = sn(bobPins.pins.get('alice')!);
    expect(shown).toEqual(sn(pub(mallory)));
    expect(shown).not.toEqual(sn(pub(alice)));
    await expectBound(B.store, 'alice', bobPins.pins);

    // Same for a peer seen for the first time: nothing is pinned or stored.
    const carol = party('carol');
    const carolPins = pinning();
    const C = cipherFor(carol, dir, carolPins.check);
    const toCarol = JSON.stringify({ ...junk, x: { ...junk.x, k: carol.spk.keyId } });
    await expect(C.cipher.decrypt('alice', toCarol)).rejects.toThrow(DecryptError);
    expect(carolPins.events).toEqual([]);
    expect(await C.cipher.hasSession('alice')).toBe(false);
  });

  it('re-checks the identity of an existing session on every send and receive', async () => {
    const alice = party('alice');
    const bob = party('bob');
    const dir = new Map([
      ['alice', alice],
      ['bob', bob],
    ]);
    const seenByA: PublicIdentity[] = [];
    const seenByB: PublicIdentity[] = [];
    const A = cipherFor(alice, dir, async (_, id) => void seenByA.push(id));
    const B = cipherFor(bob, dir, async (_, id) => void seenByB.push(id));

    await B.cipher.decrypt('alice', await A.cipher.encrypt('bob', utf8('1'))); // A: bundle, B: new session
    await A.cipher.decrypt('bob', await B.cipher.encrypt('alice', utf8('2'))); // B: send, A: receive
    await B.cipher.decrypt('alice', await A.cipher.encrypt('bob', utf8('3'))); // A: send, B: receive
    expect(seenByA).toHaveLength(3);
    expect(seenByB).toHaveLength(3);
    expect(seenByA.every((id) => sameIdentity(id, pub(bob)))).toBe(true);
    expect(seenByB.every((id) => sameIdentity(id, pub(alice)))).toBe(true);
  });

  it('persists nothing when the identity is refused and passes the error through', async () => {
    class Offline extends Error {}
    const alice = party('alice');
    const bob = party('bob');
    const dir = new Map([
      ['alice', alice],
      ['bob', bob],
    ]);
    let refuse = false;
    const A = cipherFor(alice, dir);
    const B = cipherFor(bob, dir, async () => {
      if (refuse) throw new Offline('try again later');
    });

    // A new session: neither the session nor the one-time prekey use is kept.
    const e1 = await A.cipher.encrypt('bob', utf8('e1'));
    refuse = true;
    await expect(B.cipher.decrypt('alice', e1)).rejects.toBeInstanceOf(Offline);
    expect(await B.cipher.hasSession('alice')).toBe(false);
    expect(bob.opks.size).toBe(3);
    refuse = false;
    expect(fromUtf8(await B.cipher.decrypt('alice', e1))).toBe('e1');
    expect(bob.opks.size).toBe(2);

    // An existing session: its state does not advance, so a retry works.
    const e2 = await A.cipher.encrypt('bob', utf8('e2'));
    const before = await B.store.loadSession('alice');
    refuse = true;
    await expect(B.cipher.decrypt('alice', e2)).rejects.toBeInstanceOf(Offline);
    expect(await B.store.loadSession('alice')).toEqual(before);
    refuse = false;
    expect(fromUtf8(await B.cipher.decrypt('alice', e2))).toBe('e2');

    // Sending.
    const before2 = await B.store.loadSession('alice');
    refuse = true;
    await expect(B.cipher.encrypt('alice', utf8('r'))).rejects.toBeInstanceOf(Offline);
    expect(await B.store.loadSession('alice')).toEqual(before2);
    refuse = false;
    expect(fromUtf8(await A.cipher.decrypt('bob', await B.cipher.encrypt('alice', utf8('r'))))).toBe('r');
  });

  it('checks a bundle signature before trusting its identity', async () => {
    const alice = party('alice');
    const bob = party('bob');
    const mallory = party('mallory');
    const pins = pinning();
    const forged = bundleOf(bob);
    forged.dhKey = mallory.id.dh.pub;
    const A = new SessionCipher(new MemoryStore(alice), { fetchBundle: async () => forged, checkIdentity: pins.check });
    await expect(A.encrypt('bob', utf8('hi'))).rejects.toThrow(BundleVerificationError);
    expect(pins.events).toEqual([]);
  });

  it('never silently falls back to a session with a replaced identity', async () => {
    const alice = party('alice');
    const bob = party('bob');
    const mallory = party('mallory');
    const dir = new Map([['alice', alice]]);
    const alicePins = pinning();
    const A = cipherFor(alice, dir, alicePins.check);
    const B = cipherFor(bob, dir);
    const M = cipherFor(mallory, dir);

    // The server introduces Mallory as "bob"; Alice answers her.
    expect(fromUtf8(await A.cipher.decrypt('bob', await M.cipher.encrypt('alice', utf8('m1'))))).toBe('m1');
    expect(fromUtf8(await M.cipher.decrypt('alice', await A.cipher.encrypt('bob', utf8('a1'))))).toBe('a1');
    // The real Bob shows up; Alice is told and can now verify him.
    expect(fromUtf8(await A.cipher.decrypt('bob', await B.cipher.encrypt('alice', utf8('b1'))))).toBe('b1');
    expect(alicePins.events).toEqual(['tofu', 'changed']);
    await expectBound(A.store, 'bob', alicePins.pins);

    // Mallory's session must not quietly take over again.
    const m2 = await M.cipher.encrypt('alice', utf8('m2'));
    expect(JSON.parse(m2).x).toBeUndefined();
    await expect(A.cipher.decrypt('bob', m2)).rejects.toThrow(DecryptError);
    expect(alicePins.events).toEqual(['tofu', 'changed']);
    await expectBound(A.store, 'bob', alicePins.pins);
    const out = await A.cipher.encrypt('bob', utf8('for bob'));
    expect(fromUtf8(await B.cipher.decrypt('alice', out))).toBe('for bob');
    await expect(M.cipher.decrypt('alice', out)).rejects.toThrow(DecryptError);
  });

  it('lets a replaced identity back in only as a new, flagged change', async () => {
    for (const opks of [3, 0]) {
      const alice = party('alice', opks);
      const bob = party('bob');
      const mallory = party('mallory');
      const dir = new Map([['alice', alice]]);
      const alicePins = pinning();
      const A = cipherFor(alice, dir, alicePins.check);
      const B = cipherFor(bob, dir);
      const M = cipherFor(mallory, dir);

      await A.cipher.decrypt('bob', await M.cipher.encrypt('alice', utf8('m1')));
      await A.cipher.decrypt('bob', await B.cipher.encrypt('alice', utf8('b1')));
      expect(alicePins.events).toEqual(['tofu', 'changed']);
      // Sessions bound to the replaced identity are gone.
      const rec = await A.store.loadSession('bob');
      expect([rec!.current!, ...rec!.previous].every((s) => sameIdentity(s.peer, pub(bob)))).toBe(true);

      // Mallory never got an answer, so her next message still carries her
      // prekey header. Its one-time prekey is spent; without one it can only
      // come back in as a new session, flagged like any identity change.
      const m2 = await M.cipher.encrypt('alice', utf8('m2'));
      expect(JSON.parse(m2).x).toBeDefined();
      if (opks) {
        await expect(A.cipher.decrypt('bob', m2)).rejects.toThrow(/one-time prekey already used/);
        expect(alicePins.events).toEqual(['tofu', 'changed']);
      } else {
        expect(fromUtf8(await A.cipher.decrypt('bob', m2))).toBe('m2');
        expect(alicePins.events).toEqual(['tofu', 'changed', 'changed']);
      }
      await expectBound(A.store, 'bob', alicePins.pins);
    }
  });

  it('never promotes a stored session bound to another identity', async () => {
    const alice = party('alice');
    const bob = party('bob');
    const mallory = party('mallory');
    const dir = new Map([['alice', alice]]);
    const alicePins = pinning();
    const A = cipherFor(alice, dir, alicePins.check);
    const B = cipherFor(bob, dir);
    const M = cipherFor(mallory, dir);

    await A.cipher.decrypt('bob', await M.cipher.encrypt('alice', utf8('m1')));
    const stale = (await A.store.loadSession('bob'))!.current!;
    await A.cipher.decrypt('bob', await B.cipher.encrypt('alice', utf8('b1')));
    // A record that still holds Mallory's session behind Bob's.
    const rec = (await A.store.loadSession('bob'))!;
    await A.store.saveSession('bob', { current: rec.current, previous: [stale] });

    const m2 = JSON.parse(await M.cipher.encrypt('alice', utf8('m2')));
    await expect(A.cipher.decrypt('bob', JSON.stringify(m2))).rejects.toThrow(/duplicate prekey message/);
    delete m2.x; // the server can strip the prekey header
    await expect(A.cipher.decrypt('bob', JSON.stringify(m2))).rejects.toThrow(/no session can decrypt/);
    expect(alicePins.events).toEqual(['tofu', 'changed']);
    await expectBound(A.store, 'bob', alicePins.pins);
  });
});

describe('trusted identity', () => {
  it('starts a new session instead of sending on one bound to an identity no longer trusted', async () => {
    const alice = party('alice');
    const oldBob = party('bob');
    const newBob = party('bob');
    const dir = new Map([
      ['alice', alice],
      ['bob', oldBob],
    ]);
    const { pins, events, check } = pinning();
    const store = new MemoryStore(alice);
    const A = new SessionCipher(store, {
      fetchBundle: async (peer) => bundleOf(dir.get(peer)!),
      checkIdentity: check,
      trustedIdentity: (peer) => pins.get(peer),
    });
    const B1 = cipherFor(oldBob, dir);
    await B1.cipher.decrypt('alice', await A.encrypt('bob', utf8('hi')));
    await A.decrypt('bob', await B1.cipher.encrypt('alice', utf8('hi alice')));

    // The chat is deleted and bob added again: the directory now has a new key.
    dir.set('bob', newBob);
    pins.set('bob', pub(newBob));
    const B2 = cipherFor(newBob, dir);
    const env = await A.encrypt('bob', utf8('for the new key'));

    expect(JSON.parse(env).x).toBeDefined(); // a fresh session
    expect(fromUtf8(await B2.cipher.decrypt('alice', env))).toBe('for the new key');
    await expect(B1.cipher.decrypt('alice', env)).rejects.toThrow();
    expect(sameIdentity(pins.get('bob')!, pub(newBob))).toBe(true);
    expect(events).toEqual(['tofu']); // never re-pinned to the old key
    await expectBound(store, 'bob', pins);
    // The abandoned session is not kept to fall back on.
    expect((await store.loadSession('bob'))!.previous.every((s) => sameIdentity(s.peer, pub(newBob)))).toBe(true);
  });
});

describe('prekey replay', () => {
  // Spells a 32-byte base64url value differently: its last character has two
  // unused low bits, which decoders ignore.
  function respell(s: string): string {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    return s.slice(0, -1) + alphabet[alphabet.indexOf(s[s.length - 1]) | 1];
  }

  it('rejects a replayed prekey message that used no one-time prekey', async () => {
    const alice = party('alice');
    const bob = party('bob', 0); // out of one-time prekeys (or the server left it out)
    const dir = new Map([
      ['alice', alice],
      ['bob', bob],
    ]);
    const A = cipherFor(alice, dir);
    const B = cipherFor(bob, dir);
    const e1 = await A.cipher.encrypt('bob', utf8('timer off'));
    expect(JSON.parse(e1).x.o).toBeUndefined();
    expect(fromUtf8(await B.cipher.decrypt('alice', e1))).toBe('timer off');
    expect(fromUtf8(await A.cipher.decrypt('bob', await B.cipher.encrypt('alice', utf8('ok'))))).toBe('ok');

    for (let i = 0; i < 4; i++) {
      await expect(B.cipher.decrypt('alice', e1)).rejects.toThrow(/duplicate prekey message/);
    }
    const respelled = JSON.parse(e1);
    respelled.x.e = respell(respelled.x.e);
    expect(respelled.x.e).not.toBe(JSON.parse(e1).x.e);
    expect(equal(unb64(respelled.x.e), unb64(JSON.parse(e1).x.e))).toBe(true);
    await expect(B.cipher.decrypt('alice', JSON.stringify(respelled))).rejects.toThrow(/duplicate prekey message/);

    // The live session is untouched and the conversation carries on.
    expect((await B.store.loadSession('alice'))!.previous).toHaveLength(0);
    for (let i = 0; i < 3; i++) {
      expect(fromUtf8(await B.cipher.decrypt('alice', await A.cipher.encrypt('bob', utf8(`a${i}`))))).toBe(`a${i}`);
      expect(fromUtf8(await A.cipher.decrypt('bob', await B.cipher.encrypt('alice', utf8(`b${i}`))))).toBe(`b${i}`);
    }
  });

  it('still accepts prekey messages that arrive out of order or respelled', async () => {
    const alice = party('alice');
    const bob = party('bob', 0);
    const dir = new Map([
      ['alice', alice],
      ['bob', bob],
    ]);
    const A = cipherFor(alice, dir);
    const B = cipherFor(bob, dir);
    const e1 = await A.cipher.encrypt('bob', utf8('1'));
    const e2 = await A.cipher.encrypt('bob', utf8('2'));
    const e3 = JSON.parse(await A.cipher.encrypt('bob', utf8('3')));
    e3.x.e = respell(e3.x.e);
    expect(fromUtf8(await B.cipher.decrypt('alice', e2))).toBe('2');
    expect(fromUtf8(await B.cipher.decrypt('alice', JSON.stringify(e3)))).toBe('3');
    expect(fromUtf8(await B.cipher.decrypt('alice', e1))).toBe('1');
    await expect(B.cipher.decrypt('alice', e2)).rejects.toThrow(/duplicate prekey message/);
    expect((await B.store.loadSession('alice'))!.previous).toHaveLength(0);
  });
});

describe('safety numbers', () => {
  it('is symmetric and changes when an identity changes', () => {
    const a = { username: 'alice', identity: { sigKey: newIdentity().sig.pub, dhKey: newDHKeyPair().pub } };
    const b = { username: 'bob', identity: { sigKey: newIdentity().sig.pub, dhKey: newDHKeyPair().pub } };
    const ab = safetyNumber(a, b);
    expect(ab).toHaveLength(12);
    expect(ab.every((g) => /^\d{5}$/.test(g))).toBe(true);
    expect(safetyNumber(b, a)).toEqual(ab);
    const b2 = { ...b, identity: { ...b.identity, dhKey: newDHKeyPair().pub } };
    expect(safetyNumber(a, b2)).not.toEqual(ab);
  });
});
