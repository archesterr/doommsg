import { describe, expect, it } from 'vitest';
import { b64, equal, fromUtf8, unb64, utf8 } from './bytes';
import { pad, unpad } from './padding';
import { LABEL, newDHKeyPair, newIdentity, sign, type Identity, type KeyPair } from './protocol';
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

function cipherFor(p: Party, directory: Map<string, Party>) {
  const store = new MemoryStore(p);
  const cipher = new SessionCipher(store, {
    fetchBundle: async (peer) => {
      const target = directory.get(peer)!;
      const b = bundleOf(target, target.opks.size > 0);
      return b;
    },
    checkIdentity: async () => {},
  });
  return { store, cipher };
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
