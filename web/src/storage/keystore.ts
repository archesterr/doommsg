// Persistent key material: identity, prekeys and ratchet sessions.

import { b64 } from '../crypto/bytes';
import { LABEL, newDHKeyPair, newIdentity, sign, type Identity, type KeyPair } from '../crypto/protocol';
import type { KeyStore, SessionRecord } from '../crypto/session';
import * as db from './db';

/** Retired signed prekeys stay usable this long for in-flight messages. */
const SPK_GRACE_MS = 30 * 24 * 3600 * 1000;
export const SPK_ROTATE_MS = 7 * 24 * 3600 * 1000;
export const OTK_BATCH = 100;
export const OTK_LOW_WATER = 25;

interface StoredSPK extends KeyPair {
  keyId: number;
  createdAt: number;
}

interface Counters {
  nextOtkId: number;
  nextSpkId: number;
}

export const localKeyStore: KeyStore = {
  async identity() {
    const id = await db.get<Identity>('kv', 'identity');
    if (!id) throw new Error('no local identity');
    return id;
  },
  async signedPreKey(keyId) {
    const cur = await db.get<StoredSPK>('kv', 'spk:current');
    if (cur?.keyId === keyId) return cur;
    const old = (await db.get<(StoredSPK & { retiredAt: number })[]>('kv', 'spk:old')) ?? [];
    return old.find((k) => k.keyId === keyId);
  },
  oneTimePreKey: (keyId) => db.get<KeyPair>('prekeys', keyId),
  removeOneTimePreKey: (keyId) => db.del('prekeys', keyId),
  loadSession: (peer) => db.get<SessionRecord>('sessions', peer),
  saveSession: (peer, rec) => db.put('sessions', peer, rec),
  deleteSession: (peer) => db.del('sessions', peer),
};

let countersLock: Promise<unknown> = Promise.resolve();

/**
 * Reserves `n` consecutive key ids and returns the first. The counter is
 * advanced (and stored) before any key is made, one caller at a time, so
 * overlapping or interrupted runs never hand out the same id twice.
 */
function reserveIds(counter: keyof Counters, n: number): Promise<number> {
  const run = async () => {
    const c = (await db.get<Counters>('kv', 'counters')) ?? { nextOtkId: 1, nextSpkId: 1 };
    const first = c[counter];
    c[counter] = first + n;
    await db.put('kv', 'counters', c);
    return first;
  };
  const next = countersLock.then(run, run);
  countersLock = next.catch(() => undefined);
  return next;
}

function spkJSON(id: Identity, spk: StoredSPK) {
  return { keyId: spk.keyId, pub: b64(spk.pub), sig: b64(sign(id.sig.priv, LABEL.signedPreKey, spk.pub)) };
}

/** Generates and stores `n` one-time prekeys; returns their public halves. */
export async function generateOneTimePreKeys(n = OTK_BATCH): Promise<{ keyId: number; pub: string }[]> {
  const first = await reserveIds('nextOtkId', n);
  const out: { keyId: number; pub: string }[] = [];
  for (let keyId = first; keyId < first + n; keyId++) {
    const kp = newDHKeyPair();
    await db.put('prekeys', keyId, kp);
    out.push({ keyId, pub: b64(kp.pub) });
  }
  return out;
}

/** Creates a fresh signed prekey and retires the current one. */
export async function rotateSignedPreKey(): Promise<{ keyId: number; pub: string; sig: string }> {
  const id = await localKeyStore.identity();
  const spk: StoredSPK = { ...newDHKeyPair(), keyId: await reserveIds('nextSpkId', 1), createdAt: Date.now() };
  const cur = await db.get<StoredSPK>('kv', 'spk:current');
  if (cur) {
    const now = Date.now();
    const old = ((await db.get<(StoredSPK & { retiredAt: number })[]>('kv', 'spk:old')) ?? []).filter(
      (k) => now - k.retiredAt < SPK_GRACE_MS,
    );
    old.push({ ...cur, retiredAt: now });
    await db.put('kv', 'spk:old', old);
  }
  await db.put('kv', 'spk:current', spk);
  return spkJSON(id, spk);
}

export async function signedPreKeyAge(): Promise<number> {
  const cur = await db.get<StoredSPK>('kv', 'spk:current');
  return cur ? Date.now() - cur.createdAt : Infinity;
}

/** Creates a new device identity and builds the registration request. */
export async function createIdentity(username: string) {
  const id = newIdentity();
  await db.put('kv', 'identity', id);
  const signedPreKey = await rotateSignedPreKey();
  const oneTimePreKeys = await generateOneTimePreKeys();
  return {
    identity: id,
    request: {
      username,
      sigKey: b64(id.sig.pub),
      dhKey: b64(id.dh.pub),
      dhKeySig: b64(id.dhSig),
      registerSig: b64(sign(id.sig.priv, LABEL.register, new TextEncoder().encode(username))),
      signedPreKey,
      oneTimePreKeys,
    },
  };
}
