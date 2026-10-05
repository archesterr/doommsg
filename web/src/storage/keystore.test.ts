import { beforeEach, describe, expect, it } from 'vitest';
import { b64 } from '../crypto/bytes';
import { newIdentity, type KeyPair } from '../crypto/protocol';
import * as db from './db';
import { generateOneTimePreKeys, localKeyStore, rotateSignedPreKey } from './keystore';

describe('prekey generation', () => {
  beforeEach(async () => {
    await db.wipeAll();
  });

  it('never hands out a one-time prekey id twice, even when runs overlap', async () => {
    const [a, b] = await Promise.all([generateOneTimePreKeys(5), generateOneTimePreKeys(5)]);
    const ids = [...a, ...b].map((k) => k.keyId);
    expect(new Set(ids).size).toBe(10);
    // Each id's stored private key belongs to the public key that was uploaded for it.
    for (const k of [...a, ...b]) {
      expect(b64((await db.get<KeyPair>('prekeys', k.keyId))!.pub)).toBe(k.pub);
    }
    const next = await generateOneTimePreKeys(1);
    expect(next[0].keyId).toBe(11);
  });

  it('keeps both counters when a rotation overlaps a top-up', async () => {
    await db.put('kv', 'identity', newIdentity());
    const [spk, otks] = await Promise.all([rotateSignedPreKey(), generateOneTimePreKeys(3)]);
    expect(spk.keyId).toBe(1);
    expect(otks.map((k) => k.keyId)).toEqual([1, 2, 3]);
    expect((await rotateSignedPreKey()).keyId).toBe(2);
    expect((await localKeyStore.signedPreKey(1))?.pub).toBeDefined();
    expect((await generateOneTimePreKeys(1))[0].keyId).toBe(4);
  });
});
