import { beforeEach, describe, expect, it } from 'vitest';
import * as db from './db';

describe('encrypted local store', () => {
  beforeEach(async () => {
    await db.wipeAll();
  });

  it('round-trips values including binary fields', async () => {
    const value = { name: 'alice', key: new Uint8Array([1, 2, 3, 255]), nested: { list: [new Uint8Array(32)] } };
    await db.put('kv', 'x', value);
    expect(await db.get('kv', 'x')).toEqual(value);
  });

  it('never stores plaintext', async () => {
    await db.put('contacts', 'bob', { secret: 'top-secret-marker' });
    const raw = await new Promise<unknown>((resolve, reject) => {
      const req = indexedDB.open('doommsg');
      req.onsuccess = () => {
        const get = req.result.transaction('contacts').objectStore('contacts').get('bob');
        get.onsuccess = () => {
          resolve(get.result);
          req.result.close();
        };
        get.onerror = () => reject(get.error);
      };
    });
    const bytes = new Uint8Array((raw as { ct: ArrayBuffer }).ct);
    expect(new TextDecoder().decode(bytes)).not.toContain('top-secret-marker');
  });

  it('binds ciphertext to its record so records cannot be swapped', async () => {
    await db.put('kv', 'a', { v: 1 });
    await db.put('kv', 'b', { v: 2 });
    // Copy b's sealed bytes over a, as an attacker with disk access might.
    await new Promise<void>((resolve, reject) => {
      const req = indexedDB.open('doommsg');
      req.onsuccess = () => {
        const tx = req.result.transaction('kv', 'readwrite');
        const store = tx.objectStore('kv');
        const g = store.get('b');
        g.onsuccess = () => store.put(g.result, 'a');
        tx.oncomplete = () => {
          req.result.close();
          resolve();
        };
        tx.onerror = () => reject(tx.error);
      };
    });
    await expect(db.get('kv', 'a')).rejects.toThrow();
  });

  it('orders and pages conversation messages', async () => {
    for (let i = 0; i < 5; i++) await db.putMessage({ id: `m${i}`, peer: 'bob', ts: 1000 + i, body: `hi ${i}` });
    await db.putMessage({ id: 'other', peer: 'carol', ts: 1002, body: 'x' });
    const last3 = await db.messagesFor<{ id: string }>('bob', 3);
    expect(last3.map((m) => m.id)).toEqual(['m2', 'm3', 'm4']);
    const older = await db.messagesFor<{ id: string }>('bob', 10, 1002);
    expect(older.map((m) => m.id)).toEqual(['m0', 'm1']);
    await db.deleteConversation('bob');
    expect(await db.messagesFor('bob')).toEqual([]);
    expect(await db.messagesFor('carol')).toHaveLength(1);
  });
});
