// Local persistence in IndexedDB, encrypted at rest.
//
// Every record value is sealed with AES-256-GCM under a device master key
// created as a *non-extractable* WebCrypto key. Script running in the page
// can use the key but can never read its bytes, so a copied IndexedDB
// directory, a disk image or a leaked backup is useless on its own.
// Only routing fields needed for indexes (conversation id, timestamp) are
// stored in the clear.

import { openDB, type DBSchema, type IDBPDatabase } from 'idb';
import { b64, unb64 } from '../crypto/bytes';

const DB_NAME = 'doommsg';
const DB_VERSION = 1;

interface Sealed {
  iv: Uint8Array;
  ct: ArrayBuffer;
}

interface Schema extends DBSchema {
  meta: { key: string; value: CryptoKey };
  kv: { key: string; value: Sealed };
  prekeys: { key: number; value: Sealed };
  sessions: { key: string; value: Sealed };
  contacts: { key: string; value: Sealed };
  messages: {
    key: string;
    value: { id: string; peer: string; ts: number; data: Sealed };
    indexes: { byPeerTs: [string, number] };
  };
}

export type StoreName = 'kv' | 'prekeys' | 'sessions' | 'contacts';

let dbp: Promise<IDBPDatabase<Schema>> | null = null;
let keyp: Promise<CryptoKey> | null = null;

function db(): Promise<IDBPDatabase<Schema>> {
  dbp ??= openDB<Schema>(DB_NAME, DB_VERSION, {
    upgrade(d) {
      d.createObjectStore('meta');
      d.createObjectStore('kv');
      d.createObjectStore('prekeys');
      d.createObjectStore('sessions');
      d.createObjectStore('contacts');
      const m = d.createObjectStore('messages', { keyPath: 'id' });
      m.createIndex('byPeerTs', ['peer', 'ts']);
    },
  });
  return dbp;
}

function masterKey(): Promise<CryptoKey> {
  keyp ??= (async () => {
    const d = await db();
    const existing = await d.get('meta', 'master');
    if (existing) return existing;
    const k = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    // add() fails if another tab won the race; then use theirs.
    try {
      await d.add('meta', k, 'master');
      return k;
    } catch {
      return (await d.get('meta', 'master'))!;
    }
  })();
  return keyp;
}

// JSON with Uint8Array support.
function encode(v: unknown): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify(v, (_k, val) => (val instanceof Uint8Array ? { $u8: b64(val) } : val)),
  );
}

function decode<T>(b: ArrayBuffer): T {
  return JSON.parse(new TextDecoder().decode(b), (_k, val) =>
    val && typeof val === 'object' && typeof val.$u8 === 'string' && Object.keys(val).length === 1
      ? unb64(val.$u8)
      : val,
  ) as T;
}

async function seal(v: unknown, aad: string): Promise<Sealed> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as BufferSource, additionalData: new TextEncoder().encode(aad) },
    await masterKey(),
    encode(v) as BufferSource,
  );
  return { iv, ct };
}

async function unseal<T>(s: Sealed, aad: string): Promise<T> {
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: s.iv as BufferSource, additionalData: new TextEncoder().encode(aad) },
    await masterKey(),
    s.ct,
  );
  return decode<T>(pt);
}

// The store name and key are bound as AAD so records cannot be swapped.
const aadFor = (store: string, key: IDBValidKey) => `${store}/${String(key)}`;

export async function get<T>(store: StoreName, key: string | number): Promise<T | undefined> {
  const s = await (await db()).get(store, key as never);
  return s ? unseal<T>(s, aadFor(store, key)) : undefined;
}

export async function put(store: StoreName, key: string | number, value: unknown): Promise<void> {
  const sealed = await seal(value, aadFor(store, key));
  await (await db()).put(store, sealed, key as never);
}

export async function del(store: StoreName, key: string | number): Promise<void> {
  await (await db()).delete(store, key as never);
}

export async function all<T>(store: StoreName): Promise<{ key: IDBValidKey; value: T }[]> {
  const d = await db();
  const tx = d.transaction(store);
  const out: { key: IDBValidKey; value: Sealed }[] = [];
  for await (const cursor of tx.store) out.push({ key: cursor.key, value: cursor.value });
  return Promise.all(out.map(async (r) => ({ key: r.key, value: await unseal<T>(r.value, aadFor(store, r.key)) })));
}

export async function keys(store: StoreName): Promise<IDBValidKey[]> {
  return (await db()).getAllKeys(store);
}

// ---- messages -------------------------------------------------------------

export async function putMessage<T extends { id: string; peer: string; ts: number }>(m: T): Promise<void> {
  const data = await seal(m, aadFor('messages', m.id));
  await (await db()).put('messages', { id: m.id, peer: m.peer, ts: m.ts, data });
}

export async function getMessage<T>(id: string): Promise<T | undefined> {
  const r = await (await db()).get('messages', id);
  return r ? unseal<T>(r.data, aadFor('messages', id)) : undefined;
}

export async function deleteMessage(id: string): Promise<void> {
  await (await db()).delete('messages', id);
}

/** Most recent `limit` messages of a conversation before `beforeTs`, oldest first. */
export async function messagesFor<T>(peer: string, limit = 200, beforeTs = Number.MAX_SAFE_INTEGER): Promise<T[]> {
  const d = await db();
  const range = IDBKeyRange.bound([peer, 0], [peer, beforeTs], false, true);
  const rows: { id: string; data: Sealed }[] = [];
  let cursor = await d.transaction('messages').store.index('byPeerTs').openCursor(range, 'prev');
  while (cursor && rows.length < limit) {
    rows.push({ id: cursor.value.id, data: cursor.value.data });
    cursor = await cursor.continue();
  }
  const out = await Promise.all(rows.map((r) => unseal<T>(r.data, aadFor('messages', r.id))));
  return out.reverse();
}

export async function deleteConversation(peer: string): Promise<void> {
  const d = await db();
  const tx = d.transaction('messages', 'readwrite');
  const range = IDBKeyRange.bound([peer, 0], [peer, Number.MAX_SAFE_INTEGER]);
  let cursor = await tx.store.index('byPeerTs').openCursor(range);
  while (cursor) {
    await cursor.delete();
    cursor = await cursor.continue();
  }
  await tx.done;
}

export async function allMessageIds(): Promise<{ id: string; peer: string }[]> {
  const d = await db();
  const rows = await d.getAll('messages');
  return rows.map((r) => ({ id: r.id, peer: r.peer }));
}

/** Irreversibly wipes all local data, including the master key. */
export async function wipeAll(): Promise<void> {
  if (dbp) (await dbp).close();
  dbp = null;
  keyp = null;
  await new Promise<void>((resolve, reject) => {
    const req = indexedDB.deleteDatabase(DB_NAME);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
    req.onblocked = () => resolve();
  });
}
