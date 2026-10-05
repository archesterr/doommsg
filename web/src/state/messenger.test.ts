import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { b64, fromUtf8, random, unb64, utf8 } from '../crypto/bytes';
import { newIdentity, type Identity } from '../crypto/protocol';
import { SessionCipher, type KeyStore, type SessionRecord } from '../crypto/session';
import type { PreKeyBundle } from '../crypto/x3dh';
import { ApiError } from '../net/api';
import { SendError, type InboundMessage, type Socket } from '../net/socket';
import * as db from '../storage/db';
import { createIdentity } from '../storage/keystore';
import { Messenger } from './messenger';
import { setContact, useApp } from './store';
import { defaultSettings, type ChatMessage, type Contact } from './types';

/** The parts of a Messenger these tests reach into. */
interface Internals {
  socket: Socket;
  cipher: Pick<SessionCipher, 'encrypt' | 'decrypt'>;
  account: { username: string; createdAt: number } | null;
  inbound: Promise<void>;
  seenSids: Set<number>;
  saveMessage(m: ChatMessage): Promise<void>;
  purgeExpired(): Promise<void>;
  sendContent(peer: string, content: { t: string }, eph?: boolean): Promise<{ ts: number }>;
}

const inner = (m: Messenger) => m as unknown as Internals;

// Node's setImmediate (not in the DOM typings), which tests never fake.
const { setImmediate } = globalThis as unknown as { setImmediate: (fn: () => void) => void };
const nextTask = () => new Promise<void>((r) => setImmediate(r));

/** Lets IndexedDB and fire-and-forget sends run. */
async function turns(n = 20): Promise<void> {
  for (let i = 0; i < n; i++) await nextTask();
}

/** Polls without timers, so fake timers are only advanced by the test. */
async function until(cond: () => boolean): Promise<void> {
  for (let i = 0; i < 100_000 && !cond(); i++) await nextTask();
  expect(cond()).toBe(true);
}

class MemoryStore implements KeyStore {
  sessions = new Map<string, SessionRecord>();
  constructor(public id: Identity) {}
  async identity() {
    return this.id;
  }
  async signedPreKey() {
    return undefined;
  }
  async oneTimePreKey() {
    return undefined;
  }
  async removeOneTimePreKey() {}
  async loadSession(peer: string) {
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

type Registration = Awaited<ReturnType<typeof createIdentity>>['request'];

function bundleOf(r: Registration): PreKeyBundle {
  return {
    sigKey: unb64(r.sigKey),
    dhKey: unb64(r.dhKey),
    dhKeySig: unb64(r.dhKeySig),
    signedPreKey: { keyId: r.signedPreKey.keyId, pub: unb64(r.signedPreKey.pub), sig: unb64(r.signedPreKey.sig) },
    oneTimePreKey: { keyId: r.oneTimePreKeys[0].keyId, pub: unb64(r.oneTimePreKeys[0].pub) },
  };
}

function contact(username: string): Contact {
  const id = newIdentity();
  return { username, identity: { sigKey: id.sig.pub, dhKey: id.dh.pub }, verified: false, timer: 0, lastTs: 0, unread: 0, hue: 0 };
}

function msg(id: string, peer: string, extra: Partial<ChatMessage> = {}): ChatMessage {
  return { id, peer, dir: 'in', kind: 'text', body: 'x', ts: Date.now(), status: 'delivered', ...extra };
}

/**
 * A Messenger signed in as alice whose socket is stubbed: acks and sends
 * are recorded, and `setOnline` decides whether there is a connection.
 * `fakeCipher` replaces the ratchet with plaintext JSON payloads.
 */
function harness({ fakeCipher = false } = {}) {
  const m = new Messenger();
  const x = inner(m);
  x.account = { username: 'alice', createdAt: 1 };
  const sock = x.socket;
  sock.state = 'online';
  const acks: number[][] = [];
  const sent: { to: string; payload: string; eph: boolean }[] = [];
  vi.spyOn(sock, 'ack').mockImplementation((ids) => {
    if (sock.state !== 'online') return false;
    acks.push(ids);
    return true;
  });
  vi.spyOn(sock, 'send').mockImplementation(async (to, payload, eph = false) => {
    if (sock.state !== 'online') throw new SendError('offline');
    sent.push({ to, payload, eph });
    return { ts: Date.now() };
  });
  vi.spyOn(sock, 'start').mockImplementation(() => {});
  vi.spyOn(sock, 'stop').mockImplementation(() => {});
  if (fakeCipher) {
    x.cipher = {
      decrypt: vi.fn(async (_peer: string, payload: string) => utf8(payload)),
      encrypt: async (_peer: string, plaintext: Uint8Array) => fromUtf8(plaintext),
    };
  }
  // Receipts are sent in the background; track them so tests can wait.
  const inflight = new Set<Promise<unknown>>();
  const sendContent = x.sendContent.bind(m);
  x.sendContent = (...args) => {
    const p = sendContent(...args);
    inflight.add(p);
    void p.catch(() => {}).finally(() => inflight.delete(p));
    return p;
  };
  const setOnline = (online: boolean) => {
    sock.state = online ? 'online' : 'offline';
    sock.onState(sock.state);
  };
  const deliver = (e: Omit<InboundMessage, 'ts'> & { ts?: number }) => sock.onMessage({ ts: Date.now(), ...e });
  /** Waits until every queued envelope has been processed and every send is done. */
  const idle = async () => {
    for (;;) {
      const p = x.inbound;
      await p;
      await Promise.allSettled([...inflight]);
      await turns();
      if (p === x.inbound && !inflight.size) return;
    }
  };
  // Nothing of one test may still be writing when the next wipes the database.
  settles.push(async () => {
    m.stop();
    await idle();
  });
  const receipts = () =>
    sent
      .map((s) => ({ to: s.to, c: JSON.parse(s.payload) as { t: string; ids: string[]; s: string } }))
      .filter((r) => r.c.t === 'receipt');
  return { m, x, sock, acks, sent, receipts, setOnline, deliver, idle };
}

const settles: (() => Promise<void>)[] = [];

const text = (id: string, body = 'hi') => JSON.stringify({ t: 'text', id, body, ts: 1 });

beforeEach(async () => {
  await db.wipeAll();
  useApp.setState({ contacts: {}, messages: {}, active: undefined, typing: {}, phase: 'loading', settings: defaultSettings() });
});

afterEach(async () => {
  for (const settle of settles.splice(0)) await settle();
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('acks and receipts (#9)', () => {
  it('acknowledges a backlog in frames of at most 500 ids and sends one receipt per peer', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const h = harness({ fakeCipher: true });
    setContact(contact('bob'));
    setContact(contact('carol'));
    const n = 520;
    for (let sid = 1; sid <= n; sid++) h.deliver({ sid, from: sid % 2 ? 'bob' : 'carol', payload: text(`m${sid}`) });
    await h.idle();

    expect(h.acks.length).toBeLessThanOrEqual(2);
    for (const frame of h.acks) expect(frame.length).toBeLessThanOrEqual(500);
    expect(h.acks.flat().sort((a, b) => a - b)).toEqual(Array.from({ length: n }, (_, i) => i + 1));

    const receipts = h.receipts();
    expect(receipts.map((r) => r.to).sort()).toEqual(['bob', 'carol']);
    for (const r of receipts) {
      expect(r.c.s).toBe('delivered');
      expect(r.c.ids).toHaveLength(n / 2);
    }
  }, 60_000);

  it('acknowledges on a timer while a backlog is still being processed', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const h = harness({ fakeCipher: true });
    setContact(contact('bob'));
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const decrypt = h.x.cipher.decrypt as ReturnType<typeof vi.fn>;
    decrypt.mockImplementationOnce(async (_p: string, payload: string) => utf8(payload));
    decrypt.mockImplementationOnce(async (_p: string, payload: string) => {
      await gate;
      return utf8(payload);
    });
    h.deliver({ sid: 1, from: 'bob', payload: text('m1') });
    h.deliver({ sid: 2, from: 'bob', payload: text('m2') });
    await until(() => h.x.seenSids.has(1) && decrypt.mock.calls.length === 2);
    expect(h.acks).toEqual([]);
    await vi.advanceTimersByTimeAsync(250);
    expect(h.acks).toEqual([[1]]);
    release();
    await h.idle();
    expect(h.acks).toEqual([[1], [2]]);
  });

  it('keeps acks and receipts that missed the connection and sends them on the next one', async () => {
    const h = harness({ fakeCipher: true });
    setContact(contact('bob'));
    h.setOnline(false);
    for (const sid of [1, 2, 3]) h.deliver({ sid, from: 'bob', payload: text(`m${sid}`) });
    await h.idle();
    expect(h.acks).toEqual([]);
    expect(h.receipts()).toEqual([]);

    h.setOnline(true);
    await turns();
    expect(h.acks).toEqual([[1, 2, 3]]);
    expect(h.receipts()).toEqual([{ to: 'bob', c: { t: 'receipt', ids: ['m1', 'm2', 'm3'], s: 'delivered' } }]);

    // Had the acks been lost too, the server delivers again: the envelopes
    // are recognised as seen and acknowledged without being decrypted.
    const decrypt = h.x.cipher.decrypt as ReturnType<typeof vi.fn>;
    decrypt.mockClear();
    for (const sid of [1, 2, 3]) h.deliver({ sid, from: 'bob', payload: text(`m${sid}`) });
    await h.idle();
    expect(decrypt).not.toHaveBeenCalled();
    expect(h.acks).toEqual([
      [1, 2, 3],
      [1, 2, 3],
    ]);
  });

  it('keeps processing envelopes when an ack cannot be sent', async () => {
    const h = harness({ fakeCipher: true });
    setContact(contact('bob'));
    vi.mocked(h.sock.ack).mockImplementationOnce(() => {
      throw new Error('InvalidStateError');
    });
    h.deliver({ sid: 1, from: 'bob', payload: text('m1') });
    await h.idle();
    h.deliver({ sid: 2, from: 'bob', payload: text('m2') });
    await h.idle();
    expect(await db.getMessage('m2')).toBeDefined();
    expect(h.acks.flat()).toEqual([1, 2]);
  });
});

describe('deleted chats (#10)', () => {
  it('keeps the session, so the next message brings the chat back', async () => {
    const { request } = await createIdentity('alice');
    const h = harness();
    const bobId = newIdentity();
    h.m.api.identityOf = async () => ({ sigKey: bobId.sig.pub, dhKey: bobId.dh.pub, dhKeySig: bobId.dhSig });
    const bob = new SessionCipher(new MemoryStore(bobId), {
      fetchBundle: async () => bundleOf(request),
      checkIdentity: async () => {},
    });
    const fromBob = async (sid: number, id: string, body: string) =>
      h.deliver({ sid, from: 'bob', payload: await bob.encrypt('alice', utf8(text(id, body))) });

    await fromBob(1, 'm1', 'hi');
    await h.idle();
    expect(h.m.contact('bob')).toBeDefined();
    await h.m.sendText('bob', 'hello');
    for (const s of h.sent) await bob.decrypt('alice', s.payload); // the session is established

    await h.m.deleteChat('bob');
    expect(h.m.contact('bob')).toBeUndefined();

    await fromBob(2, 'm2', 'still there?');
    await h.idle();
    expect(h.m.contact('bob')).toBeDefined();
    expect(await db.getMessage('m2')).toMatchObject({ peer: 'bob', body: 'still there?' });
    expect(h.acks.flat()).toEqual([1, 2]);
  });

  it('does not silently drop an undecryptable message from someone without a chat', async () => {
    await createIdentity('alice');
    const h = harness();
    const carol = newIdentity();
    h.m.api.identityOf = async () => ({ sigKey: carol.sig.pub, dhKey: carol.dh.pub, dhKeySig: carol.dhSig });
    const junk = JSON.stringify({ v: 1, h: { d: b64(random(32)), p: 0, n: 0 }, c: b64(random(64)) });
    h.deliver({ sid: 7, from: 'carol', payload: junk });
    await h.idle();

    expect(h.m.contact('carol')?.identity.sigKey).toEqual(carol.sig.pub);
    await h.m.open('carol');
    expect(useApp.getState().messages.carol.map((x) => x.sys?.key)).toEqual(['sys.decryptFailed']);
    expect(h.acks.flat()).toEqual([7]); // it will never decrypt: not delivered again
  });
});

describe('transient failures (#14)', () => {
  it('leaves an envelope unacknowledged when the directory is unreachable, and retries it', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const { request } = await createIdentity('alice');
    const h = harness();
    const bobId = newIdentity();
    let up = false;
    h.m.api.identityOf = async () => {
      if (!up) throw new ApiError(429, 'rate_limited');
      return { sigKey: bobId.sig.pub, dhKey: bobId.dh.pub, dhKeySig: bobId.dhSig };
    };
    const bob = new SessionCipher(new MemoryStore(bobId), {
      fetchBundle: async () => bundleOf(request),
      checkIdentity: async () => {},
    });
    h.deliver({ sid: 1, from: 'bob', payload: await bob.encrypt('alice', utf8(text('m1'))) });
    await h.idle();
    expect(h.acks).toEqual([]);
    expect(h.x.seenSids.has(1)).toBe(false);
    expect(h.m.contact('bob')).toBeUndefined();

    up = true;
    await vi.advanceTimersByTimeAsync(2_000);
    await h.idle();
    expect(h.m.contact('bob')).toBeDefined();
    expect(await db.getMessage('m1')).toMatchObject({ body: 'hi' });
    expect(h.acks).toEqual([[1]]);
  });

  it('acknowledges an envelope whose sender no longer exists', async () => {
    const { request } = await createIdentity('alice');
    const h = harness();
    h.m.api.identityOf = async () => {
      throw new ApiError(404, 'no_such_user');
    };
    const bob = new SessionCipher(new MemoryStore(newIdentity()), {
      fetchBundle: async () => bundleOf(request),
      checkIdentity: async () => {},
    });
    h.deliver({ sid: 1, from: 'bob', payload: await bob.encrypt('alice', utf8(text('m1'))) });
    await h.idle();
    expect(h.acks).toEqual([[1]]);
    expect(h.m.contact('bob')).toBeUndefined();
  });
});

describe('disappearing messages (#11)', () => {
  it('never loses an expiry to a concurrent purge or save', async () => {
    const h = harness();
    for (let trial = 0; trial < 5; trial++) {
      for (let i = 0; i < 5; i++) await h.x.saveMessage(msg(`old${trial}.${i}`, 'bob', { expiresAt: Date.now() - 10 }));
      const fresh = [`a${trial}`, `b${trial}`];
      await Promise.all([
        h.x.purgeExpired(),
        ...fresh.map((id) => h.x.saveMessage(msg(id, 'bob', { expiresAt: Date.now() + 60_000 }))),
      ]);
      const exp = ((await db.get<{ id: string }[]>('kv', 'expiries')) ?? []).map((e) => e.id);
      expect(exp).toEqual(expect.arrayContaining(fresh));
    }
  });
});

describe('prekey maintenance (#12)', () => {
  it('runs one top-up at a time', async () => {
    await createIdentity('alice');
    const h = harness();
    const uploads: { keyId: number }[][] = [];
    const keyStatus = vi.fn(async () => ({ oneTimePreKeys: 0, max: 500 }));
    h.m.api.keyStatus = keyStatus;
    h.m.api.addOneTimePreKeys = async (keys) => {
      uploads.push(keys);
    };
    h.sock.onSynced();
    h.sock.onSynced();
    await vi.waitFor(() => expect(uploads.length).toBeGreaterThan(0));
    await turns(100);
    expect(keyStatus).toHaveBeenCalledTimes(1);
    expect(uploads).toHaveLength(1);
    expect(uploads[0][0].keyId).toBe(101); // after the 100 made at registration
  });
});

describe('a stopped messenger (#15)', () => {
  it('leaves queued envelopes to the tab that took over', async () => {
    const h = harness({ fakeCipher: true });
    setContact(contact('bob'));
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const decrypt = h.x.cipher.decrypt as ReturnType<typeof vi.fn>;
    decrypt.mockImplementationOnce(async (_p: string, payload: string) => {
      await gate;
      return utf8(payload);
    });
    for (const sid of [1, 2, 3]) h.deliver({ sid, from: 'bob', payload: text(`m${sid}`) });
    await until(() => decrypt.mock.calls.length === 1);
    h.m.stop();
    release();
    await h.idle();

    expect(decrypt).toHaveBeenCalledTimes(1);
    expect(h.x.seenSids.has(2) || h.x.seenSids.has(3)).toBe(false);
    expect(h.acks.flat()).not.toContain(2);
    expect(h.acks.flat()).not.toContain(3);
    expect(await db.getMessage('m2')).toBeUndefined();
  });

  it('stops when another connection replaces this one', async () => {
    const h = harness({ fakeCipher: true });
    setContact(contact('bob'));
    h.sock.onState('replaced');
    expect(useApp.getState().phase).toBe('elsewhere');
    h.deliver({ sid: 1, from: 'bob', payload: text('m1') });
    await h.idle();
    expect(h.x.cipher.decrypt).not.toHaveBeenCalled();
    expect(h.x.seenSids.has(1)).toBe(false);
  });

  it('runs no maintenance or purge', async () => {
    const h = harness();
    await h.x.saveMessage(msg('old', 'bob', { expiresAt: Date.now() - 10 }));
    const keyStatus = vi.fn(async () => ({ oneTimePreKeys: 0, max: 500 }));
    h.m.api.keyStatus = keyStatus;
    h.m.stop();
    h.sock.onSynced();
    await h.x.purgeExpired();
    await turns();
    expect(keyStatus).not.toHaveBeenCalled();
    expect(await db.getMessage('old')).toBeDefined();
  });
});

describe('sending (#16)', () => {
  it('does not bring back a message deleted while it was being sent', async () => {
    const h = harness();
    useApp.setState({ messages: { bob: [] } });
    let accept!: (v: { ts: number }) => void;
    const sends: string[] = [];
    h.x.sendContent = async (_peer, c) => {
      sends.push(c.t);
      return c.t === 'text' ? new Promise((r) => (accept = r)) : { ts: 1 };
    };
    const sending = h.m.sendText('bob', 'regret');
    await vi.waitFor(() => expect(sends).toEqual(['text']));
    const pending = useApp.getState().messages.bob[0];
    expect(pending.status).toBe('pending');
    await h.m.deleteForEveryone(pending);
    accept({ ts: 2 });
    await sending;
    expect(useApp.getState().messages.bob).toEqual([]);
    expect(await db.getMessage(pending.id)).toBeUndefined();
  });

  it('does not resend a failed message that was deleted for everyone', async () => {
    const h = harness();
    useApp.setState({ messages: { bob: [] } });
    let fail!: (e: Error) => void;
    const sends: string[] = [];
    h.x.sendContent = async (_peer, c) => {
      sends.push(c.t);
      if (c.t === 'text' && sends.length === 1) return new Promise((_r, j) => (fail = j));
      if (c.t === 'delete') throw new SendError('offline');
      return { ts: 1 };
    };
    const sending = h.m.sendText('bob', 'regret');
    await vi.waitFor(() => expect(sends).toEqual(['text']));
    const pending = useApp.getState().messages.bob[0];
    await h.m.deleteForEveryone(pending);
    fail(new SendError('offline'));
    await sending;
    await h.m.retryFailed('bob');
    await h.m.retry(pending); // e.g. a stale retry button
    expect(sends).toEqual(['text', 'delete']);
    expect(await db.getMessage(pending.id)).toBeUndefined();
  });

  it('never sends a message deleted before it went out', async () => {
    const h = harness();
    const sends: string[] = [];
    h.x.sendContent = async (_peer, c) => {
      sends.push(c.t);
      return { ts: 1 };
    };
    const m = msg('gone', 'bob', { dir: 'out', status: 'pending' });
    await (h.m as unknown as { deliver(m: ChatMessage): Promise<void> }).deliver(m);
    expect(sends).toEqual([]);
    expect(await db.getMessage('gone')).toBeUndefined();
  });
});

describe('read state (#18)', () => {
  it('marks messages read when the tab becomes visible again', async () => {
    const listeners = new Map<string, () => void>();
    const doc = {
      visibilityState: 'hidden',
      addEventListener: (type: string, fn: () => void) => listeners.set(type, fn),
      removeEventListener: (type: string) => listeners.delete(type),
    };
    vi.stubGlobal('document', doc);
    const h = harness({ fakeCipher: true });
    await db.put('kv', 'account', { username: 'alice', createdAt: 1 });
    const bob = { ...contact('bob'), unread: 1 };
    await db.put('contacts', 'bob', bob);
    await db.putMessage(msg('m1', 'bob'));
    await h.m.boot();
    try {
      await h.m.open('bob');
      // Hidden: nothing is read yet, not even the unread count.
      expect(useApp.getState().messages.bob[0].status).toBe('delivered');
      expect(h.m.contact('bob')?.unread).toBe(1);

      doc.visibilityState = 'visible';
      listeners.get('visibilitychange')?.();
      await vi.waitFor(() => expect(h.receipts()).toEqual([{ to: 'bob', c: { t: 'receipt', ids: ['m1'], s: 'read' } }]));
      expect(useApp.getState().messages.bob[0].status).toBe('read');
      expect(h.m.contact('bob')?.unread).toBe(0);
    } finally {
      h.m.stop();
    }
    expect(listeners.has('visibilitychange')).toBe(false);
  });
});

describe('typing indicator (#19)', () => {
  it('lapses on its own when the peer goes quiet', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const h = harness({ fakeCipher: true });
    setContact(contact('bob'));
    h.deliver({ from: 'bob', payload: JSON.stringify({ t: 'typing', on: true }), eph: true });
    await h.idle();
    expect(useApp.getState().typing.bob).toBeGreaterThan(Date.now());
    await vi.advanceTimersByTimeAsync(6_000);
    expect(useApp.getState().typing.bob).toBe(0);
  });
});
