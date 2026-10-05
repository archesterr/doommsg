import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as db from '../storage/db';
import { Messenger } from './messenger';
import { useApp } from './store';
import type { ChatMessage } from './types';

// Runs a hook between the conversation snapshot and its return, which is
// where a message saved concurrently with open() used to get lost.
const hooks = vi.hoisted(() => ({ afterSnapshot: null as null | (() => Promise<void>) }));

vi.mock('../storage/db', async (importOriginal) => {
  const real = await importOriginal<typeof import('../storage/db')>();
  return {
    ...real,
    messagesFor: async <T>(...args: Parameters<typeof real.messagesFor>) => {
      const list = await real.messagesFor<T>(...args);
      const hook = hooks.afterSnapshot;
      hooks.afterSnapshot = null;
      if (hook) await hook();
      return list;
    },
  };
});

function msg(id: string, ts: number, extra: Partial<ChatMessage> = {}): ChatMessage {
  return { id, peer: 'bob', dir: 'in', kind: 'text', body: id, ts, status: 'read', ...extra };
}

describe('opening a conversation (#17)', () => {
  let m: Messenger;
  let save: (msg: ChatMessage) => Promise<void>;

  beforeEach(async () => {
    await db.wipeAll();
    useApp.setState({ contacts: {}, messages: {}, active: undefined });
    m = new Messenger();
    save = (msg) => (m as unknown as { saveMessage(m: ChatMessage): Promise<void> }).saveMessage(msg);
    for (let i = 0; i < 3; i++) await db.putMessage(msg(`h${i}`, 1000 + i));
  });

  it('keeps a message saved while the conversation loads', async () => {
    hooks.afterSnapshot = () => save(msg('new', 5000, { status: 'delivered' }));
    await m.open('bob');
    expect(useApp.getState().messages.bob.map((x) => x.id)).toEqual(['h0', 'h1', 'h2', 'new']);
  });

  it('prefers the copy saved while loading over the snapshot', async () => {
    hooks.afterSnapshot = () => save(msg('h1', 1001, { body: 'edited' }));
    await m.open('bob');
    const list = useApp.getState().messages.bob;
    expect(list.map((x) => x.id)).toEqual(['h0', 'h1', 'h2']);
    expect(list[1].body).toBe('edited');
  });

  it('does not bring back a message deleted while the conversation loads', async () => {
    hooks.afterSnapshot = () => m.deleteLocal(msg('h1', 1001));
    await m.open('bob');
    expect(useApp.getState().messages.bob.map((x) => x.id)).toEqual(['h0', 'h2']);
  });

  it('does not bring back a message deleted while older ones load', async () => {
    for (let i = 0; i < 250; i++) await db.putMessage(msg(`o${i}`, i));
    await m.open('bob'); // the newest 200
    const first = useApp.getState().messages.bob[0];
    expect(first.id).not.toBe('o0');
    hooks.afterSnapshot = () => m.deleteLocal(msg('o0', 0));
    await m.loadOlder('bob');
    const ids = useApp.getState().messages.bob.map((x) => x.id);
    expect(ids).toContain('o1');
    expect(ids).not.toContain('o0');
  });

  it('does not bring back a chat deleted while it loads', async () => {
    hooks.afterSnapshot = () => m.deleteChat('bob');
    await m.open('bob');
    expect(useApp.getState().messages.bob).toBeUndefined();
  });

  it('loads again after a failed load', async () => {
    hooks.afterSnapshot = () => Promise.reject(new Error('disk'));
    await expect(m.open('bob')).rejects.toThrow('disk');
    expect(useApp.getState().messages.bob).toBeUndefined();
    await m.open('bob');
    expect(useApp.getState().messages.bob).toHaveLength(3);
  });
});
