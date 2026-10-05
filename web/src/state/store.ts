import { create } from 'zustand';
import type { SocketState } from '../net/socket';
import { defaultSettings, type Account, type ChatMessage, type Contact, type Settings } from './types';

export type Phase = 'loading' | 'onboarding' | 'elsewhere' | 'ready' | 'unsupported';

export interface Toast {
  id: number;
  text: string;
  tone?: 'info' | 'error';
}

export interface AppState {
  phase: Phase;
  account?: Account;
  settings: Settings;
  contacts: Record<string, Contact>;
  /** Loaded conversations only (lazy). */
  messages: Record<string, ChatMessage[]>;
  active?: string;
  conn: SocketState;
  /** peer → epoch ms until which they are shown as typing. */
  typing: Record<string, number>;
  toasts: Toast[];
}

export const useApp = create<AppState>(() => ({
  phase: 'loading',
  settings: defaultSettings(navigator.language?.startsWith('fa') ? 'fa' : 'en'),
  contacts: {},
  messages: {},
  conn: 'offline',
  typing: {},
  toasts: [],
}));

let toastSeq = 0;
export function toast(text: string, tone: Toast['tone'] = 'info'): void {
  const id = ++toastSeq;
  useApp.setState((s) => ({ toasts: [...s.toasts, { id, text, tone }] }));
  setTimeout(() => useApp.setState((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })), 4000);
}

export function upsertMessage(m: ChatMessage): void {
  useApp.setState((s) => {
    const list = s.messages[m.peer];
    if (!list) return {};
    const i = list.findIndex((x) => x.id === m.id);
    const next = i >= 0 ? list.map((x, j) => (j === i ? m : x)) : insertSorted(list, m);
    return { messages: { ...s.messages, [m.peer]: next } };
  });
}

function insertSorted(list: ChatMessage[], m: ChatMessage): ChatMessage[] {
  let i = list.length;
  while (i > 0 && list[i - 1].ts > m.ts) i--;
  return [...list.slice(0, i), m, ...list.slice(i)];
}

/** Ids removed while a page of a conversation was loading, by peer. */
const removedWhileLoading = new Map<string, Set<string>[]>();

/**
 * Starts recording the messages of `peer` removed from here on; call the
 * result once the page has loaded to stop and get them. A page read from
 * the database just before a removal would otherwise bring it back.
 */
export function trackRemovals(peer: string): () => Set<string> {
  const ids = new Set<string>();
  removedWhileLoading.set(peer, [...(removedWhileLoading.get(peer) ?? []), ids]);
  return () => {
    const rest = (removedWhileLoading.get(peer) ?? []).filter((s) => s !== ids);
    if (rest.length) removedWhileLoading.set(peer, rest);
    else removedWhileLoading.delete(peer);
    return ids;
  };
}

export function removeMessages(peer: string, ids: Set<string>): void {
  for (const loading of removedWhileLoading.get(peer) ?? []) for (const id of ids) loading.add(id);
  useApp.setState((s) => {
    const list = s.messages[peer];
    if (!list) return {};
    return { messages: { ...s.messages, [peer]: list.filter((m) => !ids.has(m.id)) } };
  });
}

export function setContact(c: Contact): void {
  useApp.setState((s) => ({ contacts: { ...s.contacts, [c.username]: c } }));
}
