// The messaging engine. Owns the session cipher, socket and persistence and
// keeps the UI store in sync. All message content — text, receipts, typing
// indicators, timer changes and call signalling — travels inside the
// end-to-end encrypted channel; the server only routes opaque envelopes.

import { equal, fromUtf8, utf8 } from '../crypto/bytes';
import type { PublicIdentity } from '../crypto/protocol';
import { DecryptError, SessionCipher } from '../crypto/session';
import { Api, ApiError } from '../net/api';
import { SendError, Socket, type InboundMessage } from '../net/socket';
import * as db from '../storage/db';
import {
  createIdentity,
  generateOneTimePreKeys,
  localKeyStore,
  OTK_BATCH,
  OTK_LOW_WATER,
  rotateSignedPreKey,
  signedPreKeyAge,
  SPK_ROTATE_MS,
} from '../storage/keystore';
import { removeMessages, setContact, toast, upsertMessage, useApp } from './store';
import { defaultSettings, type Account, type ChatMessage, type Contact, type Settings } from './types';

// ---- inner (encrypted) content protocol ----------------------------------

export type CallSignal =
  | { op: 'offer'; callId: string; sdp: string; video: boolean }
  | { op: 'answer'; callId: string; sdp: string }
  | { op: 'ice'; callId: string; candidate: RTCIceCandidateInit }
  | { op: 'renegotiate'; callId: string; sdp: string }
  | { op: 'renegotiate-answer'; callId: string; sdp: string }
  | { op: 'hangup' | 'decline' | 'busy' | 'ringing'; callId: string };

type Content =
  | { t: 'text'; id: string; body: string; ts: number; exp?: number; reply?: { id: string; body: string; mine: boolean } }
  | { t: 'receipt'; ids: string[]; s: 'delivered' | 'read' }
  | { t: 'typing'; on: boolean }
  | { t: 'timer'; exp: number }
  | { t: 'delete'; ids: string[] }
  | { t: 'call'; sig: CallSignal };

const MAX_BODY = 8000;
const TYPING_TTL = 6000;

type CallHandler = (from: string, sig: CallSignal) => void;

function newId(): string {
  return crypto.randomUUID();
}

function avatarHue(name: string): number {
  let h = 0;
  for (const ch of name) h = (h * 31 + ch.codePointAt(0)!) % 360;
  return h;
}

export class Messenger {
  readonly api: Api;
  private socket: Socket;
  private cipher: SessionCipher;
  private account: Account | null = null;
  private seenSids = new Set<number>();
  private seenOrder: number[] = [];
  private inbound: Promise<void> = Promise.resolve();
  private expiryTimer: ReturnType<typeof setInterval> | null = null;
  private callHandler: CallHandler = () => {};
  private typingSentAt = new Map<string, number>();

  constructor() {
    this.api = new Api(
      () => this.account?.username ?? null,
      () => localKeyStore.identity(),
    );
    this.socket = new Socket((refresh) =>
      refresh || !this.api.authToken ? this.api.login() : Promise.resolve(this.api.authToken!),
    );
    this.socket.onState = (conn) => {
      useApp.setState({ conn });
      if (conn === 'replaced') useApp.setState({ phase: 'elsewhere' });
    };
    this.socket.onMessage = (m) => {
      // Strictly sequential processing preserves per-peer ordering.
      this.inbound = this.inbound.then(() => this.handleInbound(m)).catch((e) => console.error('inbound', e));
    };
    this.socket.onSynced = () => void this.maintainPreKeys();
    this.cipher = new SessionCipher(localKeyStore, {
      fetchBundle: (peer) => this.api.bundle(peer),
      checkIdentity: (peer, id) => this.checkIdentity(peer, id),
    });
  }

  onCallSignal(h: CallHandler): void {
    this.callHandler = h;
  }

  get username(): string | null {
    return this.account?.username ?? null;
  }

  // ---- lifecycle ----------------------------------------------------------

  async boot(): Promise<void> {
    const settings = (await db.get<Settings>('kv', 'settings')) ?? useApp.getState().settings;
    useApp.setState({ settings: { ...defaultSettings(settings.lang), ...settings } });
    this.account = (await db.get<Account>('kv', 'account')) ?? null;
    if (!this.account) {
      useApp.setState({ phase: 'onboarding' });
      return;
    }
    const contacts: Record<string, Contact> = {};
    for (const { value } of await db.all<Contact>('contacts')) contacts[value.username] = value;
    const seen = (await db.get<number[]>('kv', 'seenSids')) ?? [];
    this.seenOrder = seen;
    this.seenSids = new Set(seen);
    useApp.setState({ account: this.account, contacts, phase: 'ready' });
    await this.purgeExpired();
    this.expiryTimer = setInterval(() => void this.purgeExpired(), 5000);
    this.socket.start();
  }

  async register(username: string, registrationCode?: string): Promise<void> {
    username = username.trim().toLowerCase();
    const { request } = await createIdentity(username);
    try {
      await this.api.register({ ...request, registrationCode: registrationCode || undefined });
    } catch (e) {
      await db.wipeAll();
      throw e;
    }
    this.account = { username, createdAt: Date.now() };
    await db.put('kv', 'account', this.account);
    await db.put('kv', 'settings', useApp.getState().settings);
    await this.boot();
  }

  stop(): void {
    this.socket.stop();
    if (this.expiryTimer) clearInterval(this.expiryTimer);
  }

  async wipeDevice(): Promise<void> {
    this.stop();
    await this.api.logout();
    await db.wipeAll();
    location.reload();
  }

  async deleteAccount(): Promise<void> {
    await this.api.deleteAccount();
    this.stop();
    await db.wipeAll();
    location.reload();
  }

  async updateSettings(patch: Partial<Settings>): Promise<void> {
    const settings = { ...useApp.getState().settings, ...patch };
    useApp.setState({ settings });
    if (this.account) await db.put('kv', 'settings', settings);
  }

  private async maintainPreKeys(): Promise<void> {
    try {
      if ((await signedPreKeyAge()) > SPK_ROTATE_MS) {
        await this.api.putSignedPreKey(await rotateSignedPreKey());
      }
      const { oneTimePreKeys, max } = await this.api.keyStatus();
      if (oneTimePreKeys < OTK_LOW_WATER) {
        const n = Math.min(OTK_BATCH, max - oneTimePreKeys);
        if (n > 0) await this.api.addOneTimePreKeys(await generateOneTimePreKeys(n));
      }
    } catch (e) {
      console.warn('prekey maintenance failed', e);
    }
  }

  // ---- contacts -----------------------------------------------------------

  private async saveContact(c: Contact): Promise<void> {
    setContact(c);
    await db.put('contacts', c.username, c);
  }

  contact(username: string): Contact | undefined {
    return useApp.getState().contacts[username];
  }

  async addContact(raw: string): Promise<Contact> {
    const username = raw.trim().replace(/^@/, '').toLowerCase();
    if (!/^[a-z0-9_]{3,32}$/.test(username)) throw new ApiError(400, 'bad_username');
    if (username === this.username) throw new ApiError(400, 'self');
    const existing = this.contact(username);
    if (existing) return existing;
    const id = await this.api.identityOf(username);
    const c: Contact = {
      username,
      identity: { sigKey: id.sigKey, dhKey: id.dhKey },
      verified: false,
      timer: 0,
      lastTs: Date.now(),
      unread: 0,
      hue: avatarHue(username),
    };
    await this.saveContact(c);
    return c;
  }

  async renameContact(username: string, nickname: string): Promise<void> {
    const c = this.contact(username);
    if (c) await this.saveContact({ ...c, nickname: nickname.trim().slice(0, 64) || undefined });
  }

  async setVerified(username: string, verified: boolean): Promise<void> {
    const c = this.contact(username);
    if (!c) return;
    await this.saveContact({ ...c, verified, identityChanged: undefined });
    await this.system(username, verified ? 'sys.verified' : 'sys.unverified');
  }

  async acknowledgeIdentityChange(username: string): Promise<void> {
    const c = this.contact(username);
    if (c) await this.saveContact({ ...c, identityChanged: undefined });
  }

  async setBlocked(username: string, blocked: boolean): Promise<void> {
    const c = this.contact(username);
    if (c) await this.saveContact({ ...c, blocked });
  }

  async deleteChat(username: string): Promise<void> {
    await db.deleteConversation(username);
    await db.del('contacts', username);
    await this.cipher.reset(username);
    useApp.setState((s) => {
      const contacts = { ...s.contacts };
      const messages = { ...s.messages };
      delete contacts[username];
      delete messages[username];
      return { contacts, messages, active: s.active === username ? undefined : s.active };
    });
  }

  /**
   * Trust-on-first-use with change detection. A first contact must match
   * the server directory; later changes are accepted but flagged, and a
   * verified contact becomes unverified.
   */
  private async checkIdentity(peer: string, id: PublicIdentity): Promise<void> {
    const c = this.contact(peer);
    if (c) {
      if (equal(c.identity.sigKey, id.sigKey) && equal(c.identity.dhKey, id.dhKey)) return;
      await this.saveContact({ ...c, identity: id, verified: false, identityChanged: Date.now() });
      await this.system(peer, 'sys.identityChanged');
      return;
    }
    const dir = await this.api.identityOf(peer);
    if (!equal(dir.sigKey, id.sigKey) || !equal(dir.dhKey, id.dhKey)) {
      throw new DecryptError('identity does not match directory');
    }
    await this.saveContact({
      username: peer,
      identity: id,
      verified: false,
      timer: 0,
      lastTs: Date.now(),
      unread: 0,
      hue: avatarHue(peer),
    });
  }

  // ---- conversations ------------------------------------------------------

  async open(peer: string | undefined): Promise<void> {
    useApp.setState({ active: peer });
    if (!peer) return;
    if (!useApp.getState().messages[peer]) {
      const list = await db.messagesFor<ChatMessage>(peer);
      useApp.setState((s) => ({ messages: { ...s.messages, [peer]: list } }));
    }
    await this.markRead(peer);
  }

  async loadOlder(peer: string): Promise<boolean> {
    const list = useApp.getState().messages[peer] ?? [];
    if (!list.length) return false;
    const older = await db.messagesFor<ChatMessage>(peer, 100, list[0].ts);
    if (!older.length) return false;
    useApp.setState((s) => ({ messages: { ...s.messages, [peer]: [...older, ...(s.messages[peer] ?? [])] } }));
    return true;
  }

  async markRead(peer: string): Promise<void> {
    const c = this.contact(peer);
    if (c?.unread) await this.saveContact({ ...c, unread: 0 });
    if (document.visibilityState !== 'visible') return;
    const unreadIn = (useApp.getState().messages[peer] ?? []).filter(
      (m) => m.dir === 'in' && m.kind === 'text' && m.status !== 'read',
    );
    if (!unreadIn.length) return;
    for (const m of unreadIn) await this.saveMessage({ ...m, status: 'read' });
    if (useApp.getState().settings.readReceipts) {
      void this.sendContent(peer, { t: 'receipt', ids: unreadIn.map((m) => m.id), s: 'read' }).catch(() => {});
    }
  }

  private async saveMessage(m: ChatMessage): Promise<void> {
    await db.putMessage(m);
    upsertMessage(m);
    if (m.expiresAt) {
      const exp = (await db.get<{ id: string; peer: string; at: number }[]>('kv', 'expiries')) ?? [];
      if (!exp.some((e) => e.id === m.id)) {
        exp.push({ id: m.id, peer: m.peer, at: m.expiresAt });
        await db.put('kv', 'expiries', exp);
      }
    }
  }

  private async touchContact(peer: string, m: ChatMessage, unreadDelta: number): Promise<void> {
    const c = this.contact(peer);
    if (!c) return;
    const preview = m.kind === 'text' ? m.body.slice(0, 80) : undefined;
    await this.saveContact({
      ...c,
      lastTs: Math.max(c.lastTs, m.ts),
      lastPreview: preview ?? c.lastPreview,
      unread: c.unread + unreadDelta,
    });
  }

  private async system(peer: string, key: string, params?: Record<string, string | number>): Promise<void> {
    const m: ChatMessage = { id: newId(), peer, dir: 'in', kind: 'system', body: '', ts: Date.now(), status: 'read', sys: { key, params } };
    await this.saveMessage(m);
  }

  async recordCall(peer: string, dir: 'in' | 'out', call: ChatMessage['call']): Promise<void> {
    const m: ChatMessage = { id: newId(), peer, dir, kind: 'call', body: '', ts: Date.now(), status: 'read', call };
    await this.saveMessage(m);
    await this.touchContact(peer, m, call?.outcome === 'missed' && useApp.getState().active !== peer ? 1 : 0);
  }

  private async purgeExpired(): Promise<void> {
    const exp = (await db.get<{ id: string; peer: string; at: number }[]>('kv', 'expiries')) ?? [];
    if (!exp.length) return;
    const now = Date.now();
    const due = exp.filter((e) => e.at <= now);
    if (!due.length) return;
    const byPeer = new Map<string, Set<string>>();
    for (const e of due) {
      await db.deleteMessage(e.id);
      if (!byPeer.has(e.peer)) byPeer.set(e.peer, new Set());
      byPeer.get(e.peer)!.add(e.id);
    }
    await db.put('kv', 'expiries', exp.filter((e) => e.at > now));
    for (const [peer, ids] of byPeer) removeMessages(peer, ids);
  }

  // ---- sending ------------------------------------------------------------

  private async sendContent(peer: string, content: Content, eph = false): Promise<{ ts: number }> {
    const payload = await this.cipher.encrypt(peer, utf8(JSON.stringify(content)));
    return this.socket.send(peer, payload, eph);
  }

  async sendText(peer: string, body: string, replyTo?: ChatMessage): Promise<void> {
    body = body.trim();
    if (!body) return;
    if (body.length > MAX_BODY) {
      toast('err.tooLong', 'error');
      return;
    }
    const c = this.contact(peer);
    const ts = Date.now();
    const m: ChatMessage = {
      id: newId(),
      peer,
      dir: 'out',
      kind: 'text',
      body,
      ts,
      status: 'pending',
      timer: c?.timer || undefined,
      expiresAt: c?.timer ? ts + c.timer * 1000 : undefined,
      replyTo: replyTo ? { id: replyTo.id, body: replyTo.body.slice(0, 200), dir: replyTo.dir } : undefined,
    };
    await this.saveMessage(m);
    await this.touchContact(peer, m, 0);
    await this.deliver(m);
  }

  private async deliver(m: ChatMessage): Promise<void> {
    try {
      await this.sendContent(m.peer, {
        t: 'text',
        id: m.id,
        body: m.body,
        ts: m.ts,
        exp: m.timer,
        reply: m.replyTo ? { id: m.replyTo.id, body: m.replyTo.body, mine: m.replyTo.dir === 'out' } : undefined,
      });
      const cur = useApp.getState().messages[m.peer]?.find((x) => x.id === m.id) ?? m;
      if (cur.status === 'pending' || cur.status === 'failed') await this.saveMessage({ ...cur, status: 'sent' });
    } catch (e) {
      console.warn('send failed', e);
      await this.saveMessage({ ...m, status: 'failed' });
      if (e instanceof ApiError && e.code === 'no_such_user') toast('err.noSuchUser', 'error');
    }
  }

  async retry(m: ChatMessage): Promise<void> {
    await this.saveMessage({ ...m, status: 'pending' });
    await this.deliver({ ...m, status: 'pending' });
  }

  /** Retries every failed outgoing message, e.g. after reconnecting. */
  async retryFailed(peer: string): Promise<void> {
    for (const m of useApp.getState().messages[peer] ?? []) {
      if (m.dir === 'out' && m.status === 'failed') await this.retry(m);
    }
  }

  async deleteForEveryone(m: ChatMessage): Promise<void> {
    await db.deleteMessage(m.id);
    removeMessages(m.peer, new Set([m.id]));
    if (m.dir === 'out') await this.sendContent(m.peer, { t: 'delete', ids: [m.id] }).catch(() => {});
  }

  async deleteLocal(m: ChatMessage): Promise<void> {
    await db.deleteMessage(m.id);
    removeMessages(m.peer, new Set([m.id]));
  }

  async setTimer(peer: string, exp: number): Promise<void> {
    const c = this.contact(peer);
    if (!c || c.timer === exp) return;
    await this.saveContact({ ...c, timer: exp });
    await this.system(peer, 'sys.timerYou', { exp });
    await this.sendContent(peer, { t: 'timer', exp }).catch(() => toast('err.sendFailed', 'error'));
  }

  typing(peer: string, on: boolean): void {
    if (!useApp.getState().settings.typingIndicators || !this.socket.online) return;
    const last = this.typingSentAt.get(peer) ?? 0;
    if (on && Date.now() - last < 3000) return;
    this.typingSentAt.set(peer, on ? Date.now() : 0);
    void this.sendContent(peer, { t: 'typing', on }, true).catch(() => {});
  }

  /** Call signalling: ephemeral, end-to-end encrypted. */
  sendCallSignal(peer: string, sig: CallSignal): Promise<{ ts: number }> {
    return this.sendContent(peer, { t: 'call', sig }, true);
  }

  // ---- receiving ----------------------------------------------------------

  private async markSeen(sid: number): Promise<void> {
    this.seenSids.add(sid);
    this.seenOrder.push(sid);
    if (this.seenOrder.length > 1000) this.seenSids.delete(this.seenOrder.shift()!);
    await db.put('kv', 'seenSids', this.seenOrder);
  }

  private async handleInbound(m: InboundMessage): Promise<void> {
    if (m.sid !== undefined && this.seenSids.has(m.sid)) {
      this.socket.ack([m.sid]);
      return;
    }
    const blocked = this.contact(m.from)?.blocked;
    let content: Content | null = null;
    if (!blocked) {
      try {
        content = JSON.parse(fromUtf8(await this.cipher.decrypt(m.from, m.payload))) as Content;
      } catch (e) {
        console.warn('decrypt failed', m.from, e);
        if (!m.eph && this.contact(m.from)) await this.system(m.from, 'sys.decryptFailed');
      }
    }
    if (content) {
      try {
        await this.apply(m, content);
      } catch (e) {
        console.error('apply failed', e);
      }
    }
    // Persist "seen" before acking: a redelivery after a crash is skipped
    // instead of failing to decrypt with an already-consumed key.
    if (m.sid !== undefined) {
      await this.markSeen(m.sid);
      this.socket.ack([m.sid]);
    }
  }

  private async apply(m: InboundMessage, c: Content): Promise<void> {
    const peer = m.from;
    switch (c.t) {
      case 'text': {
        if (typeof c.body !== 'string' || typeof c.id !== 'string') return;
        if (await db.getMessage(c.id)) return; // duplicate
        const exp = typeof c.exp === 'number' && c.exp > 0 ? c.exp : undefined;
        const msg: ChatMessage = {
          id: c.id,
          peer,
          dir: 'in',
          kind: 'text',
          body: c.body.slice(0, MAX_BODY),
          // Use the server timestamp for ordering; the sender clock may lie.
          ts: m.ts,
          status: 'delivered',
          timer: exp,
          expiresAt: exp ? m.ts + exp * 1000 : undefined,
          replyTo: c.reply ? { id: c.reply.id, body: String(c.reply.body).slice(0, 200), dir: c.reply.mine ? 'in' : 'out' } : undefined,
        };
        const viewing = useApp.getState().active === peer && document.visibilityState === 'visible';
        await this.saveMessage(msg);
        await this.touchContact(peer, msg, viewing ? 0 : 1);
        useApp.setState((s) => ({ typing: { ...s.typing, [peer]: 0 } }));
        void this.sendContent(peer, { t: 'receipt', ids: [c.id], s: 'delivered' }).catch(() => {});
        if (viewing) await this.markRead(peer);
        else this.notify(peer);
        break;
      }
      case 'receipt': {
        const rank = { pending: 0, failed: 0, sent: 1, delivered: 2, read: 3 } as const;
        for (const id of (c.ids ?? []).slice(0, 500)) {
          const existing = useApp.getState().messages[peer]?.find((x) => x.id === id) ?? (await db.getMessage<ChatMessage>(id));
          if (!existing || existing.peer !== peer || existing.dir !== 'out') continue;
          if (rank[c.s] > rank[existing.status]) await this.saveMessage({ ...existing, status: c.s });
        }
        break;
      }
      case 'typing':
        useApp.setState((s) => ({ typing: { ...s.typing, [peer]: c.on ? Date.now() + TYPING_TTL : 0 } }));
        break;
      case 'timer': {
        const ct = this.contact(peer);
        const exp = Math.max(0, Math.min(Number(c.exp) || 0, 4 * 7 * 24 * 3600));
        if (ct && ct.timer !== exp) {
          await this.saveContact({ ...ct, timer: exp });
          await this.system(peer, 'sys.timerPeer', { exp });
        }
        break;
      }
      case 'delete': {
        const ids = new Set<string>();
        for (const id of (c.ids ?? []).slice(0, 100)) {
          const existing = await db.getMessage<ChatMessage>(id);
          // Only the original sender may delete for everyone.
          if (existing && existing.peer === peer && existing.dir === 'in') {
            await db.deleteMessage(id);
            ids.add(id);
          }
        }
        removeMessages(peer, ids);
        break;
      }
      case 'call':
        this.callHandler(peer, c.sig);
        break;
    }
  }

  private notify(peer: string): void {
    const { settings } = useApp.getState();
    if (!settings.notifications || typeof Notification === 'undefined') return;
    if (Notification.permission !== 'granted' || document.visibilityState === 'visible') return;
    const c = this.contact(peer);
    // Content is never shown in notifications.
    const n = new Notification(c?.nickname || `@${peer}`, {
      body: settings.lang === 'fa' ? 'پیام جدید' : 'New message',
      tag: `msg-${peer}`,
      silent: false,
    });
    n.onclick = () => {
      window.focus();
      void this.open(peer);
      n.close();
    };
  }

  isSendError(e: unknown, code: string): boolean {
    return e instanceof SendError && e.code === code;
  }
}

export const messenger = new Messenger();
