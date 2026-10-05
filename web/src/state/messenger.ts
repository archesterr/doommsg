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
/** Acks are sent in batches, at the latest this long after an envelope is processed. */
const ACK_DELAY = 250;
/** Envelope ids per ack frame; the server refuses more. */
const MAX_ACK_IDS = 500;
/** Receipts wait this long for a backlog to drain, so each peer gets one. */
const RECEIPT_DELAY = 1000;
/** Message ids per receipt; a receiver honours no more. */
const MAX_RECEIPT_IDS = 500;
/** Local retries of an envelope that could not be processed for a transient reason. */
const RETRY_DELAYS = [2_000, 5_000, 15_000, 30_000, 60_000];

type CallHandler = (from: string, sig: CallSignal) => void;
type ReceiptStatus = 'delivered' | 'read';
type Expiry = { id: string; peer: string; at: number };

function newId(): string {
  return crypto.randomUUID();
}

function avatarHue(name: string): number {
  let h = 0;
  for (const ch of name) h = (h * 31 + ch.codePointAt(0)!) % 360;
  return h;
}

function newContact(username: string, identity: PublicIdentity): Contact {
  return { username, identity, verified: false, timer: 0, lastTs: Date.now(), unread: 0, hue: avatarHue(username) };
}

function pageVisible(): boolean {
  return typeof document !== 'undefined' && document.visibilityState === 'visible';
}

/**
 * Whether an envelope failed to decrypt because of what it contains, so a
 * redelivery would fail the same way. Anything else (network, rate limits,
 * server or storage errors) consumed nothing and is worth another try.
 */
function isPermanent(e: unknown): boolean {
  if (e instanceof DecryptError) return true;
  return e instanceof ApiError && e.status >= 400 && e.status < 500 && ![401, 408, 429].includes(e.status);
}

/** A loaded page of a conversation plus messages saved while it loaded; those are newer. */
function mergeMessages(loaded: ChatMessage[], live: ChatMessage[]): ChatMessage[] {
  if (!live.length) return loaded;
  const ids = new Set(live.map((m) => m.id));
  return [...loaded.filter((m) => !ids.has(m.id)), ...live].sort((a, b) => a.ts - b.ts);
}

export class Messenger {
  readonly api: Api;
  private socket: Socket;
  private cipher: SessionCipher;
  private account: Account | null = null;
  /** Set once another tab or connection owns the account: nothing more is processed. */
  private stopped = false;
  private seenSids = new Set<number>();
  private seenOrder: number[] = [];
  private inbound: Promise<void> = Promise.resolve();
  /** Envelopes handed to `inbound` and not yet processed. */
  private queued = 0;
  private retryTimers = new Set<ReturnType<typeof setTimeout>>();
  /** Processed envelopes not yet acknowledged to the server. */
  private acks = new Set<number>();
  private ackTimer: ReturnType<typeof setTimeout> | null = null;
  /** Outgoing receipts by status and peer, coalesced into one per peer. */
  private receipts: Record<ReceiptStatus, Map<string, Set<string>>> = { delivered: new Map(), read: new Map() };
  private receiptTimer: ReturnType<typeof setTimeout> | null = null;
  private expiryTimer: ReturnType<typeof setInterval> | null = null;
  private expiriesLock: Promise<unknown> = Promise.resolve();
  private prekeyJob: Promise<void> | null = null;
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
      // Acks and receipts that missed the last connection go out on this one.
      if (conn === 'online') this.flushOutbox();
      if (conn === 'replaced') {
        this.halt();
        useApp.setState({ phase: 'elsewhere' });
      }
    };
    this.socket.onMessage = (m) => this.enqueue(m);
    this.socket.onSynced = () => void this.maintainPreKeys();
    this.cipher = new SessionCipher(localKeyStore, {
      fetchBundle: (peer) => this.api.bundle(peer),
      checkIdentity: (peer, id) => this.checkIdentity(peer, id),
      trustedIdentity: (peer) => this.contact(peer)?.identity,
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
    this.stopped = false;
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
    // Messages that arrived while the tab was hidden are read once it shows.
    if (typeof document !== 'undefined') document.addEventListener('visibilitychange', this.onVisibility);
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
    this.halt();
    this.socket.stop();
  }

  /**
   * Stops all processing: envelopes still queued are left on the server for
   * whichever tab owns the account now, and no maintenance runs.
   */
  private halt(): void {
    // What was processed is acknowledged while there may still be a socket.
    this.flushAcks();
    this.stopped = true;
    if (this.expiryTimer) clearInterval(this.expiryTimer);
    if (this.ackTimer) clearTimeout(this.ackTimer);
    if (this.receiptTimer) clearTimeout(this.receiptTimer);
    for (const t of this.retryTimers) clearTimeout(t);
    this.expiryTimer = this.ackTimer = this.receiptTimer = null;
    this.retryTimers.clear();
    this.acks.clear();
    this.receipts.delivered.clear();
    this.receipts.read.clear();
    if (typeof document !== 'undefined') document.removeEventListener('visibilitychange', this.onVisibility);
  }

  private onVisibility = () => {
    const peer = useApp.getState().active;
    if (peer && !this.stopped && pageVisible()) void this.markRead(peer);
  };

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

  /** Tops up prekeys after each sync; one run at a time, as runs overlap across reconnects. */
  private maintainPreKeys(): Promise<void> {
    this.prekeyJob ??= this.refreshPreKeys().finally(() => {
      this.prekeyJob = null;
    });
    return this.prekeyJob;
  }

  private async refreshPreKeys(): Promise<void> {
    try {
      if (this.stopped) return;
      if ((await signedPreKeyAge()) > SPK_ROTATE_MS) {
        await this.api.putSignedPreKey(await rotateSignedPreKey());
      }
      const { oneTimePreKeys, max } = await this.api.keyStatus();
      if (this.stopped) return;
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
    if (existing?.hidden) {
      const shown = { ...existing, hidden: false, lastTs: Date.now() };
      await this.saveContact(shown);
      return shown;
    }
    if (existing) return existing;
    const id = await this.api.identityOf(username);
    const c = newContact(username, { sigKey: id.sigKey, dhKey: id.dhKey });
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

  /**
   * Deletes the history and the contact. The ratchet session stays: the peer
   * still uses it, and their next message brings the chat back (re-checked
   * against the directory like any first contact). A blocked contact is
   * kept, hidden, so that deleting the chat does not lift the block.
   */
  async deleteChat(username: string): Promise<void> {
    const c = this.contact(username);
    await db.deleteConversation(username);
    const kept: Contact | undefined = c?.blocked
      ? { ...c, hidden: true, unread: 0, lastPreview: undefined, identityChanged: undefined }
      : undefined;
    if (kept) await db.put('contacts', username, kept);
    else await db.del('contacts', username);
    // A receipt sent now would only re-create the contact.
    this.receipts.delivered.delete(username);
    this.receipts.read.delete(username);
    useApp.setState((s) => {
      const contacts = { ...s.contacts };
      const messages = { ...s.messages };
      if (kept) contacts[username] = kept;
      else delete contacts[username];
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
    await this.saveContact(newContact(peer, id));
  }

  // ---- conversations ------------------------------------------------------

  async open(peer: string | undefined): Promise<void> {
    useApp.setState({ active: peer });
    if (!peer) return;
    if (!useApp.getState().messages[peer]) {
      // An empty list first, so that messages saved while the page loads
      // are kept by upsertMessage instead of being lost to the snapshot.
      useApp.setState((s) => ({ messages: { ...s.messages, [peer]: [] } }));
      let list: ChatMessage[];
      try {
        list = await db.messagesFor<ChatMessage>(peer);
      } catch (e) {
        useApp.setState((s) => {
          const messages = { ...s.messages };
          delete messages[peer];
          return { messages };
        });
        throw e;
      }
      useApp.setState((s) => {
        const live = s.messages[peer];
        if (!live) return {}; // the chat was deleted meanwhile
        return { messages: { ...s.messages, [peer]: mergeMessages(list, live) } };
      });
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
    // Nothing is read while the tab is hidden; it is caught up when it shows.
    if (!pageVisible()) return;
    const c = this.contact(peer);
    if (c?.unread) await this.saveContact({ ...c, unread: 0 });
    const unreadIn = (useApp.getState().messages[peer] ?? []).filter(
      (m) => m.dir === 'in' && m.kind === 'text' && m.status !== 'read',
    );
    if (!unreadIn.length) return;
    for (const m of unreadIn) await this.saveMessage({ ...m, status: 'read' });
    if (useApp.getState().settings.readReceipts) this.queueReceipt(peer, 'read', unreadIn.map((m) => m.id));
  }

  private async saveMessage(m: ChatMessage): Promise<void> {
    await db.putMessage(m);
    upsertMessage(m);
    const at = m.expiresAt;
    if (at) {
      await this.withExpiries(async (exp) => {
        if (exp.some((e) => e.id === m.id)) return;
        exp.push({ id: m.id, peer: m.peer, at });
        await db.put('kv', 'expiries', exp);
      });
    }
  }

  /**
   * Runs `fn` on the current 'expiries' list. Every change to the list goes
   * through here, one at a time, so that no update overwrites another.
   */
  private withExpiries<T>(fn: (exp: Expiry[]) => Promise<T>): Promise<T> {
    const run = async () => fn((await db.get<Expiry[]>('kv', 'expiries')) ?? []);
    const next = this.expiriesLock.then(run, run);
    this.expiriesLock = next.catch(() => undefined);
    return next;
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

  private purgeExpired(): Promise<void> {
    return this.withExpiries(async (exp) => {
      if (this.stopped || !exp.length) return;
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
    });
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
    // The stored copy is the truth: the user may delete a message while it
    // is pending, and a deleted message is neither sent nor written back.
    if (!(await db.getMessage(m.id))) return;
    try {
      await this.sendContent(m.peer, {
        t: 'text',
        id: m.id,
        body: m.body,
        ts: m.ts,
        exp: m.timer,
        reply: m.replyTo ? { id: m.replyTo.id, body: m.replyTo.body, mine: m.replyTo.dir === 'out' } : undefined,
      });
      const cur = await db.getMessage<ChatMessage>(m.id);
      if (cur && (cur.status === 'pending' || cur.status === 'failed')) await this.saveMessage({ ...cur, status: 'sent' });
    } catch (e) {
      console.warn('send failed', e);
      const cur = await db.getMessage<ChatMessage>(m.id);
      if (cur?.status === 'pending') await this.saveMessage({ ...cur, status: 'failed' });
      if (e instanceof ApiError && e.code === 'no_such_user') toast('err.noSuchUser', 'error');
    }
  }

  async retry(m: ChatMessage): Promise<void> {
    if (!(await db.getMessage(m.id))) return;
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

  private enqueue(m: InboundMessage, attempt = 0): void {
    this.queued++;
    // Strictly sequential processing preserves per-peer ordering.
    this.inbound = this.inbound
      .then(() => this.handleInbound(m, attempt))
      .finally(() => {
        // Once a backlog is through, acknowledge it and send its receipts.
        if (--this.queued === 0) this.flushOutbox();
      })
      .catch((e) => console.error('inbound', e));
  }

  private async handleInbound(m: InboundMessage, attempt: number): Promise<void> {
    // Another tab owns the sessions now; it gets this envelope from the server.
    if (this.stopped) return;
    if (m.sid !== undefined && this.seenSids.has(m.sid)) {
      // Redelivered because its ack never arrived: acknowledge it again.
      this.queueAck(m.sid);
      return;
    }
    const blocked = this.contact(m.from)?.blocked;
    let content: Content | null = null;
    if (!blocked) {
      let plaintext: Uint8Array | undefined;
      try {
        plaintext = await this.cipher.decrypt(m.from, m.payload);
      } catch (e) {
        if (!isPermanent(e)) {
          // Nothing was consumed, so the envelope stays on the server for a
          // redelivery and is retried here meanwhile.
          console.warn('decrypt deferred', m.from, e);
          this.retryLater(m, attempt);
          return;
        }
        console.warn('decrypt failed', m.from, e);
      }
      if (plaintext) {
        try {
          content = JSON.parse(fromUtf8(plaintext)) as Content;
        } catch (e) {
          console.warn('unreadable message', m.from, e);
        }
      }
      if (!content && !m.eph) await this.reportUnreadable(m.from);
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
      this.queueAck(m.sid);
    }
  }

  private retryLater(m: InboundMessage, attempt: number): void {
    if (attempt >= RETRY_DELAYS.length) return; // left to the next connection's redelivery
    const t = setTimeout(() => {
      this.retryTimers.delete(t);
      this.enqueue(m, attempt + 1);
    }, RETRY_DELAYS[attempt]);
    this.retryTimers.add(t);
  }

  /**
   * Tells the user a message from `peer` was lost. A sender with no chat
   * (e.g. one the user deleted) gets one, pinned to the directory identity
   * like any new contact, so the loss does not go unnoticed.
   */
  private async reportUnreadable(peer: string): Promise<void> {
    try {
      if (!this.contact(peer)) {
        const id = await this.api.identityOf(peer);
        if (!this.contact(peer)) await this.saveContact(newContact(peer, { sigKey: id.sigKey, dhKey: id.dhKey }));
      }
      await this.system(peer, 'sys.decryptFailed');
    } catch (e) {
      console.warn('could not report an unreadable message', peer, e);
    }
  }

  private queueAck(sid: number): void {
    if (this.stopped) return;
    this.acks.add(sid);
    if (this.acks.size >= MAX_ACK_IDS) this.flushAcks();
    else this.ackTimer ??= setTimeout(() => this.flushAcks(), ACK_DELAY);
  }

  private flushAcks(): void {
    if (this.ackTimer) clearTimeout(this.ackTimer);
    this.ackTimer = null;
    while (this.acks.size && !this.stopped) {
      const ids = [...this.acks].slice(0, MAX_ACK_IDS);
      // Without a connection they wait for the next one. Envelopes the
      // server redelivers meanwhile are recognised as seen and acked again.
      if (!this.socket.ack(ids)) return;
      for (const id of ids) this.acks.delete(id);
    }
  }

  private queueReceipt(peer: string, s: ReceiptStatus, ids: string[]): void {
    if (this.stopped) return;
    const pending = this.receipts[s].get(peer) ?? new Set<string>();
    for (const id of ids) pending.add(id);
    this.receipts[s].set(peer, pending);
    // Within a backlog, receipts wait for it to drain (or pause) so that
    // each peer gets one with many ids instead of one per message.
    if (!this.queued) this.flushReceipts();
    else this.receiptTimer ??= setTimeout(() => this.flushReceipts(), RECEIPT_DELAY);
  }

  private flushReceipts(): void {
    if (this.receiptTimer) clearTimeout(this.receiptTimer);
    this.receiptTimer = null;
    if (this.stopped || !this.socket.online) return; // kept for the next connection
    for (const s of ['delivered', 'read'] as const) {
      for (const [peer, pending] of this.receipts[s]) {
        this.receipts[s].delete(peer);
        const ids = [...pending];
        for (let i = 0; i < ids.length; i += MAX_RECEIPT_IDS) {
          const chunk = ids.slice(i, i + MAX_RECEIPT_IDS);
          void this.sendContent(peer, { t: 'receipt', ids: chunk, s }).catch((e) => {
            if (this.isSendError(e, 'offline')) this.queueReceipt(peer, s, chunk);
          });
        }
      }
    }
  }

  private flushOutbox(): void {
    if (this.stopped) return;
    this.flushAcks();
    this.flushReceipts();
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
        const viewing = useApp.getState().active === peer && pageVisible();
        await this.saveMessage(msg);
        await this.touchContact(peer, msg, viewing ? 0 : 1);
        useApp.setState((s) => ({ typing: { ...s.typing, [peer]: 0 } }));
        this.queueReceipt(peer, 'delivered', [c.id]);
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
      case 'typing': {
        const until = c.on ? Date.now() + TYPING_TTL : 0;
        useApp.setState((s) => ({ typing: { ...s.typing, [peer]: until } }));
        // Cleared when it lapses, since a peer who goes quiet never says so
        // and the chat list has no clock of its own to notice.
        if (until) {
          setTimeout(
            () => useApp.setState((s) => (s.typing[peer] === until ? { typing: { ...s.typing, [peer]: 0 } } : {})),
            TYPING_TTL,
          );
        }
        break;
      }
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
    if (Notification.permission !== 'granted' || pageVisible()) return;
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
