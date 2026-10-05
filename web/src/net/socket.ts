// WebSocket transport with authentication, request/response correlation,
// liveness checks and exponential-backoff reconnects.

export type SocketState = 'offline' | 'connecting' | 'online' | 'replaced';

export interface InboundMessage {
  sid?: number;
  from: string;
  payload: string;
  eph?: boolean;
  ts: number;
}

interface Frame {
  type: string;
  id?: string;
  sid?: number;
  from?: string;
  payload?: string;
  eph?: boolean;
  ts?: number;
  code?: string;
  username?: string;
}

export class SendError extends Error {
  constructor(public code: string) {
    super(code);
  }
}

interface Pending {
  resolve: (v: { ts: number; sid?: number }) => void;
  reject: (e: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

const SEND_TIMEOUT = 15_000;
const PING_EVERY = 25_000;
const PONG_TIMEOUT = 10_000;

export class Socket {
  private ws: WebSocket | null = null;
  private pending = new Map<string, Pending>();
  private attempt = 0;
  private stopped = true;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private pingTimer: ReturnType<typeof setInterval> | null = null;
  private pongTimer: ReturnType<typeof setTimeout> | null = null;
  private seq = 0;
  state: SocketState = 'offline';

  onMessage: (m: InboundMessage) => void = () => {};
  onSynced: () => void = () => {};
  onState: (s: SocketState) => void = () => {};

  constructor(private getToken: (forceRefresh: boolean) => Promise<string>) {}

  start(): void {
    if (!this.stopped) return;
    this.stopped = false;
    this.attempt = 0;
    void this.connect(false);
    window.addEventListener('online', this.kick);
    document.addEventListener('visibilitychange', this.kick);
  }

  stop(): void {
    this.stopped = true;
    window.removeEventListener('online', this.kick);
    document.removeEventListener('visibilitychange', this.kick);
    this.clearTimers();
    this.ws?.close(1000);
    this.ws = null;
    this.failPending('offline');
    this.setState('offline');
  }

  /** Reconnect immediately when the network or tab comes back. */
  private kick = () => {
    if (this.stopped || document.visibilityState === 'hidden') return;
    if (this.state === 'offline') {
      if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
      this.attempt = 0;
      void this.connect(false);
    }
  };

  private setState(s: SocketState) {
    if (this.state !== s) {
      this.state = s;
      this.onState(s);
    }
  }

  private async connect(refresh: boolean): Promise<void> {
    if (this.stopped) return;
    this.setState('connecting');
    let token: string;
    try {
      token = await this.getToken(refresh);
    } catch {
      this.scheduleReconnect(true);
      return;
    }
    if (this.stopped) return;

    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${proto}//${location.host}/api/v1/ws`);
    this.ws = ws;
    let authed = false;

    ws.onopen = () => ws.send(JSON.stringify({ type: 'auth', token }));
    ws.onmessage = (ev) => {
      let f: Frame;
      try {
        f = JSON.parse(String(ev.data)) as Frame;
      } catch {
        return;
      }
      this.armPong();
      switch (f.type) {
        case 'ready':
          authed = true;
          this.attempt = 0;
          this.setState('online');
          this.startPing();
          break;
        case 'synced':
          this.onSynced();
          break;
        case 'msg':
          if (f.from && f.payload) this.onMessage({ sid: f.sid, from: f.from, payload: f.payload, eph: f.eph, ts: f.ts ?? Date.now() });
          break;
        case 'sent':
          this.settle(f.id, null, { ts: f.ts ?? Date.now(), sid: f.sid });
          break;
        case 'error':
          if (f.code === 'unauthorized') {
            ws.close();
            return;
          }
          this.settle(f.id, new SendError(f.code ?? 'error'));
          break;
        case 'pong':
          break;
      }
    };
    ws.onclose = (ev) => {
      if (this.ws !== ws) return;
      this.ws = null;
      this.clearTimers();
      this.failPending('offline');
      if (ev.code === 1008 && ev.reason === 'replaced') {
        this.stopped = true;
        this.setState('replaced');
        return;
      }
      this.setState('offline');
      // A close before "ready" usually means the token expired.
      this.scheduleReconnect(!authed);
    };
  }

  private scheduleReconnect(refreshToken: boolean) {
    if (this.stopped) return;
    const base = Math.min(30_000, 500 * 2 ** this.attempt++);
    const delay = base / 2 + Math.random() * (base / 2); // jitter
    this.reconnectTimer = setTimeout(() => void this.connect(refreshToken), delay);
  }

  private startPing() {
    this.pingTimer = setInterval(() => {
      this.ws?.send(JSON.stringify({ type: 'ping' }));
      this.armPong();
    }, PING_EVERY);
  }

  private armPong() {
    if (this.pongTimer) clearTimeout(this.pongTimer);
    this.pongTimer = setTimeout(() => this.ws?.close(4000, 'timeout'), PING_EVERY + PONG_TIMEOUT);
  }

  private clearTimers() {
    if (this.pingTimer) clearInterval(this.pingTimer);
    if (this.pongTimer) clearTimeout(this.pongTimer);
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.pingTimer = this.pongTimer = this.reconnectTimer = null;
  }

  private settle(id: string | undefined, err: Error | null, v?: { ts: number; sid?: number }) {
    if (!id) return;
    const p = this.pending.get(id);
    if (!p) return;
    clearTimeout(p.timer);
    this.pending.delete(id);
    if (err) p.reject(err);
    else p.resolve(v!);
  }

  private failPending(code: string) {
    for (const [id] of this.pending) this.settle(id, new SendError(code));
  }

  get online(): boolean {
    return this.state === 'online';
  }

  /** Sends an envelope; resolves once the server has accepted it. */
  send(to: string, payload: string, eph = false): Promise<{ ts: number; sid?: number }> {
    const ws = this.ws;
    if (!ws || this.state !== 'online') return Promise.reject(new SendError('offline'));
    const id = `${Date.now().toString(36)}-${(this.seq++).toString(36)}`;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.settle(id, new SendError('timeout')), SEND_TIMEOUT);
      this.pending.set(id, { resolve, reject, timer });
      ws.send(JSON.stringify({ type: 'send', id, to, payload, eph: eph || undefined }));
    });
  }

  /** Acknowledges stored envelopes; false when there is no connection to do it on. */
  ack(sids: number[]): boolean {
    if (!this.ws || this.state !== 'online') return false;
    if (sids.length) this.ws.send(JSON.stringify({ type: 'ack', ids: sids }));
    return true;
  }
}
