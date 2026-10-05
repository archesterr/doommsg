// Call-manager state machine tests against mocked WebRTC, media devices and
// messenger. They pin down the races where a call ends while one of its
// async steps (getUserMedia, ICE config, SDP, signalling) is still pending.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { CallSignal } from '../state/messenger';

type Sent = CallSignal & { peer: string };

const h = vi.hoisted(() => ({
  sent: [] as unknown[],
  handler: (() => {}) as (from: string, sig: unknown) => void,
  settings: { relayCalls: false, notifications: true, lang: 'en' },
  turn: (async () => ({ iceServers: [], expiresAt: Date.now() / 1000 + 3600 })) as () => Promise<unknown>,
  /** Lets a test hold one sendCallSignal open; returns the promise to wait on. */
  holdSend: null as null | ((sig: { op: string }) => Promise<unknown> | undefined),
  tone: null as null | string,
}));

vi.mock('../state/messenger', () => ({
  messenger: {
    onCallSignal: (fn: (from: string, sig: unknown) => void) => {
      h.handler = fn;
    },
    sendCallSignal: vi.fn(async (peer: string, sig: { op: string }) => {
      h.sent.push({ peer, ...sig });
      await h.holdSend?.(sig);
      return { ts: 1 };
    }),
    recordCall: vi.fn(async () => {}),
    isSendError: () => false,
    api: { turn: () => h.turn() },
  },
}));
vi.mock('../state/store', () => ({
  toast: vi.fn(),
  useApp: { getState: () => ({ settings: h.settings, contacts: {} }) },
}));
vi.mock('./tones', () => ({
  playRingback: () => (h.tone = 'ringback'),
  playRingtone: () => (h.tone = 'ringtone'),
  playEndTone: () => (h.tone = null),
  stopTone: () => (h.tone = null),
}));

// ---- WebRTC / media fakes ---------------------------------------------------

class Track {
  stopped = false;
  enabled = true;
  constructor(public kind: 'audio' | 'video') {}
  stop() {
    this.stopped = true;
  }
}

class Stream {
  private tracks: Track[];
  constructor(tracks: Track[] = []) {
    this.tracks = [...tracks];
  }
  getTracks() {
    return [...this.tracks];
  }
  getAudioTracks() {
    return this.tracks.filter((t) => t.kind === 'audio');
  }
  getVideoTracks() {
    return this.tracks.filter((t) => t.kind === 'video');
  }
  addTrack(t: Track) {
    this.tracks.push(t);
  }
  removeTrack(t: Track) {
    this.tracks = this.tracks.filter((x) => x !== t);
  }
}

function closedError() {
  return Object.assign(new Error('closed'), { name: 'InvalidStateError' });
}

const pcs: FakePC[] = [];
class FakePC {
  closed = false;
  connectionState = 'new';
  signalingState = 'stable';
  remoteDescription: unknown = null;
  localDescription: { type?: string; sdp: string } | null = null;
  senders: { track: Track | null; replaceTrack: (t: Track) => Promise<void> }[] = [];
  onconnectionstatechange: (() => void) | null = null;
  onicecandidate: unknown = null;
  ontrack: unknown = null;
  onnegotiationneeded: unknown = null;
  /** Set by a test to hold setRemoteDescription open. */
  static holdRemote: Promise<void> | null = null;
  constructor(public cfg: RTCConfiguration) {
    pcs.push(this);
  }
  addTrack(track: Track) {
    if (this.closed) throw closedError();
    const sender = {
      track: track as Track | null,
      replaceTrack: async (t: Track) => {
        sender.track = t;
      },
    };
    this.senders.push(sender);
    return sender;
  }
  getSenders() {
    return this.senders;
  }
  async createOffer() {
    if (this.closed) throw closedError();
    return { type: 'offer', sdp: 'offer-sdp' };
  }
  async createAnswer() {
    if (this.closed) throw closedError();
    return { type: 'answer', sdp: 'answer-sdp' };
  }
  async setLocalDescription(d?: { sdp: string }) {
    if (this.closed) throw closedError();
    this.localDescription = d ?? { sdp: 'local-sdp' };
  }
  async setRemoteDescription(d: unknown) {
    if (FakePC.holdRemote) await FakePC.holdRemote;
    if (this.closed) throw closedError();
    this.remoteDescription = d;
  }
  async addIceCandidate() {}
  restartIce() {}
  async getStats() {
    return new Map();
  }
  close() {
    this.closed = true;
  }
  fire(state: string) {
    this.connectionState = state;
    this.onconnectionstatechange?.();
  }
}

function deferred<T>() {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((a, b) => {
    resolve = a;
    reject = b;
  });
  return { promise, resolve, reject };
}

/** Each getUserMedia call parks here until the test settles it. */
const gum: { constraints: MediaStreamConstraints; d: ReturnType<typeof deferred<Stream>> }[] = [];
const notifications: { title: string; opts: NotificationOptions }[] = [];

vi.stubGlobal('window', { addEventListener() {}, focus() {} });
vi.stubGlobal('document', { visibilityState: 'hidden' });
vi.stubGlobal('MediaStream', Stream);
vi.stubGlobal('RTCPeerConnection', FakePC);
vi.stubGlobal(
  'Notification',
  class {
    static permission = 'granted';
    onclick: unknown = null;
    constructor(title: string, opts: NotificationOptions) {
      notifications.push({ title, opts });
    }
    close() {}
  },
);
vi.stubGlobal('navigator', {
  mediaDevices: {
    getUserMedia: (constraints: MediaStreamConstraints) => {
      const d = deferred<Stream>();
      gum.push({ constraints, d });
      return d.promise;
    },
  },
});

const flush = async () => {
  for (let i = 0; i < 50; i++) await Promise.resolve();
};

// ---- harness ----------------------------------------------------------------

type Mod = typeof import('./callManager');
let calls: Mod['calls'];
let useCall: Mod['useCall'];
let messenger: typeof import('../state/messenger').messenger;
let toast: ReturnType<typeof vi.fn>;

const sent = () => h.sent as Sent[];
const ops = () => sent().map((s) => s.op);
const signal = async (from: string, sig: CallSignal) => {
  h.handler(from, sig);
  await flush();
};
const lastGum = () => gum[gum.length - 1];
const grant = async (...kinds: ('audio' | 'video')[]) => {
  const tracks = kinds.map((k) => new Track(k));
  lastGum().d.resolve(new Stream(tracks));
  await flush();
  return tracks;
};
const deny = async (name: string) => {
  lastGum().d.reject(Object.assign(new Error(name), { name }));
  await flush();
};

/** Places an outgoing call that the peer answers and that then connects. */
async function activeCall(peer: string, video = false) {
  void calls.start(peer, video);
  await flush();
  const tracks = await grant(...(video ? (['audio', 'video'] as const) : (['audio'] as const)));
  const callId = useCall.getState().callId!;
  await signal(peer, { op: 'answer', callId, sdp: 'answer-sdp' });
  const pc = pcs[pcs.length - 1];
  pc.fire('connected');
  expect(useCall.getState().phase).toBe('active');
  return { callId, pc, tracks };
}

/** Receives an offer and waits in the ringing state. */
async function incoming(from: string, callId: string, video: boolean) {
  await signal(from, { op: 'offer', callId, sdp: 'offer-sdp', video });
  expect(useCall.getState().phase).toBe('incoming');
}

beforeEach(async () => {
  vi.useFakeTimers();
  vi.resetModules();
  vi.clearAllMocks();
  h.sent.length = 0;
  h.holdSend = null;
  h.tone = null;
  h.settings.relayCalls = false;
  h.settings.notifications = true;
  h.turn = async () => ({ iceServers: [], expiresAt: Date.now() / 1000 + 3600 });
  FakePC.holdRemote = null;
  pcs.length = 0;
  gum.length = 0;
  notifications.length = 0;
  ({ calls, useCall } = await import('./callManager'));
  ({ messenger } = await import('../state/messenger'));
  toast = (await import('../state/store')).toast as unknown as ReturnType<typeof vi.fn>;
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

// ---- tests ------------------------------------------------------------------

describe('accept() racing the end of the call', () => {
  it('releases the camera and sends no answer when the caller hangs up during getUserMedia', async () => {
    await incoming('alice', 'c1', true);
    const accepting = calls.accept();
    await flush();
    expect(useCall.getState().phase).toBe('connecting');

    await signal('alice', { op: 'hangup', callId: 'c1' });
    expect(useCall.getState().phase).toBe('idle');

    const [audio, video] = await grant('audio', 'video');
    await accepting;
    expect(audio.stopped).toBe(true);
    expect(video.stopped).toBe(true);
    expect(useCall.getState().local).toBeUndefined();
    expect(pcs).toHaveLength(0);
    expect(ops()).not.toContain('answer');
  });

  it('closes the new peer connection when the caller hangs up while the offer is applied', async () => {
    await incoming('alice', 'c1', false);
    const hold = deferred<void>();
    FakePC.holdRemote = hold.promise;
    const accepting = calls.accept();
    await flush();
    const [audio] = await grant('audio');
    expect(pcs).toHaveLength(1);

    await signal('alice', { op: 'hangup', callId: 'c1' });
    hold.resolve();
    await accepting;
    await flush();
    expect(useCall.getState().phase).toBe('idle');
    expect(audio.stopped).toBe(true);
    expect(pcs[0].closed).toBe(true);
    expect(ops()).not.toContain('answer');
    // Ended by the peer: no failure toast, no extra hangup.
    expect(toast).not.toHaveBeenCalled();
    expect(ops().filter((o) => o === 'hangup')).toHaveLength(0);
  });
});

describe('start() racing the end of the call', () => {
  it('sends no offer and keeps no media when the caller hangs up during getUserMedia', async () => {
    const starting = calls.start('bob', true);
    await flush();
    await calls.hangup();
    expect(useCall.getState().phase).toBe('idle');

    const [audio, video] = await grant('audio', 'video');
    await starting;
    expect(audio.stopped && video.stopped).toBe(true);
    expect(ops()).not.toContain('offer');
    expect(pcs).toHaveLength(0);
    expect(h.tone).toBeNull();
  });

  it('does not start ringback or arm the ring timer when hung up while the offer is in flight', async () => {
    const offerSent = deferred<void>();
    h.holdSend = (sig) => (sig.op === 'offer' ? offerSent.promise : undefined);
    const starting = calls.start('bob', false);
    await flush();
    const [audio] = await grant('audio');
    expect(ops()).toEqual(['offer']);

    await calls.hangup();
    offerSent.resolve();
    await starting;
    await flush();
    expect(h.tone).toBeNull();
    expect(audio.stopped).toBe(true);
    expect(pcs[0].closed).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('a cancelled call leaves no ring timer behind to hang up the next call', async () => {
    const first = calls.start('bob', true);
    await flush();
    await calls.hangup();
    await grant('audio', 'video');
    await first;

    vi.advanceTimersByTime(10_000);
    await activeCall('carol');
    h.sent.length = 0;
    vi.advanceTimersByTime(60_000);
    await flush();
    expect(useCall.getState().phase).toBe('active');
    expect(useCall.getState().peer).toBe('carol');
    expect(ops()).not.toContain('hangup');
  });

  it('the outgoing ring timer still cancels an unanswered call', async () => {
    void calls.start('bob', false);
    await flush();
    await grant('audio');
    const callId = useCall.getState().callId;
    expect(h.tone).toBe('ringback');
    vi.advanceTimersByTime(45_000);
    await flush();
    expect(useCall.getState().phase).toBe('idle');
    expect(sent().filter((s) => s.op === 'hangup').map((s) => s.callId)).toEqual([callId]);
    expect(messenger.recordCall).toHaveBeenCalledWith('bob', 'out', expect.objectContaining({ outcome: 'cancelled' }));
  });
});

describe('camera changes racing the end of the call', () => {
  it('toggleCamera() stops the new camera track if the call ends during getUserMedia', async () => {
    const { callId } = await activeCall('bob');
    const toggling = calls.toggleCamera();
    await flush();
    await signal('bob', { op: 'hangup', callId });
    expect(useCall.getState().phase).toBe('idle');

    const [cam] = await grant('video');
    await toggling;
    expect(cam.stopped).toBe(true);
    expect(useCall.getState().local).toBeUndefined();
    expect(toast).not.toHaveBeenCalled();
  });

  it('toggleCamera() still upgrades a live voice call to video', async () => {
    const { pc } = await activeCall('bob');
    const toggling = calls.toggleCamera();
    await flush();
    const [cam] = await grant('video');
    await toggling;
    expect(cam.stopped).toBe(false);
    expect(useCall.getState().local?.getVideoTracks()).toEqual([cam]);
    expect(pc.senders.map((s) => s.track)).toContain(cam);
  });

  it('switchCamera() stops the new camera track if the call ends during getUserMedia', async () => {
    const { callId } = await activeCall('bob', true);
    const switching = calls.switchCamera();
    await flush();
    expect(lastGum().constraints.video).toMatchObject({ facingMode: 'environment' });
    await signal('bob', { op: 'hangup', callId });

    const [cam] = await grant('video');
    await switching;
    expect(cam.stopped).toBe(true);
    expect(useCall.getState().phase).toBe('idle');
    expect(toast).not.toHaveBeenCalled();
  });

  it('switchCamera() keeps the camera off when it is turned off while the new one opens', async () => {
    const { pc } = await activeCall('bob', true);
    const switching = calls.switchCamera();
    await flush();
    await calls.toggleCamera(); // camera off during getUserMedia
    expect(useCall.getState().cameraOff).toBe(true);

    const [cam] = await grant('video');
    await switching;
    expect(pc.senders.map((s) => s.track)).toContain(cam);
    expect(cam.enabled).toBe(false);
    expect(useCall.getState().cameraOff).toBe(true);
  });

  it('switchCamera() ignores a second flip while one is opening the camera', async () => {
    const { tracks } = await activeCall('bob', true);
    const first = calls.switchCamera();
    await flush();
    await calls.switchCamera();
    expect(gum).toHaveLength(2); // the call's own, plus the first flip only

    const [cam] = await grant('video');
    await first;
    expect(tracks.find((t) => t.kind === 'video')!.stopped).toBe(true);
    expect(useCall.getState().local?.getVideoTracks()).toEqual([cam]);
  });

  it('switchCamera() swaps the sent track on a live call', async () => {
    const { pc, tracks } = await activeCall('bob', true);
    const old = tracks.find((t) => t.kind === 'video')!;
    const switching = calls.switchCamera();
    await flush();
    const [cam] = await grant('video');
    await switching;
    expect(old.stopped).toBe(true);
    expect(cam.stopped).toBe(false);
    expect(pc.senders.map((s) => s.track)).toContain(cam);
    expect(useCall.getState().local?.getVideoTracks()).toEqual([cam]);
  });
});

describe('Always relay calls', () => {
  it('fails an outgoing call instead of falling back to direct candidates when TURN is unavailable', async () => {
    h.settings.relayCalls = true;
    h.turn = async () => {
      throw new Error('503');
    };
    const starting = calls.start('bob', false);
    await flush();
    const [audio] = await grant('audio');
    await starting;
    expect(pcs).toHaveLength(0);
    expect(ops()).not.toContain('offer');
    expect(toast).toHaveBeenCalledWith('call.err.relay', 'error');
    expect(useCall.getState().phase).toBe('idle');
    expect(audio.stopped).toBe(true);
  });

  it('refuses to answer when the ICE config carries no TURN credentials', async () => {
    h.settings.relayCalls = true;
    h.turn = async () => ({ iceServers: [{ urls: ['stun:example.com:3478'] }], expiresAt: Date.now() / 1000 + 3600 });
    await incoming('alice', 'c1', false);
    const accepting = calls.accept();
    await flush();
    const [audio] = await grant('audio');
    await accepting;
    expect(pcs).toHaveLength(0);
    expect(toast).toHaveBeenCalledWith('call.err.relay', 'error');
    expect(ops()).toContain('hangup');
    expect(ops()).not.toContain('answer');
    expect(audio.stopped).toBe(true);
  });

  it('uses relay-only ICE when TURN credentials are available', async () => {
    h.settings.relayCalls = true;
    h.turn = async () => ({
      iceServers: [{ urls: ['turn:example.com:3478'], username: '1:me', credential: 'x' }],
      expiresAt: Date.now() / 1000 + 3600,
    });
    void calls.start('bob', false);
    await flush();
    await grant('audio');
    expect(pcs[0].cfg.iceTransportPolicy).toBe('relay');
    expect(ops()).toContain('offer');
  });
});

describe('answering a video call without a usable camera', () => {
  it.each(['NotFoundError', 'NotReadableError', 'OverconstrainedError'])('falls back to audio only on %s', async (name) => {
    await incoming('alice', 'c1', true);
    const accepting = calls.accept();
    await flush();
    expect(lastGum().constraints.video).toBeTruthy();
    await deny(name);
    expect(lastGum().constraints.video).toBe(false);
    const [audio] = await grant('audio');
    await accepting;

    expect(ops()).toContain('answer');
    expect(useCall.getState()).toMatchObject({ phase: 'connecting', video: true, cameraOff: true });
    expect(useCall.getState().local?.getTracks()).toEqual([audio]);
    expect(toast).not.toHaveBeenCalled();
  });

  it('still fails when the microphone is unavailable too', async () => {
    await incoming('alice', 'c1', true);
    const accepting = calls.accept();
    await flush();
    await deny('NotFoundError');
    await deny('NotFoundError');
    await accepting;
    expect(toast).toHaveBeenCalledWith('call.err.media', 'error');
    expect(ops()).toContain('hangup');
    expect(useCall.getState().phase).toBe('idle');
  });

  it('does not retry for a voice call', async () => {
    await incoming('alice', 'c1', false);
    const accepting = calls.accept();
    await flush();
    await deny('NotReadableError');
    await accepting;
    expect(gum).toHaveLength(1);
    expect(toast).toHaveBeenCalledWith('call.err.media', 'error');
  });
});

describe('glare: both sides call each other at once', () => {
  it('yields to the peer’s call when it has the smaller id', async () => {
    vi.spyOn(crypto, 'randomUUID').mockReturnValue('bbbbbbbb-0000-4000-8000-000000000000');
    void calls.start('bob', false);
    await flush();
    const [audio] = await grant('audio');
    expect(useCall.getState().phase).toBe('outgoing');

    await signal('bob', { op: 'offer', callId: 'aaaaaaaa-0000-4000-8000-000000000000', sdp: 'offer-sdp', video: false });
    expect(useCall.getState()).toMatchObject({ phase: 'incoming', peer: 'bob', callId: 'aaaaaaaa-0000-4000-8000-000000000000', dir: 'in' });
    expect(ops()).not.toContain('busy');
    // Our own attempt is withdrawn quietly: no failed/missed entry in the log.
    expect(sent().find((s) => s.op === 'hangup')?.callId).toBe('bbbbbbbb-0000-4000-8000-000000000000');
    expect(messenger.recordCall).not.toHaveBeenCalled();
    expect(audio.stopped).toBe(true);
    expect(pcs[0].closed).toBe(true);
    expect(h.tone).toBe('ringtone');

    // The surviving call can be answered normally.
    const accepting = calls.accept();
    await flush();
    await grant('audio');
    await accepting;
    expect(sent().find((s) => s.op === 'answer')?.callId).toBe('aaaaaaaa-0000-4000-8000-000000000000');
  });

  it('keeps its own call and ignores the peer’s when its id is smaller', async () => {
    vi.spyOn(crypto, 'randomUUID').mockReturnValue('aaaaaaaa-0000-4000-8000-000000000000');
    void calls.start('bob', false);
    await flush();
    await grant('audio');

    await signal('bob', { op: 'offer', callId: 'bbbbbbbb-0000-4000-8000-000000000000', sdp: 'offer-sdp', video: false });
    expect(useCall.getState()).toMatchObject({ phase: 'outgoing', callId: 'aaaaaaaa-0000-4000-8000-000000000000' });
    expect(ops()).toEqual(['offer']);
    expect(messenger.recordCall).not.toHaveBeenCalled();

    // The peer yields and answers ours.
    await signal('bob', { op: 'answer', callId: 'aaaaaaaa-0000-4000-8000-000000000000', sdp: 'answer-sdp' });
    expect(useCall.getState().phase).toBe('connecting');
  });

  it('abandons its own setup cleanly when it yields during getUserMedia', async () => {
    vi.spyOn(crypto, 'randomUUID').mockReturnValue('bbbbbbbb-0000-4000-8000-000000000000');
    const starting = calls.start('bob', true);
    await flush();
    await signal('bob', { op: 'offer', callId: 'aaaaaaaa-0000-4000-8000-000000000000', sdp: 'offer-sdp', video: false });
    expect(useCall.getState().phase).toBe('incoming');

    const [audio, video] = await grant('audio', 'video');
    await starting;
    expect(audio.stopped && video.stopped).toBe(true);
    expect(ops()).not.toContain('offer');
    expect(useCall.getState()).toMatchObject({ phase: 'incoming', callId: 'aaaaaaaa-0000-4000-8000-000000000000' });
    expect(h.tone).toBe('ringtone');
  });

  it('answers the peer busy when its own offer never goes out after winning', async () => {
    vi.spyOn(crypto, 'randomUUID').mockReturnValue('aaaaaaaa-0000-4000-8000-000000000000');
    const starting = calls.start('bob', false);
    await flush();
    // Bob's offer arrives while ours waits for the microphone: ours wins.
    await signal('bob', { op: 'offer', callId: 'bbbbbbbb-0000-4000-8000-000000000000', sdp: 'offer-sdp', video: true });
    expect(useCall.getState().phase).toBe('outgoing');
    expect(ops()).toEqual([]);

    // The microphone is refused, so our offer is never sent and Bob would
    // never yield: he is told we are busy, and we log his call as missed.
    await deny('NotAllowedError');
    await starting;
    expect(useCall.getState().phase).toBe('idle');
    expect(ops()).not.toContain('offer');
    expect(sent().find((s) => s.op === 'busy')).toMatchObject({ peer: 'bob', callId: 'bbbbbbbb-0000-4000-8000-000000000000' });
    expect(messenger.recordCall).toHaveBeenCalledWith('bob', 'in', { video: true, outcome: 'missed' });
  });

  it('owes the peer nothing once its winning offer has gone out', async () => {
    vi.spyOn(crypto, 'randomUUID').mockReturnValue('aaaaaaaa-0000-4000-8000-000000000000');
    void calls.start('bob', false);
    await flush();
    await signal('bob', { op: 'offer', callId: 'bbbbbbbb-0000-4000-8000-000000000000', sdp: 'offer-sdp', video: false });
    await grant('audio');
    expect(ops()).toEqual(['offer']);

    // Bob yields once our offer reaches him; hanging up now only ends ours.
    await calls.hangup();
    expect(ops()).toEqual(['offer', 'hangup']);
    expect(messenger.recordCall).not.toHaveBeenCalledWith('bob', 'in', expect.anything());
  });

  it('still answers busy to a third party', async () => {
    void calls.start('bob', false);
    await flush();
    await grant('audio');
    await signal('carol', { op: 'offer', callId: 'zz', sdp: 'offer-sdp', video: false });
    expect(sent().find((s) => s.op === 'busy')).toMatchObject({ peer: 'carol', callId: 'zz' });
    expect(useCall.getState()).toMatchObject({ phase: 'outgoing', peer: 'bob' });
  });
});

describe('connection recovery', () => {
  it('a grace timer pending when the connection fails does not later end the recovered call', async () => {
    const { pc } = await activeCall('bob');
    vi.advanceTimersByTime(1000);
    pc.fire('disconnected');
    vi.advanceTimersByTime(3000);
    pc.fire('failed');
    vi.advanceTimersByTime(2000);
    pc.fire('connected');
    h.sent.length = 0;
    vi.advanceTimersByTime(30_000);
    await flush();
    expect(useCall.getState().phase).toBe('active');
    expect(ops()).not.toContain('hangup');
  });

  it('still ends a call whose ICE restart never reconnects', async () => {
    const { pc } = await activeCall('bob');
    pc.fire('disconnected');
    vi.advanceTimersByTime(8000);
    expect(useCall.getState().quality).toBe('reconnecting');
    vi.advanceTimersByTime(15_000);
    await flush();
    expect(useCall.getState().phase).toBe('idle');
    expect(ops()).toContain('hangup');
  });
});

describe('incoming-call notifications', () => {
  it('are not shown when notifications are turned off in settings', async () => {
    h.settings.notifications = false;
    await incoming('alice', 'c1', true);
    expect(notifications).toHaveLength(0);
  });

  it('are shown when enabled and the tab is hidden', async () => {
    await incoming('alice', 'c1', true);
    expect(notifications).toEqual([{ title: '@alice', opts: expect.objectContaining({ body: 'Incoming video call' }) }]);
  });
});
