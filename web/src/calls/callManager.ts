// 1:1 voice and video calls over WebRTC.
//
// Media is encrypted end to end by DTLS-SRTP between the two browsers. The
// SDP, which carries the DTLS certificate fingerprints, is exchanged only
// through the Double Ratchet channel, so the server (and any TURN relay)
// cannot substitute its own keys or read the media: it only ever relays
// SRTP packets it cannot decrypt.

import { create } from 'zustand';
import { messenger, type CallSignal } from '../state/messenger';
import { toast, useApp } from '../state/store';
import type { CallInfo } from '../state/types';
import { playEndTone, playRingback, playRingtone, stopTone } from './tones';

export type CallPhase = 'idle' | 'outgoing' | 'incoming' | 'connecting' | 'active';

export interface CallState {
  phase: CallPhase;
  peer?: string;
  callId?: string;
  video: boolean;
  dir?: 'in' | 'out';
  ringing: boolean;
  startedAt?: number;
  muted: boolean;
  cameraOff: boolean;
  remoteVideo: boolean;
  local?: MediaStream;
  remote?: MediaStream;
  quality: 'good' | 'poor' | 'reconnecting';
}

const idle: CallState = {
  phase: 'idle',
  video: false,
  ringing: false,
  muted: false,
  cameraOff: false,
  remoteVideo: false,
  quality: 'good',
};

export const useCall = create<CallState>(() => idle);

const RING_TIMEOUT = 45_000;
const DISCONNECT_GRACE = 8_000;

/** "Always relay calls" is on, but there are no TURN credentials to relay with. */
class RelayUnavailableError extends Error {}

/** Stops a stream's tracks and closes a peer connection; both are idempotent. */
function release(stream?: MediaStream, pc?: RTCPeerConnection): void {
  stream?.getTracks().forEach((t) => t.stop());
  pc?.close();
}

const audioConstraints: MediaTrackConstraints = {
  echoCancellation: true,
  noiseSuppression: true,
  autoGainControl: true,
};
const videoConstraints = (facingMode: 'user' | 'environment' = 'user'): MediaTrackConstraints => ({
  width: { ideal: 1280 },
  height: { ideal: 720 },
  frameRate: { ideal: 30, max: 30 },
  facingMode,
});

class CallManager {
  private pc: RTCPeerConnection | null = null;
  private pendingOffer: { sdp: string; video: boolean } | null = null;
  private remoteCandidates: RTCIceCandidateInit[] = [];
  private ringTimer: ReturnType<typeof setTimeout> | null = null;
  private disconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private iceCache: { servers: RTCIceServer[]; expiresAt: number } | null = null;
  private makingOffer = false;
  /** Perfect negotiation: the callee yields on offer collisions. */
  private polite = false;
  private restarted = false;
  private facing: 'user' | 'environment' = 'user';
  /** A camera flip is under way; a second one waits for it. */
  private flipping = false;
  /** Our offer for the current outgoing call has gone out. */
  private offerSent = false;
  /**
   * A colliding offer we won glare against before ours went out. The peer
   * only yields once ours arrives, so if ours never does, theirs is
   * answered as busy (and logged as missed) when our call ends.
   */
  private ignoredOffer: { from: string; callId: string; video: boolean } | null = null;
  private statsTimer: ReturnType<typeof setInterval> | null = null;
  /**
   * Bumped by reset(). Async steps capture it before they await and give up,
   * releasing whatever they acquired, once the call they belong to is over.
   */
  private gen = 0;

  constructor() {
    messenger.onCallSignal((from, sig) => void this.onSignal(from, sig));
    window.addEventListener('pagehide', () => {
      const s = useCall.getState();
      if (s.phase !== 'idle' && s.peer && s.callId) {
        void messenger.sendCallSignal(s.peer, { op: 'hangup', callId: s.callId }).catch(() => {});
      }
    });
  }

  private set(p: Partial<CallState>) {
    useCall.setState(p);
  }

  private ended(gen: number): boolean {
    return gen !== this.gen;
  }

  private async iceServers(): Promise<RTCIceServer[]> {
    if (this.iceCache && this.iceCache.expiresAt - Date.now() > 60_000) return this.iceCache.servers;
    try {
      const cfg = await messenger.api.turn();
      this.iceCache = { servers: cfg.iceServers, expiresAt: cfg.expiresAt * 1000 };
      return cfg.iceServers;
    } catch {
      return [];
    }
  }

  private async media(video: boolean): Promise<MediaStream> {
    return navigator.mediaDevices.getUserMedia({
      audio: audioConstraints,
      video: video ? videoConstraints(this.facing) : false,
    });
  }

  private createPeer(peer: string, callId: string, polite: boolean, iceServers: RTCIceServer[]): RTCPeerConnection {
    const { relayCalls } = useApp.getState().settings;
    // Never fall back to direct candidates, which would reveal our IP address.
    if (relayCalls && !iceServers.some((s) => s.username)) throw new RelayUnavailableError();
    const pc = new RTCPeerConnection({
      iceServers,
      iceTransportPolicy: relayCalls ? 'relay' : 'all',
      bundlePolicy: 'max-bundle',
      rtcpMuxPolicy: 'require',
    });
    this.pc = pc;
    const remote = new MediaStream();
    this.set({ remote });

    pc.onicecandidate = (e) => {
      if (e.candidate) {
        void messenger.sendCallSignal(peer, { op: 'ice', callId, candidate: e.candidate.toJSON() }).catch(() => {});
      }
    };
    pc.ontrack = (e) => {
      remote.addTrack(e.track);
      if (e.track.kind === 'video') {
        this.set({ remoteVideo: true });
        e.track.onmute = () => this.set({ remoteVideo: false });
        e.track.onunmute = () => this.set({ remoteVideo: true });
      }
      // New object so subscribers re-render.
      this.set({ remote: new MediaStream(remote.getTracks()) });
    };
    pc.onnegotiationneeded = async () => {
      // Mid-call renegotiation (e.g. turning the camera on in a voice call
      // or an ICE restart), using the "perfect negotiation" pattern.
      if (useCall.getState().phase !== 'active' && useCall.getState().phase !== 'connecting') return;
      try {
        this.makingOffer = true;
        await pc.setLocalDescription();
        await messenger.sendCallSignal(peer, { op: 'renegotiate', callId, sdp: pc.localDescription!.sdp });
      } catch (e) {
        console.warn('renegotiation failed', e);
      } finally {
        this.makingOffer = false;
      }
    };
    pc.onconnectionstatechange = () => {
      const st = pc.connectionState;
      if (st === 'connected') {
        if (this.disconnectTimer) clearTimeout(this.disconnectTimer);
        this.disconnectTimer = null;
        if (useCall.getState().phase !== 'active') {
          stopTone();
          this.set({ phase: 'active', startedAt: Date.now(), quality: 'good' });
          this.startStats();
        } else {
          this.set({ quality: 'good' });
        }
      } else if (st === 'disconnected') {
        this.set({ quality: 'reconnecting' });
        this.disconnectTimer ??= setTimeout(() => this.recover(), DISCONNECT_GRACE);
      } else if (st === 'failed') {
        this.recover();
      }
    };
    this.polite = polite;
    return pc;
  }

  private recover() {
    const pc = this.pc;
    if (!pc) return;
    // A grace timer still pending here must not fire later and end the call
    // once the ICE restart below has recovered it.
    if (this.disconnectTimer) clearTimeout(this.disconnectTimer);
    this.disconnectTimer = null;
    if (!this.restarted) {
      this.restarted = true;
      this.set({ quality: 'reconnecting' });
      pc.restartIce();
      this.disconnectTimer = setTimeout(() => {
        if (pc.connectionState !== 'connected') void this.finish('failed', true);
      }, 15_000);
    } else {
      void this.finish('failed', true);
    }
  }

  private startStats() {
    this.statsTimer = setInterval(async () => {
      const pc = this.pc;
      if (!pc) return;
      const stats = await pc.getStats().catch(() => null);
      if (!stats || pc !== this.pc) return;
      let rtt = 0;
      let lost = 0;
      let received = 0;
      stats.forEach((r) => {
        if (r.type === 'candidate-pair' && r.state === 'succeeded' && r.nominated) rtt = r.currentRoundTripTime ?? 0;
        if (r.type === 'inbound-rtp') {
          lost += r.packetsLost ?? 0;
          received += r.packetsReceived ?? 0;
        }
      });
      const lossRate = received ? lost / (lost + received) : 0;
      if (useCall.getState().quality !== 'reconnecting') {
        this.set({ quality: rtt > 0.4 || lossRate > 0.08 ? 'poor' : 'good' });
      }
    }, 3000);
  }

  private async flushCandidates() {
    const pc = this.pc;
    if (!pc?.remoteDescription) return;
    const queued = this.remoteCandidates;
    this.remoteCandidates = [];
    for (const c of queued) await pc.addIceCandidate(c).catch(() => {});
  }

  /** Arms the ring timeout, replacing any earlier one; it only acts on `callId`. */
  private armRing(callId: string, ms: number, onTimeout: () => void) {
    this.clearRing();
    this.ringTimer = setTimeout(() => {
      this.ringTimer = null;
      if (useCall.getState().callId === callId) onTimeout();
    }, ms);
  }

  private clearRing() {
    if (this.ringTimer) clearTimeout(this.ringTimer);
    this.ringTimer = null;
  }

  // ---- public API --------------------------------------------------------

  async start(peer: string, video: boolean): Promise<void> {
    if (useCall.getState().phase !== 'idle') return;
    const gen = this.gen;
    const callId = crypto.randomUUID();
    this.restarted = false;
    this.set({ ...idle, phase: 'outgoing', peer, callId, video, dir: 'out' });
    let local: MediaStream;
    try {
      local = await this.media(video);
    } catch {
      if (this.ended(gen)) return;
      toast('call.err.media', 'error');
      this.reset();
      return;
    }
    if (this.ended(gen)) return release(local);
    this.set({ local });
    let pc: RTCPeerConnection | undefined;
    try {
      const iceServers = await this.iceServers();
      if (this.ended(gen)) return release(local);
      pc = this.createPeer(peer, callId, false, iceServers);
      for (const t of local.getTracks()) pc.addTrack(t, local);
      await pc.setLocalDescription(await pc.createOffer());
      if (this.ended(gen)) return release(local, pc);
      await messenger.sendCallSignal(peer, { op: 'offer', callId, sdp: pc.localDescription!.sdp, video });
    } catch (e) {
      if (this.ended(gen)) return release(local, pc);
      toast(
        e instanceof RelayUnavailableError
          ? 'call.err.relay'
          : messenger.isSendError(e, 'offline')
            ? 'call.err.offline'
            : 'call.err.failed',
        'error',
      );
      this.reset();
      await messenger.recordCall(peer, 'out', { video, outcome: 'failed' });
      return;
    }
    // Hung up, or already answered, while the offer was on its way.
    if (this.ended(gen)) return release(local, pc);
    // A peer whose offer collided with ours yields once ours arrives.
    this.offerSent = true;
    this.ignoredOffer = null;
    if (useCall.getState().phase !== 'outgoing') return;
    playRingback();
    this.armRing(callId, RING_TIMEOUT, () => void this.finish('cancelled', true));
  }

  async accept(): Promise<void> {
    const s = useCall.getState();
    if (s.phase !== 'incoming' || !s.peer || !s.callId || !this.pendingOffer) return;
    const gen = this.gen;
    stopTone();
    this.clearRing();
    const { peer, callId } = s;
    const offer = this.pendingOffer;
    this.set({ phase: 'connecting' });
    let local: MediaStream | undefined;
    let cameraOff = false;
    try {
      local = await this.media(offer.video);
    } catch {
      // No usable camera (missing, busy or blocked): answer a video call with
      // audio only. Its video m-line is then answered recvonly, and the camera
      // can still be turned on later.
      if (offer.video && !this.ended(gen)) {
        local = await this.media(false).catch(() => undefined);
        cameraOff = true;
      }
    }
    if (this.ended(gen)) return release(local);
    if (!local) {
      toast('call.err.media', 'error');
      await this.finish('failed', true);
      return;
    }
    this.set({ local, cameraOff });
    let pc: RTCPeerConnection | undefined;
    try {
      const iceServers = await this.iceServers();
      if (this.ended(gen)) return release(local);
      pc = this.createPeer(peer, callId, true, iceServers);
      // Apply the offer first so our tracks reuse its transceivers instead
      // of creating new ones that would force a renegotiation.
      await pc.setRemoteDescription({ type: 'offer', sdp: offer.sdp });
      if (this.ended(gen)) return release(local, pc);
      for (const t of local.getTracks()) pc.addTrack(t, local);
      await pc.setLocalDescription(await pc.createAnswer());
      if (this.ended(gen)) return release(local, pc);
      await messenger.sendCallSignal(peer, { op: 'answer', callId, sdp: pc.localDescription!.sdp });
      if (this.ended(gen)) return release(local, pc);
      await this.flushCandidates();
    } catch (e) {
      if (this.ended(gen)) return release(local, pc);
      console.warn('accept failed', e);
      if (e instanceof RelayUnavailableError) toast('call.err.relay', 'error');
      await this.finish('failed', true);
    }
  }

  async decline(): Promise<void> {
    const s = useCall.getState();
    if (s.phase !== 'incoming' || !s.peer || !s.callId) return;
    void messenger.sendCallSignal(s.peer, { op: 'decline', callId: s.callId }).catch(() => {});
    this.reset();
    await messenger.recordCall(s.peer, 'in', { video: s.video, outcome: 'declined' });
  }

  async hangup(): Promise<void> {
    const s = useCall.getState();
    if (s.phase === 'idle') return;
    if (s.phase === 'incoming') return this.decline();
    await this.finish(s.phase === 'active' ? 'completed' : 'cancelled', true);
  }

  toggleMute(): void {
    const s = useCall.getState();
    const muted = !s.muted;
    s.local?.getAudioTracks().forEach((t) => (t.enabled = !muted));
    this.set({ muted });
  }

  async toggleCamera(): Promise<void> {
    const s = useCall.getState();
    const pc = this.pc;
    if (!pc || !s.local) return;
    const track = s.local.getVideoTracks()[0];
    if (track) {
      const cameraOff = !s.cameraOff;
      track.enabled = !cameraOff;
      this.set({ cameraOff });
      return;
    }
    // Upgrade a voice call to video: add a track and renegotiate.
    const gen = this.gen;
    let cam: MediaStream | undefined;
    try {
      cam = await navigator.mediaDevices.getUserMedia({ video: videoConstraints(this.facing) });
      // The call may have ended, or the camera come on, while we waited.
      const local = useCall.getState().local;
      if (this.ended(gen) || !local || local.getVideoTracks().length) return release(cam);
      const vt = cam.getVideoTracks()[0];
      pc.addTrack(vt, local);
      local.addTrack(vt);
      this.set({ video: true, cameraOff: false, local: new MediaStream(local.getTracks()) });
    } catch {
      release(cam);
      if (!this.ended(gen)) toast('call.err.media', 'error');
    }
  }

  async switchCamera(): Promise<void> {
    const s = useCall.getState();
    const old = s.local?.getVideoTracks()[0];
    const pc = this.pc;
    const sender = pc?.getSenders().find((x) => x.track === old);
    if (!old || !pc || !sender || !s.local || this.flipping) return;
    this.flipping = true;
    const gen = this.gen;
    const facing = this.facing === 'user' ? 'environment' : 'user';
    let cam: MediaStream | undefined;
    try {
      cam = await navigator.mediaDevices.getUserMedia({ video: videoConstraints(facing) });
      if (this.ended(gen)) return release(cam);
      const vt = cam.getVideoTracks()[0];
      // The camera may have been turned off while it opened: the new track
      // must not go out live, now or after the swap.
      vt.enabled = !useCall.getState().cameraOff;
      await sender.replaceTrack(vt);
      if (this.ended(gen)) return release(cam);
      vt.enabled = !useCall.getState().cameraOff;
      this.facing = facing;
      s.local.removeTrack(old);
      old.stop();
      s.local.addTrack(vt);
      this.set({ local: new MediaStream(s.local.getTracks()) });
    } catch {
      release(cam);
      if (!this.ended(gen)) toast('call.err.media', 'error');
    } finally {
      this.flipping = false;
    }
  }

  // ---- signalling --------------------------------------------------------

  private async onSignal(from: string, sig: CallSignal): Promise<void> {
    const s = useCall.getState();
    const mine = s.peer === from && s.callId === sig.callId;

    switch (sig.op) {
      case 'offer': {
        if (s.phase === 'outgoing' && s.peer === from && s.callId && !mine) {
          // Glare: we called each other at the same moment. Both sides keep
          // the call with the smaller id, so exactly one of them survives.
          if (sig.callId > s.callId) {
            // Ours wins: the peer yields when our offer reaches them.
            if (!this.offerSent) this.ignoredOffer = { from, callId: sig.callId, video: sig.video };
            return;
          }
          // Theirs wins: withdraw ours quietly (the peer ignores it; the hangup
          // only matters if its own call ended meanwhile) and ring for theirs.
          void messenger.sendCallSignal(from, { op: 'hangup', callId: s.callId }).catch(() => {});
          this.reset();
        } else if (s.phase !== 'idle') {
          if (!mine) {
            void messenger.sendCallSignal(from, { op: 'busy', callId: sig.callId }).catch(() => {});
            await messenger.recordCall(from, 'in', { video: sig.video, outcome: 'missed' });
          }
          return;
        }
        if (useApp.getState().contacts[from]?.blocked) return;
        this.restarted = false;
        this.pendingOffer = { sdp: sig.sdp, video: sig.video };
        this.remoteCandidates = [];
        this.set({ ...idle, phase: 'incoming', peer: from, callId: sig.callId, video: sig.video, dir: 'in' });
        void messenger.sendCallSignal(from, { op: 'ringing', callId: sig.callId }).catch(() => {});
        playRingtone();
        this.notifyIncoming(from, sig.video);
        this.armRing(sig.callId, RING_TIMEOUT + 5000, () => {
          if (useCall.getState().phase === 'incoming') void this.missed(from, sig.video);
        });
        return;
      }
      case 'ringing':
        if (mine && s.phase === 'outgoing') this.set({ ringing: true });
        return;
      case 'answer': {
        const pc = this.pc;
        if (!mine || s.phase !== 'outgoing' || !pc) return;
        const gen = this.gen;
        this.clearRing();
        stopTone();
        this.set({ phase: 'connecting' });
        try {
          await pc.setRemoteDescription({ type: 'answer', sdp: sig.sdp });
          if (!this.ended(gen)) await this.flushCandidates();
        } catch (e) {
          if (this.ended(gen)) return;
          console.warn('bad answer', e);
          await this.finish('failed', true);
        }
        return;
      }
      case 'ice':
        if (!mine) return;
        if (this.pc?.remoteDescription) await this.pc.addIceCandidate(sig.candidate).catch(() => {});
        else if (this.remoteCandidates.length < 200) this.remoteCandidates.push(sig.candidate);
        return;
      case 'renegotiate': {
        const pc = this.pc;
        if (!mine || !pc) return;
        const collision = this.makingOffer || pc.signalingState !== 'stable';
        if (collision && !this.polite) return; // impolite peer ignores the colliding offer
        try {
          await pc.setRemoteDescription({ type: 'offer', sdp: sig.sdp }); // implicit rollback
          await pc.setLocalDescription();
          await messenger.sendCallSignal(from, { op: 'renegotiate-answer', callId: sig.callId, sdp: pc.localDescription!.sdp });
          await this.flushCandidates();
        } catch (e) {
          console.warn('renegotiate failed', e);
        }
        return;
      }
      case 'renegotiate-answer':
        if (mine && this.pc) await this.pc.setRemoteDescription({ type: 'answer', sdp: sig.sdp }).catch(() => {});
        return;
      case 'hangup':
        if (!mine) return;
        if (s.phase === 'incoming') await this.missed(from, s.video);
        else await this.finish(s.phase === 'active' ? 'completed' : 'cancelled', false);
        return;
      case 'decline':
      case 'busy':
        if (!mine) return;
        toast(sig.op === 'busy' ? 'call.busy' : 'call.declined');
        await this.finish(sig.op === 'busy' ? 'busy' : 'declined', false);
        return;
    }
  }

  private notifyIncoming(from: string, video: boolean) {
    const { notifications, lang } = useApp.getState().settings;
    if (!notifications || typeof Notification === 'undefined' || Notification.permission !== 'granted') return;
    if (document.visibilityState === 'visible') return;
    const n = new Notification(`@${from}`, {
      body: lang === 'fa' ? (video ? 'تماس تصویری ورودی' : 'تماس صوتی ورودی') : video ? 'Incoming video call' : 'Incoming voice call',
      tag: 'call',
      requireInteraction: true,
    });
    n.onclick = () => {
      window.focus();
      n.close();
    };
  }

  private async finish(outcome: CallInfo['outcome'], notifyPeer: boolean): Promise<void> {
    const s = useCall.getState();
    if (s.phase === 'idle' || !s.peer) return;
    if (notifyPeer && s.callId) {
      void messenger.sendCallSignal(s.peer, { op: 'hangup', callId: s.callId }).catch(() => {});
    }
    const durationSec = s.startedAt ? Math.round((Date.now() - s.startedAt) / 1000) : undefined;
    const final = s.startedAt && outcome !== 'failed' ? 'completed' : outcome;
    // Tear down before the async log write, so nothing can end (and log) this
    // call a second time, or reset a newer one, while the write is pending.
    this.reset();
    playEndTone();
    await messenger.recordCall(s.peer, s.dir ?? 'out', { video: s.video, outcome: final, durationSec });
  }

  /** Ends an unanswered incoming call and logs it as missed. */
  private async missed(peer: string, video: boolean): Promise<void> {
    this.reset();
    await messenger.recordCall(peer, 'in', { video, outcome: 'missed' });
  }

  private reset() {
    this.gen++;
    stopTone();
    for (const t of [this.ringTimer, this.disconnectTimer]) if (t) clearTimeout(t);
    if (this.statsTimer) clearInterval(this.statsTimer);
    this.ringTimer = this.disconnectTimer = this.statsTimer = null;
    const s = useCall.getState();
    s.local?.getTracks().forEach((t) => t.stop());
    this.pc?.close();
    this.pc = null;
    this.pendingOffer = null;
    this.remoteCandidates = [];
    this.makingOffer = false;
    this.offerSent = false;
    const ignored = this.ignoredOffer;
    this.ignoredOffer = null;
    useCall.setState(idle, true);
    if (ignored) {
      void messenger.sendCallSignal(ignored.from, { op: 'busy', callId: ignored.callId }).catch(() => {});
      void messenger.recordCall(ignored.from, 'in', { video: ignored.video, outcome: 'missed' }).catch(() => {});
    }
  }
}

export const calls = new CallManager();
