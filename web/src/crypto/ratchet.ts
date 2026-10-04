// Double Ratchet (https://signal.org/docs/specifications/doubleratchet/).
//
// Provides forward secrecy (old message keys are deleted) and post-compromise
// security (every round trip mixes in fresh DH output). State updates are
// transactional: decryption works on a copy and only commits on success, so
// a forged or corrupted message can never desynchronise a session.

import { b64, concat, u32be, wipe } from './bytes';
import { dh, kdf, LABEL, mac, newDHKeyPair, open, seal, type KeyPair } from './protocol';

/** Max message keys skipped in a single step (DoS bound). */
export const MAX_SKIP = 1000;
/** Max skipped keys retained per session; oldest are evicted first. */
export const MAX_STORED_SKIPPED = 2000;

export interface Header {
  dh: Uint8Array; // sender's current ratchet public key
  pn: number; // length of the previous sending chain
  n: number; // message number in the current sending chain
}

export interface RatchetState {
  rk: Uint8Array;
  dhs: KeyPair;
  dhr: Uint8Array | null;
  cks: Uint8Array | null;
  ckr: Uint8Array | null;
  ns: number;
  nr: number;
  pn: number;
  /** Skipped message keys, keyed by `${b64(dh)}:${n}`, in insertion order. */
  skipped: [string, Uint8Array][];
  ad: Uint8Array;
}

export class RatchetError extends Error {}

function kdfRK(rk: Uint8Array, dhOut: Uint8Array): [Uint8Array, Uint8Array] {
  const out = kdf(dhOut, rk, LABEL.ratchet, 64);
  wipe(dhOut);
  return [out.slice(0, 32), out.slice(32, 64)];
}

function kdfCK(ck: Uint8Array): [Uint8Array, Uint8Array] {
  return [mac(ck, Uint8Array.of(0x02)), mac(ck, Uint8Array.of(0x01))]; // [nextCK, mk]
}

export function encodeHeader(h: Header): Uint8Array {
  return concat(h.dh, u32be(h.pn), u32be(h.n));
}

/** Initiator (Alice) after X3DH, with Bob's signed prekey as first ratchet key. */
export function initAlice(sk: Uint8Array, bobRatchetPub: Uint8Array, ad: Uint8Array): RatchetState {
  const dhs = newDHKeyPair();
  const [rk, cks] = kdfRK(sk, dh(dhs.priv, bobRatchetPub));
  return { rk, dhs, dhr: bobRatchetPub, cks, ckr: null, ns: 0, nr: 0, pn: 0, skipped: [], ad };
}

/** Responder (Bob) after X3DH; his signed prekey is the first ratchet key. */
export function initBob(sk: Uint8Array, signedPreKey: KeyPair, ad: Uint8Array): RatchetState {
  return {
    rk: sk,
    dhs: { pub: signedPreKey.pub.slice(), priv: signedPreKey.priv.slice() },
    dhr: null,
    cks: null,
    ckr: null,
    ns: 0,
    nr: 0,
    pn: 0,
    skipped: [],
    ad,
  };
}

export function cloneState(s: RatchetState): RatchetState {
  return {
    rk: s.rk.slice(),
    dhs: { pub: s.dhs.pub.slice(), priv: s.dhs.priv.slice() },
    dhr: s.dhr?.slice() ?? null,
    cks: s.cks?.slice() ?? null,
    ckr: s.ckr?.slice() ?? null,
    ns: s.ns,
    nr: s.nr,
    pn: s.pn,
    skipped: s.skipped.map(([k, v]) => [k, v.slice()]),
    ad: s.ad.slice(),
  };
}

/** Encrypts in place, advancing the sending chain. */
export function encrypt(s: RatchetState, plaintext: Uint8Array): { header: Header; ciphertext: Uint8Array } {
  if (!s.cks) throw new RatchetError('no sending chain yet');
  const [ck, mk] = kdfCK(s.cks);
  wipe(s.cks);
  s.cks = ck;
  const header: Header = { dh: s.dhs.pub, pn: s.pn, n: s.ns };
  s.ns += 1;
  const ciphertext = seal(mk, plaintext, concat(s.ad, encodeHeader(header)));
  wipe(mk);
  return { header, ciphertext };
}

/**
 * Decrypts a message. Returns the new state and plaintext; the input state
 * is left untouched, so callers persist the returned state only on success.
 */
export function decrypt(state: RatchetState, header: Header, ciphertext: Uint8Array): { state: RatchetState; plaintext: Uint8Array } {
  const s = cloneState(state);
  const ad = concat(s.ad, encodeHeader(header));

  const id = `${b64(header.dh)}:${header.n}`;
  const idx = s.skipped.findIndex(([k]) => k === id);
  if (idx >= 0) {
    const mk = s.skipped[idx][1];
    const plaintext = tryOpen(mk, ciphertext, ad);
    s.skipped.splice(idx, 1);
    wipe(mk);
    return { state: s, plaintext };
  }

  if (!s.dhr || b64(header.dh) !== b64(s.dhr)) {
    skip(s, header.pn);
    dhRatchet(s, header);
  }
  skip(s, header.n);
  if (!s.ckr) throw new RatchetError('no receiving chain');
  const [ck, mk] = kdfCK(s.ckr);
  s.ckr = ck;
  s.nr += 1;
  const plaintext = tryOpen(mk, ciphertext, ad);
  wipe(mk);
  return { state: s, plaintext };
}

function tryOpen(mk: Uint8Array, ct: Uint8Array, ad: Uint8Array): Uint8Array {
  try {
    return open(mk, ct, ad);
  } catch {
    throw new RatchetError('message authentication failed');
  }
}

function skip(s: RatchetState, until: number): void {
  if (!s.ckr) return;
  if (until < s.nr) return; // already past it (duplicate or old)
  if (until - s.nr > MAX_SKIP) throw new RatchetError('too many skipped messages');
  const dhr = b64(s.dhr!);
  while (s.nr < until) {
    const [ck, mk] = kdfCK(s.ckr);
    s.ckr = ck;
    s.skipped.push([`${dhr}:${s.nr}`, mk]);
    s.nr += 1;
  }
  while (s.skipped.length > MAX_STORED_SKIPPED) {
    const evicted = s.skipped.shift();
    if (evicted) wipe(evicted[1]);
  }
}

function dhRatchet(s: RatchetState, header: Header): void {
  s.pn = s.ns;
  s.ns = 0;
  s.nr = 0;
  s.dhr = header.dh.slice();
  [s.rk, s.ckr] = kdfRK(s.rk, dh(s.dhs.priv, s.dhr));
  wipe(s.dhs.priv);
  s.dhs = newDHKeyPair();
  [s.rk, s.cks] = kdfRK(s.rk, dh(s.dhs.priv, s.dhr));
}
