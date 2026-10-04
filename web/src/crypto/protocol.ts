// Primitives and identity keys for the DoomMsg protocol.
//
// Every signature and KDF uses a distinct, versioned domain-separation label.
// The signature labels must match the server (server/internal/api/api.go).

import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { concat, utf8 } from './bytes';

export const LABEL = {
  identityDH: utf8('DoomMsg/v1/identity-dh'),
  signedPreKey: utf8('DoomMsg/v1/signed-prekey'),
  register: utf8('DoomMsg/v1/register'),
  auth: utf8('DoomMsg/v1/auth'),
  x3dh: utf8('DoomMsg/v1/x3dh'),
  ratchet: utf8('DoomMsg/v1/ratchet'),
  messageKeys: utf8('DoomMsg/v1/message-keys'),
} as const;

export interface KeyPair {
  pub: Uint8Array;
  priv: Uint8Array;
}

/**
 * A device identity: an Ed25519 key for signatures and an X25519 key for
 * Diffie-Hellman. The DH key is signed by the signing key so the pair is
 * bound together; safety numbers cover both.
 */
export interface Identity {
  sig: KeyPair;
  dh: KeyPair;
  dhSig: Uint8Array;
}

export interface PublicIdentity {
  sigKey: Uint8Array;
  dhKey: Uint8Array;
}

export function newDHKeyPair(): KeyPair {
  const priv = x25519.utils.randomSecretKey();
  return { priv, pub: x25519.getPublicKey(priv) };
}

export function newIdentity(): Identity {
  const sigPriv = ed25519.utils.randomSecretKey();
  const sig = { priv: sigPriv, pub: ed25519.getPublicKey(sigPriv) };
  const dh = newDHKeyPair();
  return { sig, dh, dhSig: sign(sig.priv, LABEL.identityDH, dh.pub) };
}

export function sign(priv: Uint8Array, label: Uint8Array, msg: Uint8Array): Uint8Array {
  return ed25519.sign(concat(label, msg), priv);
}

export function verify(pub: Uint8Array, label: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  try {
    return ed25519.verify(sig, concat(label, msg), pub);
  } catch {
    return false;
  }
}

/** X25519. Throws on low-order points (all-zero shared secret). */
export function dh(priv: Uint8Array, pub: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(priv, pub);
}

export function kdf(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, len: number): Uint8Array {
  return hkdf(sha256, ikm, salt, info, len);
}

export function mac(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(sha256, key, data);
}

export { sha256 };

/**
 * AEAD with a single-use message key. Key and nonce are both derived from
 * the message key, which is never reused, so a deterministic nonce is safe.
 */
export function seal(mk: Uint8Array, plaintext: Uint8Array, ad: Uint8Array): Uint8Array {
  const okm = kdf(mk, new Uint8Array(32), LABEL.messageKeys, 56);
  return xchacha20poly1305(okm.subarray(0, 32), okm.subarray(32, 56), ad).encrypt(plaintext);
}

export function open(mk: Uint8Array, ciphertext: Uint8Array, ad: Uint8Array): Uint8Array {
  const okm = kdf(mk, new Uint8Array(32), LABEL.messageKeys, 56);
  return xchacha20poly1305(okm.subarray(0, 32), okm.subarray(32, 56), ad).decrypt(ciphertext);
}
