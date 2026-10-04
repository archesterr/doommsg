// Safety numbers: a 60-digit code both parties compare out of band (in
// person, or over a call) to rule out a man-in-the-middle, modelled on
// Signal's numeric fingerprints. Each half is derived by iterated hashing
// of one party's identity, and halves are ordered so both sides see the
// same number.

import { sha512 } from '@noble/hashes/sha2.js';
import { concat, utf8 } from './bytes';
import type { PublicIdentity } from './protocol';

const ITERATIONS = 5200;
const VERSION = Uint8Array.of(0, 1);

function half(username: string, id: PublicIdentity): string {
  const key = concat(id.sigKey, id.dhKey);
  let h = sha512(concat(VERSION, key, utf8(username)));
  for (let i = 0; i < ITERATIONS; i++) h = sha512(concat(h, key));
  let out = '';
  for (let i = 0; i < 30; i += 5) {
    const chunk =
      h[i] * 2 ** 32 + h[i + 1] * 2 ** 24 + h[i + 2] * 2 ** 16 + h[i + 3] * 2 ** 8 + h[i + 4];
    out += String(chunk % 100000).padStart(5, '0');
  }
  return out;
}

/** Returns the 60-digit safety number as 12 groups of 5 digits. */
export function safetyNumber(
  a: { username: string; identity: PublicIdentity },
  b: { username: string; identity: PublicIdentity },
): string[] {
  const ha = half(a.username, a.identity);
  const hb = half(b.username, b.identity);
  const full = ha < hb ? ha + hb : hb + ha;
  return full.match(/.{5}/g)!;
}
