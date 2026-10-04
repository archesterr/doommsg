// ISO/IEC 7816-4 padding to fixed buckets, so ciphertext length reveals
// only a coarse size class, not the exact message length.

const BLOCK = 256;

export function pad(data: Uint8Array): Uint8Array {
  const size = Math.ceil((data.length + 1) / BLOCK) * BLOCK;
  const out = new Uint8Array(size);
  out.set(data);
  out[data.length] = 0x80;
  return out;
}

export function unpad(data: Uint8Array): Uint8Array {
  for (let i = data.length - 1; i >= 0; i--) {
    if (data[i] === 0x80) return data.subarray(0, i);
    if (data[i] !== 0x00) break;
  }
  throw new Error('invalid padding');
}
