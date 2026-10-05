// X3DH key agreement (https://signal.org/docs/specifications/x3dh/).
//
//   DH1 = DH(IK_A, SPK_B)   DH2 = DH(EK_A, IK_B)
//   DH3 = DH(EK_A, SPK_B)   DH4 = DH(EK_A, OPK_B)   (if a one-time key exists)
//   SK  = HKDF(F || DH1 || DH2 || DH3 [|| DH4])
//
// The associated data binds both parties' full identities (signing + DH key)
// into every message of the resulting session.

import { concat, wipe } from './bytes';
import { dh, kdf, LABEL, newDHKeyPair, verify, type Identity, type KeyPair, type PublicIdentity } from './protocol';

export interface PreKeyBundle extends PublicIdentity {
  dhKeySig: Uint8Array;
  signedPreKey: { keyId: number; pub: Uint8Array; sig: Uint8Array };
  oneTimePreKey?: { keyId: number; pub: Uint8Array };
}

export interface InitiatorResult {
  sk: Uint8Array;
  ad: Uint8Array;
  ephemeralPub: Uint8Array;
  signedPreKeyId: number;
  signedPreKeyPub: Uint8Array;
  oneTimePreKeyId?: number;
}

export class BundleVerificationError extends Error {}

// 32 0xFF bytes prepended for curve25519 per the X3DH spec.
const F = new Uint8Array(32).fill(0xff);

export function associatedData(initiator: PublicIdentity, responder: PublicIdentity): Uint8Array {
  return concat(initiator.sigKey, initiator.dhKey, responder.sigKey, responder.dhKey);
}

function deriveSK(dhs: Uint8Array[]): Uint8Array {
  const ikm = concat(F, ...dhs);
  const sk = kdf(ikm, new Uint8Array(32), LABEL.x3dh, 32);
  wipe(ikm, ...dhs);
  return sk;
}

export function verifyBundle(b: PreKeyBundle): void {
  if (!verify(b.sigKey, LABEL.identityDH, b.dhKey, b.dhKeySig)) {
    throw new BundleVerificationError('identity DH key signature invalid');
  }
  if (!verify(b.sigKey, LABEL.signedPreKey, b.signedPreKey.pub, b.signedPreKey.sig)) {
    throw new BundleVerificationError('signed prekey signature invalid');
  }
}

/** Alice's side: start a session from Bob's published bundle. */
export function initiate(me: Identity, bundle: PreKeyBundle): InitiatorResult {
  verifyBundle(bundle);
  const ek = newDHKeyPair();
  const dhs = [
    dh(me.dh.priv, bundle.signedPreKey.pub),
    dh(ek.priv, bundle.dhKey),
    dh(ek.priv, bundle.signedPreKey.pub),
  ];
  if (bundle.oneTimePreKey) dhs.push(dh(ek.priv, bundle.oneTimePreKey.pub));
  const sk = deriveSK(dhs);
  wipe(ek.priv);
  return {
    sk,
    ad: associatedData({ sigKey: me.sig.pub, dhKey: me.dh.pub }, bundle),
    ephemeralPub: ek.pub,
    signedPreKeyId: bundle.signedPreKey.keyId,
    signedPreKeyPub: bundle.signedPreKey.pub,
    oneTimePreKeyId: bundle.oneTimePreKey?.keyId,
  };
}

/** Bob's side: derive the same secret from Alice's initial message. */
export function respond(
  me: Identity,
  signedPreKey: KeyPair,
  oneTimePreKey: KeyPair | undefined,
  initiator: PublicIdentity,
  ephemeralPub: Uint8Array,
): { sk: Uint8Array; ad: Uint8Array } {
  const dhs = [
    dh(signedPreKey.priv, initiator.dhKey),
    dh(me.dh.priv, ephemeralPub),
    dh(signedPreKey.priv, ephemeralPub),
  ];
  if (oneTimePreKey) dhs.push(dh(oneTimePreKey.priv, ephemeralPub));
  return {
    sk: deriveSK(dhs),
    ad: associatedData(initiator, { sigKey: me.sig.pub, dhKey: me.dh.pub }),
  };
}
