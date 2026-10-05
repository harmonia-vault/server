import { sha256 } from '@noble/hashes/sha2.js';
import { hash, exact } from './enrollment-wire.js';
import { bytes, grantBytes } from './protocol.js';
import type { SignedGrant } from './model.js';
const b64 = (v: Uint8Array): string => Buffer.from(v).toString('base64url');
const digest = (v: Uint8Array): string => Buffer.from(sha256(v)).toString('hex');
export function issuerAuthorityHash(s: SignedGrant): string {
  exact(s, ["grant", "signature"]);
  bytes(s.signature, 64);
  return hash(["harmonia/issuer-authority/v1", b64(grantBytes(s.grant)), s.signature]);
}
