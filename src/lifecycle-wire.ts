import { sha256 } from "@noble/hashes/sha2.js";
import { Fault, type Account } from "./model.js";
import { trustRootHash, validateTrustRoot, type TrustRoot } from "./trust-root.js";
export { trustRootPayload, trustRootHash, validateTrustRoot, type TrustRoot } from "./trust-root.js";
import { bytes, generation, identifier } from "./protocol.js";
export interface RecoveryAuth { token: string; accountGeneration: string; deviceId?: string }
export interface Envelope { environmentId: string; keyVersion: string; envelope: string }
export interface RotationProposal { idempotencyKey: string; newRecoveryGeneration: string; newRecoverySigningPublicKey: string; newRecoveryReceivingPublicKey: string; envelopes: Envelope[]; newTrustRoot?: TrustRoot }
export interface BootChallenge { id: string; deviceId: string; generation: string; signingPublicKey: string; receivingPublicKey: string; nonce: string; expiresAt: number }
export interface RecoveryChallenge { id: string; generation: string; recoveryGeneration: string; signingPublicKey: string; nonce: string; expiresAt: number }
export interface RotationRecord {
  state: "pending" | "complete"; id: string; generation: string; recoveryGeneration: string;
  sessionHash: string; deviceId: string | null; nonce: string; expiresAt: number;
  proposal: RotationProposal; envelopesHash: string; signature?: string; sequence?: number; trustRootHash?: string;
}
export function canonical(fields: string[]): Uint8Array { return new TextEncoder().encode(JSON.stringify(fields)); }
export function envelopeHash(envelopes: Envelope[]): string {
  if (!Array.isArray(envelopes) || envelopes.length > 256) throw new Fault(400, "envelopes_invalid");
  const seen = new Set<string>();
  for (const e of envelopes) {
    if (!e || Object.keys(e).sort().join("|") !== "envelope|environmentId|keyVersion") throw new Fault(400, "envelope_fields_invalid");
    identifier(e.environmentId); generation(e.keyVersion); bytes(e.envelope, 80);
    if (seen.has(e.environmentId)) throw new Fault(400, "envelope_duplicate"); seen.add(e.environmentId);
  }
  const sorted = [...envelopes].sort((a, b) => a.environmentId < b.environmentId ? -1 : a.environmentId > b.environmentId ? 1 : 0);
  return Buffer.from(sha256(new TextEncoder().encode(JSON.stringify(sorted.map(e => [e.environmentId, e.keyVersion, e.envelope]))))).toString("hex");
}
export function fullEnvelopes(account: Account, envelopes: Envelope[]): string {
  const hash = envelopeHash(envelopes); const ids = Object.keys(account.environments).sort();
  if (ids.length !== envelopes.length || envelopes.some(e => !Object.hasOwn(account.environments, e.environmentId) || account.environments[e.environmentId]!.keyVersion !== e.keyVersion)) throw new Fault(409, "envelope_set_stale_or_incomplete");
  return hash;
}
export function validateRecoveryState(account: Account): void {
  if (Object.keys(account.environments).length && !account.recoverySigningPublicKey) throw new Fault(409, "recovery_uninitialized");
  if (!account.recoverySigningPublicKey) return;
  generation(account.recoveryGeneration); bytes(account.recoverySigningPublicKey, 32); bytes(account.recoveryReceivingPublicKey ?? "", 32);
  if (account.trustRoot) {
    validateTrustRoot(account.id, account.generation, account.trustRoot);
    const root = account.trustRoot, trusted = account.devices[root.rootDeviceId];
    if (root.recoveryGeneration !== account.recoveryGeneration || root.recoverySigningPublicKey !== account.recoverySigningPublicKey || root.recoveryReceivingPublicKey !== account.recoveryReceivingPublicKey || !trusted || trusted.signingPublicKey !== root.rootSigningPublicKey || trusted.receivingPublicKey !== root.rootReceivingPublicKey) throw new Fault(409, "trust_root_stale");
  }
  for (const env of Object.values(account.environments)) {
    bytes(env.recoveryEnvelope, 80);
    if (env.recoveryGeneration !== account.recoveryGeneration || env.recoveryKeyVersion !== env.keyVersion) throw new Fault(409, "recovery_envelope_stale");
  }
}
export function bootPayload(accountId: string, c: BootChallenge): string[] {
  return ["harmonia/device-boot/v1", accountId, c.generation, c.deviceId, c.signingPublicKey, c.receivingPublicKey, c.id, c.nonce, String(c.expiresAt)];
}
export function recoveryPayload(accountId: string, c: RecoveryChallenge): string[] {
  return ["harmonia/recovery-proof/v1", accountId, c.generation, c.recoveryGeneration, c.id, c.nonce, String(c.expiresAt)];
}
export function rotationPayload(accountId: string, r: RotationRecord): string[] {
  const p = r.proposal;
  const fields = ["harmonia/recovery-rotation/v1", accountId, r.generation, r.sessionHash, r.recoveryGeneration, r.id, r.nonce, String(r.expiresAt), p.newRecoveryGeneration, p.newRecoverySigningPublicKey, p.newRecoveryReceivingPublicKey, r.envelopesHash];
  if (r.trustRootHash) fields.push(r.trustRootHash);
  return fields;
}

export function rotationTrustHash(account: Account, proposal: RotationProposal): string | undefined {
  if (!account.trustRoot) {
    if (proposal.newTrustRoot) throw new Fault(409, "trust_root_uninitialized");
    // Legacy internal fixtures only. Public initialization always establishes a signed trust root.
    return undefined;
  }
  const prior = account.trustRoot, root = proposal.newTrustRoot;
  if (!root) throw new Fault(400, "trust_root_required");
  const hash = trustRootHash(account.id, account.generation, root);
  if (root.rootDeviceId !== prior.rootDeviceId || root.rootSigningPublicKey !== prior.rootSigningPublicKey || root.rootReceivingPublicKey !== prior.rootReceivingPublicKey) throw new Fault(403, "trust_root_substitution");
  if (root.recoveryGeneration !== proposal.newRecoveryGeneration || root.recoverySigningPublicKey !== proposal.newRecoverySigningPublicKey || root.recoveryReceivingPublicKey !== proposal.newRecoveryReceivingPublicKey) throw new Fault(409, "trust_root_recovery_binding_invalid");
  return hash;
}
