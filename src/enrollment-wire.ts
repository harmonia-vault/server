import { sha256 } from "@noble/hashes/sha2.js";
import { Fault, type Account, type Device, type SignedGrant } from "./model.js";
import { bytes, generation, grantBytes, identifier, verify } from "./protocol.js";
export const pairingProfile = "boringssl-spake2-edwards25519-draft02-v1";
import { validateTrustRoot, type TrustRoot } from "./trust-root.js";
export { validateTrustRoot, trustRootPayload as trustRootFields, type TrustRoot } from "./trust-root.js";
export interface InitialEnvironment { environmentId: string; keyVersion: string; recoveryEnvelope: string; grant: SignedGrant }
export interface InitializationProposal {
  idempotencyKey: string; device: Omit<Device, "revoked">; recoveryGeneration: string;
  recoverySigningPublicKey: string; recoveryReceivingPublicKey: string; trustRootSignature: string; environments: InitialEnvironment[];
}
export interface InitializationRecord {
  id: string; sessionHash: string; accountGeneration: string; nonce: string; expiresAt: number;
  proposal: InitializationProposal; proposalHash: string; complete?: { sequence: number; deviceSignature: string; recoverySignature: string };
}
export interface PairingContext {
  accountId: string; accountGeneration: string; purpose: "enroll-device"; sessionId: string; challengeNonce: string; expiresAt: string;
  initiatorDeviceId: string; initiatorSigningPublicKey: string; initiatorReceivingPublicKey: string;
  approverDeviceId: string; approverSigningPublicKey: string; approverReceivingPublicKey: string;
}
export interface EnrollmentCertificate {
  context: PairingContext; pairingProfile: string; transcriptHash: string; grants: SignedGrant[];
  approverSignature: string; initiatorSignature?: string;
}
export interface PairingRecord {
  context: PairingContext;
  messages: Partial<Record<"initiator" | "approver", string>>;
  confirmations: Partial<Record<"initiator" | "approver", string>>;
}
export type EnrollmentAccount = Account & {
  trustRoot?: TrustRoot; vaultInitializations?: Record<string, InitializationRecord>;
};
export function exact(value: unknown, fields: string[]): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join("|") !== [...fields].sort().join("|")) throw new Fault(400, "fields_invalid");
}
export const canonical = (value: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(value));
export const hash = (value: unknown): string => Buffer.from(sha256(canonical(value))).toString("hex");
export function own<T>(map: Record<string, T> | undefined, key: string): T | undefined { return map && Object.hasOwn(map, key) ? map[key] : undefined; }
export function proposalRoot(p: InitializationProposal): TrustRoot {
  return { rootDeviceId: p.device.id, rootSigningPublicKey: p.device.signingPublicKey, rootReceivingPublicKey: p.device.receivingPublicKey,
    recoveryGeneration: p.recoveryGeneration, recoverySigningPublicKey: p.recoverySigningPublicKey,
    recoveryReceivingPublicKey: p.recoveryReceivingPublicKey, signature: p.trustRootSignature };
}
export function initializationHash(accountId: string, accountGeneration: string, p: InitializationProposal): string {
  exact(p, ["idempotencyKey", "device", "recoveryGeneration", "recoverySigningPublicKey", "recoveryReceivingPublicKey", "trustRootSignature", "environments"]);
  identifier(p.idempotencyKey); exact(p.device, ["id", "signingPublicKey", "receivingPublicKey"]); identifier(p.device.id);
  bytes(p.device.signingPublicKey, 32); bytes(p.device.receivingPublicKey, 32);
  if (p.device.signingPublicKey === p.device.receivingPublicKey || p.recoveryGeneration !== "1") throw new Fault(400, "initial_keys_invalid");
  validateTrustRoot(accountId, accountGeneration, proposalRoot(p));
  if (!Array.isArray(p.environments) || p.environments.length < 1 || p.environments.length > 16) throw new Fault(400, "initial_environments_invalid");
  const seen = new Set<string>();
  for (const e of p.environments) exact(e, ["environmentId", "keyVersion", "recoveryEnvelope", "grant"]);
  const sorted = [...p.environments].sort((a, b) => a.environmentId < b.environmentId ? -1 : a.environmentId > b.environmentId ? 1 : 0);
  const envs = sorted.map(e => {
    exact(e, ["environmentId", "keyVersion", "recoveryEnvelope", "grant"]); identifier(e.environmentId); bytes(e.recoveryEnvelope, 80);
    if (e.keyVersion !== "1" || seen.has(e.environmentId)) throw new Fault(400, "initial_environments_invalid"); seen.add(e.environmentId);
    exact(e.grant, ["grant", "signature"]); const g = e.grant.grant; const encoded = grantBytes(g);
    if (g.accountId !== accountId || g.accountGeneration !== accountGeneration || g.issuerDeviceId !== p.device.id || g.subjectDeviceId !== p.device.id ||
      g.subjectSigningPublicKey !== p.device.signingPublicKey || g.subjectReceivingPublicKey !== p.device.receivingPublicKey || g.environmentId !== e.environmentId ||
      g.keyVersion !== "1" || g.grantGeneration !== "1" || g.role !== "admin" || g.expiresAt !== "0") throw new Fault(403, "initial_grant_binding_invalid");
    verify(p.device.signingPublicKey, encoded, e.grant.signature);
    return [e.environmentId, e.keyVersion, e.recoveryEnvelope, Buffer.from(encoded).toString("base64url"), e.grant.signature];
  });
  return hash(["harmonia/vault-initialization-proposal/v1", p.idempotencyKey, p.device.id, p.device.signingPublicKey, p.device.receivingPublicKey,
    p.recoveryGeneration, p.recoverySigningPublicKey, p.recoveryReceivingPublicKey, p.trustRootSignature, envs]);
}
export function initializationFields(accountId: string, r: InitializationRecord): string[] {
  return ["harmonia/vault-initialize/v1", accountId, r.accountGeneration, r.sessionHash, r.id, r.nonce, String(r.expiresAt), r.proposalHash];
}
export function pairingContextFields(c: PairingContext): string[] {
  return ["harmonia/pairing-context/v1", pairingProfile, c.accountId, c.accountGeneration, c.purpose, c.sessionId, c.challengeNonce, c.expiresAt,
    c.initiatorDeviceId, c.initiatorSigningPublicKey, c.initiatorReceivingPublicKey, c.approverDeviceId, c.approverSigningPublicKey, c.approverReceivingPublicKey];
}
export function transcriptHash(record: Pick<PairingRecord, "context" | "messages" | "confirmations">): string {
  const a = record.messages.initiator, b = record.messages.approver;
  if (!a || !b || !record.confirmations.initiator || !record.confirmations.approver) throw new Fault(409, "pairing_confirmation_required");
  return hash(["harmonia/pairing-transcript/v1", Buffer.from(canonical(pairingContextFields(record.context))).toString("base64url"), a, b]);
}
export function grantsHash(grants: SignedGrant[]): string {
  if (!Array.isArray(grants) || !grants.length || grants.length > 256) throw new Fault(400, "grants_invalid");
  const seen = new Set<string>();
  for (const s of grants) { exact(s, ["grant", "signature"]); grantBytes(s.grant); bytes(s.signature, 64); }
  return hash([...grants].sort((a, b) => a.grant.environmentId < b.grant.environmentId ? -1 : a.grant.environmentId > b.grant.environmentId ? 1 : 0).map(s => {
    exact(s, ["grant", "signature"]); const encoded = grantBytes(s.grant); bytes(s.signature, 64);
    if (seen.has(s.grant.environmentId)) throw new Fault(400, "grant_duplicate"); seen.add(s.grant.environmentId);
    return [s.grant.environmentId, Buffer.from(encoded).toString("base64url"), s.signature];
  }));
}
export function enrollmentFields(cert: EnrollmentCertificate): string[] {
  const c = cert.context;
  if (cert.pairingProfile !== pairingProfile || !/^[0-9a-f]{64}$/.test(cert.transcriptHash)) throw new Fault(400, "pairing_profile_invalid");
  return [cert.pairingProfile, c.accountId, c.accountGeneration, c.sessionId, c.challengeNonce, c.expiresAt,
    c.initiatorDeviceId, c.initiatorSigningPublicKey, c.initiatorReceivingPublicKey, c.approverDeviceId, c.approverSigningPublicKey, c.approverReceivingPublicKey,
    cert.transcriptHash, grantsHash(cert.grants)];
}
