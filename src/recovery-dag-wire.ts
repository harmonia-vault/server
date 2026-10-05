import { canonical, exact, hash, enrollmentFields, pairingProfile } from './enrollment-wire.js';
import { Fault } from './model.js';
import { bytes, generation, grantBytes, identifier } from './protocol.js';
import { environmentOriginBytes, environmentOriginHash, type SignedEnvironmentOrigin } from './environment-origin.js';
import { type IssuerRecoveryAuthority } from './issuer-recovery.js';
import { trustRootPayload, validateTrustRoot, type TrustRoot } from './trust-root.js';
import { initializationReference, transitionBytes, recoveryManifestHash, recoveryAdminHash, recoveryEnvelopesHash, recoveryRootHash, digest, type RecoveryAuthorityTransition, type RecoveryTransitionSubmission } from './recovery-authority-wire.js';
import { recoveredEnrollmentBytes, recoveredRightsHash, recoveredGrantsHash, recoveredEnvelopesHash, type RecoveredEnrollment, type RecoveredDeviceSubmission } from './recovered-device-wire.js';
import type { OriginalInitialization } from './initialization-evidence.js';

export const recoveryDAGCapability = 'issuer-recovery-dag-v1';
export const issuerRecoveryDAGProfile = 'harmonia/issuer-proof/v4';
export const recoverySourceViewProfile = 'harmonia/issuer-proof/v3-source/v1';
export const maxRecoveryDAGBytes = 2 * 1024 * 1024;
import { sha256 } from '@noble/hashes/sha2.js';
import { strictRecoveryJson } from './strict-recovery-body.js';
const b64 = (v: Uint8Array): string => Buffer.from(v).toString('base64url');
const compare = (a: string, b: string): number => a < b ? -1 : a > b ? 1 : 0;
function fail(): never { throw new Fault(400, 'recovery_dag_invalid'); }
export type RecoveryDAGKind = 'transition-v2' | 'recovered-v2';
export interface RecoveryDependency { kind: RecoveryDAGKind; referenceHash: string }
export type DAGPairedEnrollment = { certificateVersion: '5'; issuerProofHash: string; approval: import('./enrollment-wire.js').EnrollmentCertificate };
export type DAGArchive = { kind: 'paired'; enrollment: DAGPairedEnrollment } | { kind: 'recovered'; recoveryEnrollmentHash: string };
export interface RecoverySourceView {
  profile: typeof recoverySourceViewProfile; accountId: string; accountGeneration: string;
  initializationHash: string; trustRoot: TrustRoot; recoveryHeadHash: string;
  path: DAGArchive[]; authorities: IssuerRecoveryAuthority[];
  targets: { environmentId: string; authorityHash: string }[];
  origins: SignedEnvironmentOrigin[]; identityPaths: DAGArchive[][]; dependencies: RecoveryDependency[];
}
export type RecoverySource = { kind: 'proof3'; view: RecoverySourceView };
export type RecoveryAuthorityTransitionV2 = RecoveryAuthorityTransition;
export type RecoveryTransitionSubmissionV2 = Omit<RecoveryTransitionSubmission, 'issuerEvidence'> & { issuerEvidence: RecoverySource | null };
export interface AcceptedRecoveryTransitionV2 { submission: RecoveryTransitionSubmissionV2; sequence: number }
export type RecoveredDeviceEnrollmentV2 = RecoveredEnrollment;
export type RecoveredDeviceSubmissionV2 = Omit<RecoveredDeviceSubmission, 'certificateVersion' | 'capabilities' | 'issuerEvidence'> & { certificateVersion: '5'; capabilities: [typeof recoveryDAGCapability]; issuerEvidence: RecoverySource };
export interface AcceptedRecoveredDeviceV2 { submission: RecoveredDeviceSubmissionV2; sequence: number }
export type RecoveryDAGRecord =
  { kind: 'transition-v2'; record: AcceptedRecoveryTransitionV2 } |
  { kind: 'recovered-v2'; record: AcceptedRecoveredDeviceV2 };
export interface RecoveryDependencyBundle { initialization: OriginalInitialization; records: RecoveryDAGRecord[] }
export interface IssuerRecoveryDAG {
  profile: typeof issuerRecoveryDAGProfile; accountId: string; accountGeneration: string;
  initialization: OriginalInitialization; source: RecoverySource; records: RecoveryDAGRecord[];
}
export interface RecoveryTransitionCommandV2 { submission: RecoveryTransitionSubmissionV2; dependencyBundle: RecoveryDependencyBundle }
export interface RecoveredDeviceCommandV2 { submission: RecoveredDeviceSubmissionV2; dependencyBundle: RecoveryDependencyBundle }

export const transitionBytesV2 = (t: RecoveryAuthorityTransitionV2): Uint8Array => transitionBytes(t);
export const recoveredEnrollmentBytesV2 = (e: RecoveredDeviceEnrollmentV2): Uint8Array => recoveredEnrollmentBytes(e);
export function transitionHashV2(s: RecoveryTransitionSubmissionV2): string {
  bytes(s.authorizationSignature, 64); bytes(s.newRecoverySignature, 64);
  return hash(['harmonia/recovery-authority-transition-ref/v2', b64(transitionBytesV2(s.transition)), s.authorizationSignature, s.newRecoverySignature]);
}
export function recoveredDeviceHashV2(s: RecoveredDeviceSubmissionV2): string {
  bytes(s.recoverySignature, 64); bytes(s.deviceSignature, 64);
  return hash(['harmonia/recovered-device-enrollment-ref/v2', b64(recoveredEnrollmentBytesV2(s.enrollment)), s.recoverySignature, s.deviceSignature]);
}
export function dagArchiveFields(n: DAGPairedEnrollment): string[] {
  if (n.certificateVersion !== '5') fail();
  exact(n, ['certificateVersion', 'issuerProofHash', 'approval']); digest(n.issuerProofHash);
  exact(n.approval, ['context', 'pairingProfile', 'transcriptHash', 'grants', 'approverSignature', 'initiatorSignature']);
  const c = n.approval.context;
  exact(c, ['accountId', 'accountGeneration', 'purpose', 'sessionId', 'challengeNonce', 'expiresAt', 'initiatorDeviceId', 'initiatorSigningPublicKey', 'initiatorReceivingPublicKey', 'approverDeviceId', 'approverSigningPublicKey', 'approverReceivingPublicKey']);
  for (const id of [c.accountId, c.sessionId, c.initiatorDeviceId, c.approverDeviceId]) identifier(id);
  generation(c.accountGeneration); generation(c.expiresAt); bytes(c.challengeNonce, 32);
  for (const pub of [c.initiatorSigningPublicKey, c.initiatorReceivingPublicKey, c.approverSigningPublicKey, c.approverReceivingPublicKey]) bytes(pub, 32);
  if (c.purpose !== 'enroll-device' || c.initiatorDeviceId === c.approverDeviceId || c.initiatorSigningPublicKey === c.initiatorReceivingPublicKey || c.approverSigningPublicKey === c.approverReceivingPublicKey || BigInt(c.expiresAt) > 253402300799n || n.approval.pairingProfile !== pairingProfile) fail();
  bytes(n.approval.approverSignature, 64); bytes(n.approval.initiatorSignature!, 64);
  return ['harmonia/device-enrollment/v5', ...enrollmentFields(n.approval), n.issuerProofHash];
}
export function dagPathRows(path: DAGArchive[]): string[][] {
  if (!Array.isArray(path) || path.length > 32) fail();
  return path.map((n, i) => {
    if (n.kind === 'paired') { exact(n, ['kind', 'enrollment']); return ['paired', n.enrollment.certificateVersion, b64(canonical(dagArchiveFields(n.enrollment))), n.enrollment.approval.approverSignature, n.enrollment.approval.initiatorSignature!]; }
    if (n.kind !== 'recovered' || i !== 0) fail(); exact(n, ['kind', 'recoveryEnrollmentHash']); digest(n.recoveryEnrollmentHash); return ['recovered', n.recoveryEnrollmentHash];
  });
}
export function dependencyRows(deps: RecoveryDependency[]): string[][] {
  if (!Array.isArray(deps) || deps.length > 256) fail(); const seen = new Set<string>();
  return [...deps].sort((a, b) => compare(a.kind, b.kind) || compare(a.referenceHash, b.referenceHash)).map(d => {
    exact(d, ['kind', 'referenceHash']); if (!['transition-v2', 'recovered-v2'].includes(d.kind) || seen.has(d.referenceHash)) fail();
    digest(d.referenceHash); seen.add(d.referenceHash); return [d.kind, d.referenceHash];
  });
}
export function sourceViewCanonical(v: RecoverySourceView): Uint8Array {
  exact(v, ['profile', 'accountId', 'accountGeneration', 'initializationHash', 'trustRoot', 'recoveryHeadHash', 'path', 'authorities', 'targets', 'origins', 'identityPaths', 'dependencies']);
  if (v.profile !== recoverySourceViewProfile || !Array.isArray(v.authorities) || !v.authorities.length || v.authorities.length > 1024 || !Array.isArray(v.targets) || v.targets.length > 256 || !Array.isArray(v.origins) || v.origins.length > 128 || !Array.isArray(v.identityPaths) || v.identityPaths.length > 32) fail();
  identifier(v.accountId); generation(v.accountGeneration); digest(v.initializationHash); digest(v.recoveryHeadHash); validateTrustRoot(v.accountId, v.accountGeneration, v.trustRoot);
  const path = dagPathRows(v.path), paths = v.identityPaths.map(dagPathRows).sort((a, b) => compare(JSON.stringify(a), JSON.stringify(b)));
  if (path.length + paths.reduce((n, p) => n + p.length, 0) > 256 || paths.some((p, i) => !p.length || i > 0 && JSON.stringify(p) === JSON.stringify(paths[i - 1]))) fail();
  const seen = new Set<string>(), authorities = [...v.authorities].sort((a, b) => { const x = a.grant.grant, y = b.grant.grant; return compare(x.environmentId, y.environmentId) || compare(x.subjectDeviceId, y.subjectDeviceId) || (BigInt(x.grantGeneration) < BigInt(y.grantGeneration) ? -1 : BigInt(x.grantGeneration) > BigInt(y.grantGeneration) ? 1 : 0); }).map(n => {
    exact(n, ['grant', 'parentHash', 'originHash', 'previousGrantHash', 'recoveryEnrollmentHash']); exact(n.grant, ['grant', 'signature']);
    const g = n.grant.grant, encoded = grantBytes(g), id = `${g.environmentId}/${g.subjectDeviceId}/${g.grantGeneration}`;
    if (g.role === 'none' || seen.has(id)) fail(); seen.add(id); bytes(n.grant.signature, 64);
    for (const h of [n.parentHash, n.originHash, n.previousGrantHash, n.recoveryEnrollmentHash]) if (h !== '') digest(h);
    return [g.environmentId, g.subjectDeviceId, g.grantGeneration, b64(encoded), n.grant.signature, n.parentHash, n.originHash, n.previousGrantHash, n.recoveryEnrollmentHash];
  });
  const targetIds = new Set<string>(), targets = [...v.targets].sort((a, b) => compare(a.environmentId, b.environmentId)).map(t => {
    exact(t, ['environmentId', 'authorityHash']); identifier(t.environmentId); digest(t.authorityHash); if (targetIds.has(t.environmentId)) fail(); targetIds.add(t.environmentId); return [t.environmentId, t.authorityHash];
  });
  const originIds = new Set<string>(), origins = v.origins.map(o => { const h = environmentOriginHash(o); if (originIds.has(h)) fail(); originIds.add(h); return [h, b64(environmentOriginBytes(o.origin)), o.signature]; }).sort((a, b) => compare(a[0]!, b[0]!));
  const encoded = canonical([v.profile, v.accountId, v.accountGeneration, v.initializationHash, [b64(canonical(trustRootPayload(v.accountId, v.accountGeneration, v.trustRoot))), v.trustRoot.signature], v.recoveryHeadHash, path, authorities, targets, origins, paths, dependencyRows(v.dependencies)]);
  if (encoded.length > maxRecoveryDAGBytes) fail(); return encoded;
}
export function sourceCanonical(s: RecoverySource): Uint8Array {
  if (s.kind !== 'proof3') fail(); exact(s, ['kind', 'view']); return canonical(['harmonia/recovery-source/v1', 'proof3', recoverySourceViewProfile, b64(sourceViewCanonical(s.view))]);
}
export const sourceHash = (s: RecoverySource): string => Buffer.from(sha256(sourceCanonical(s))).toString('hex');
export function initializationDAGRow(o: OriginalInitialization): string[] {
  const h = initializationReference(o), p = o.proposal, c = o.proof;
  // 复用原初始化域与实际双签；不推断当前self-grant或造替代原proposal。
  const envs = [...p.environments].sort((a, b) => compare(a.environmentId, b.environmentId)).map(e => [e.environmentId, e.keyVersion, e.recoveryEnvelope, b64(grantBytes(e.grant.grant)), e.grant.signature]);
  const proposal = canonical(['harmonia/vault-initialization-proposal/v1', p.idempotencyKey, p.device.id, p.device.signingPublicKey, p.device.receivingPublicKey, p.recoveryGeneration, p.recoverySigningPublicKey, p.recoveryReceivingPublicKey, p.trustRootSignature, envs]);
  const proof = canonical(['harmonia/vault-initialize/v1', c.accountId, c.accountGeneration, c.loginTokenHash, c.challengeId, c.nonce, c.expiresAt, c.proposalHash]);
  return [h, b64(proposal), b64(proof), o.deviceSignature, o.recoverySignature, '1'];
}
export function recordRow(r: RecoveryDAGRecord): string[] {
  exact(r, ['kind', 'record']); exact(r.record, ['submission', 'sequence']);
  let reference: string, signing: Uint8Array, a: string, b: string;
  switch (r.kind) {
    case 'transition-v2': transitionReferencesV2(r.record.submission); reference = transitionHashV2(r.record.submission); signing = transitionBytesV2(r.record.submission.transition); a = r.record.submission.authorizationSignature; b = r.record.submission.newRecoverySignature; break;
    case 'recovered-v2': recoveredReferencesV2(r.record.submission); reference = recoveredDeviceHashV2(r.record.submission); signing = recoveredEnrollmentBytesV2(r.record.submission.enrollment); a = r.record.submission.recoverySignature; b = r.record.submission.deviceSignature; break;
    default: return fail();
  }
  if (!Number.isSafeInteger(r.record.sequence) || r.record.sequence < 2) fail(); return [r.kind, reference, b64(signing), a, b, String(r.record.sequence)];
}
export function recordRows(records: RecoveryDAGRecord[]): string[][] {
  if (!Array.isArray(records) || records.length > 256) fail(); const seen = new Set<string>(), counts = { transition: 0, recovered: 0 };
  return records.map(r => { const row = recordRow(r), kind = r.kind.startsWith('transition') ? 'transition' : 'recovered'; if (++counts[kind] > 128 || seen.has(row[1]!)) fail(); seen.add(row[1]!); return row; }).sort((a, b) => compare(a[0]!, b[0]!) || compare(a[1]!, b[1]!));
}
export function dagCanonical(p: IssuerRecoveryDAG): Uint8Array {
  exact(p, ['profile', 'accountId', 'accountGeneration', 'initialization', 'source', 'records']);
  if (p.profile !== issuerRecoveryDAGProfile || p.accountId !== p.initialization.proof.accountId || p.accountGeneration !== p.initialization.proof.accountGeneration) fail();
  const encoded = canonical([p.profile, p.accountId, p.accountGeneration, initializationDAGRow(p.initialization), sourceHash(p.source), recordRows(p.records)]);
  if (encoded.length > maxRecoveryDAGBytes || Buffer.byteLength(JSON.stringify(p)) > maxRecoveryDAGBytes) fail(); return encoded;
}
export const dagHash = (p: IssuerRecoveryDAG): string => Buffer.from(sha256(dagCanonical(p))).toString('hex');
export function transitionReferencesV2(s: RecoveryTransitionSubmissionV2): void {
  exact(s, ['transition', 'environmentManifest', 'authoritySet', 'issuerEvidence', 'envelopes', 'newTrustRoot', 'authorizationSignature', 'newRecoverySignature']);
  const t = s.transition; transitionBytesV2(t); bytes(s.authorizationSignature, 64); bytes(s.newRecoverySignature, 64);
  if (recoveryManifestHash(s.environmentManifest) !== t.environmentManifestHash || recoveryEnvelopesHash(s.envelopes) !== t.envelopesHash || recoveryRootHash(t.accountId, t.accountGeneration, s.newTrustRoot) !== t.newTrustRootHash || s.envelopes.length !== s.environmentManifest.length || s.envelopes.some((e, i) => e.environmentId !== s.environmentManifest[i]!.environmentId || e.keyVersion !== s.environmentManifest[i]!.keyVersion)) fail();
  if (t.authorizationKind === 'old-recovery') { if (!Array.isArray(s.authoritySet) || s.authoritySet.length || s.issuerEvidence !== null) fail(); }
  else if (!s.issuerEvidence || recoveryAdminHash(s.authoritySet) !== t.authoritySetHash || sourceHash(s.issuerEvidence) !== t.issuerEvidenceHash || s.authoritySet.length !== s.environmentManifest.length) fail();
  if (Buffer.byteLength(JSON.stringify(s)) > maxRecoveryDAGBytes) fail();
}
export function recoveredReferencesV2(s: RecoveredDeviceSubmissionV2): void {
  exact(s, ['certificateVersion', 'capabilities', 'enrollment', 'selectedRights', 'grants', 'issuerEvidence', 'envelopes', 'recoverySignature', 'deviceSignature']);
  if (s.certificateVersion !== '5' || JSON.stringify(s.capabilities) !== JSON.stringify([recoveryDAGCapability])) fail();
  const e = s.enrollment; recoveredEnrollmentBytesV2(e); bytes(s.recoverySignature, 64); bytes(s.deviceSignature, 64);
  if (recoveredRightsHash(s.selectedRights) !== e.selectedRightsHash || recoveredGrantsHash(s.grants) !== e.grantsHash || recoveredEnvelopesHash(s.envelopes) !== e.envelopesHash || sourceHash(s.issuerEvidence) !== e.issuerEvidenceHash || s.grants.length !== s.selectedRights.length || s.envelopes.length !== s.grants.length) fail();
  if (Buffer.byteLength(JSON.stringify(s)) > maxRecoveryDAGBytes) fail();
}

/** 独立新schema；拒绝重复成员、未知字段、无效UTF-8、过深或超量JSON。 */
export function decodeIssuerRecoveryDAG(raw: Uint8Array): IssuerRecoveryDAG {
  const p = strictRecoveryJson(raw) as unknown as IssuerRecoveryDAG; dagCanonical(p); return p;
}
export function decodeRecoveryDependencyBundle(raw: Uint8Array): RecoveryDependencyBundle {
  const b = strictRecoveryJson(raw) as unknown as RecoveryDependencyBundle;
  exact(b, ['initialization', 'records']); initializationDAGRow(b.initialization); recordRows(b.records); return b;
}
export function decodeRecoveryTransitionCommandV2(raw: Uint8Array): RecoveryTransitionCommandV2 {
  const c = strictRecoveryJson(raw) as unknown as RecoveryTransitionCommandV2;
  exact(c, ['submission', 'dependencyBundle']); transitionReferencesV2(c.submission);
  exact(c.dependencyBundle, ['initialization', 'records']); initializationDAGRow(c.dependencyBundle.initialization); recordRows(c.dependencyBundle.records); return c;
}
export function decodeRecoveredDeviceCommandV2(raw: Uint8Array): RecoveredDeviceCommandV2 {
  const c = strictRecoveryJson(raw) as unknown as RecoveredDeviceCommandV2;
  exact(c, ['submission', 'dependencyBundle']); recoveredReferencesV2(c.submission);
  exact(c.dependencyBundle, ['initialization', 'records']); initializationDAGRow(c.dependencyBundle.initialization); recordRows(c.dependencyBundle.records); return c;
}

/** 新DAG入口持有独立JSON材料；原parser不使用此快照函数。 */
export function snapshotDAGValue<T extends object>(value: T): T {
  let raw: string;
  try {
    raw = JSON.stringify(value, (_key, member: unknown) => {
      if (member === undefined || typeof member === 'function' || typeof member === 'symbol' || typeof member === 'bigint' || typeof member === 'number' && !Number.isSafeInteger(member)) fail();
      return member;
    });
  } catch { return fail(); }
  return strictRecoveryJson(new TextEncoder().encode(raw)) as unknown as T;
}
