import { ed25519 } from '@noble/curves/ed25519.js';
import { Fault } from './model.js';
import { canonical, exact, hash } from './enrollment-wire.js';
import { bytes, generation, identifier } from './protocol.js';
import { digest, recoveryAdminHash, recoveryManifestHash } from './recovery-authority-wire.js';
import { initializationDAGRow, recordRows, sourceHash, type RecoveryDependencyBundle } from './recovery-dag-wire.js';
import type { DAGAuthorityChallenge, DAGRecoveredChallenge } from './recovery-dag-service.js';

export const recoveryOperationClosureCapability = 'recovery-operation-closure-v1';
export const resolutionProfile = 'harmonia-recovery-operation-resolution-v1';
export const maxResolutionBytes = 8192;
export type OperationKind = 'transition-v2' | 'recovered-v2';
export interface ResolutionBasis {
  initializationHash: string; expectedSequence: string; recoveryGeneration: string; recoveryHeadHash: string;
  recoverySigningPublicKey: string; recoveryReceivingPublicKey: string; dependencyBundleHash: string; environmentManifestHash: string;
}
export interface ResolutionTarget {
  profile: 'issuer-recovery-dag-v1'; kind: OperationKind; accountId: string; accountGeneration: string;
  operationId: string; originalSessionHash: string; authorizationKind: 'old-recovery' | 'all-environments-admin';
  deviceId: string; deviceSigningPublicKey: string; deviceReceivingPublicKey: string;
  stage: 'intent' | 'challenged' | 'sealed'; basis: ResolutionBasis;
  declaredIntentHash: string; knownChallengeHash: string; declaredContentHash: string;
}
export interface ResolutionRequest {
  version: 1; mode: 'query' | 'resolve-or-close'; target: ResolutionTarget; deviceSignature: string;
}
interface ResolutionCommon {
  version: 1; profile: typeof resolutionProfile; accountId: string; accountGeneration: string;
  kind: OperationKind; operationId: string; targetHash: string;
}
export type ResolutionReceipt =
  (ResolutionCommon & {state: 'pending'}) |
  (ResolutionCommon & {state: 'accepted'; sequence: number; contentHash: string}) |
  (ResolutionCommon & {state: 'closed'; sequence: number; observedChallengeHash: string | null});

export function validateResolutionTarget(t: ResolutionTarget): void {
  exact(t, ['profile', 'kind', 'accountId', 'accountGeneration', 'operationId', 'originalSessionHash', 'authorizationKind', 'deviceId', 'deviceSigningPublicKey', 'deviceReceivingPublicKey', 'stage', 'basis', 'declaredIntentHash', 'knownChallengeHash', 'declaredContentHash']);
  if (t.profile !== 'issuer-recovery-dag-v1' || !['transition-v2', 'recovered-v2'].includes(t.kind) || !['old-recovery', 'all-environments-admin'].includes(t.authorizationKind) || t.kind === 'recovered-v2' && t.authorizationKind !== 'old-recovery') throw new Fault(400, 'fields_invalid');
  for (const id of [t.accountId, t.operationId, t.deviceId]) identifier(id);
  generation(t.accountGeneration); digest(t.originalSessionHash); digest(t.declaredIntentHash);
  bytes(t.deviceSigningPublicKey, 32); bytes(t.deviceReceivingPublicKey, 32);
  if (t.deviceSigningPublicKey === t.deviceReceivingPublicKey) throw new Fault(400, 'fields_invalid');
  const b = t.basis;
  exact(b, ['initializationHash', 'expectedSequence', 'recoveryGeneration', 'recoveryHeadHash', 'recoverySigningPublicKey', 'recoveryReceivingPublicKey', 'dependencyBundleHash', 'environmentManifestHash']);
  for (const h of [b.initializationHash, b.recoveryHeadHash, b.dependencyBundleHash, b.environmentManifestHash]) digest(h);
  generation(b.expectedSequence); generation(b.recoveryGeneration);
  if (BigInt(b.expectedSequence) > BigInt(Number.MAX_SAFE_INTEGER)) throw new Fault(400, 'checkpoint_invalid');
  bytes(b.recoverySigningPublicKey, 32); bytes(b.recoveryReceivingPublicKey, 32);
  if (b.recoverySigningPublicKey === b.recoveryReceivingPublicKey) throw new Fault(400, 'fields_invalid');
  if (t.knownChallengeHash !== '') digest(t.knownChallengeHash);
  if (t.declaredContentHash !== '') digest(t.declaredContentHash);
  if (t.stage === 'intent' ? t.knownChallengeHash !== '' || t.declaredContentHash !== '' :
      t.stage === 'challenged' ? t.knownChallengeHash === '' || t.declaredContentHash !== '' :
      t.stage === 'sealed' ? t.knownChallengeHash === '' || t.declaredContentHash === '' : true) throw new Fault(400, 'fields_invalid');
}
export function resolutionTargetFields(t: ResolutionTarget): string[] {
  validateResolutionTarget(t); const b = t.basis;
  return ['harmonia/recovery-operation-target/v1', '1', t.profile, t.kind, t.accountId, t.accountGeneration, t.operationId, t.originalSessionHash, t.authorizationKind, t.deviceId, t.deviceSigningPublicKey, t.deviceReceivingPublicKey, t.stage, b.initializationHash, b.expectedSequence, b.recoveryGeneration, b.recoveryHeadHash, b.recoverySigningPublicKey, b.recoveryReceivingPublicKey, b.dependencyBundleHash, b.environmentManifestHash, t.declaredIntentHash, t.knownChallengeHash, t.declaredContentHash];
}
export const resolutionTargetHash = (t: ResolutionTarget): string => hash(resolutionTargetFields(t));
export function resolutionSigningFields(r: ResolutionRequest, currentSessionHash: string): string[] {
  exact(r, ['version', 'mode', 'target', 'deviceSignature']);
  if (r.version !== 1 || !['query', 'resolve-or-close'].includes(r.mode)) throw new Fault(400, 'fields_invalid');
  digest(currentSessionHash);
  return ['harmonia/recovery-operation-resolution/v1', r.mode, currentSessionHash, resolutionTargetHash(r.target)];
}
export function verifyResolutionRequest(r: ResolutionRequest, currentSessionHash: string): void {
  const fields = resolutionSigningFields(r, currentSessionHash);
  if (!ed25519.verify(bytes(r.deviceSignature, 64), canonical(fields), bytes(r.target.deviceSigningPublicKey, 32))) throw new Fault(403, 'signature_invalid');
}
export function dependencyBasisHash(b: RecoveryDependencyBundle): string {
  return hash(['harmonia/recovery-operation-basis/v1', Buffer.from(canonical(initializationDAGRow(b.initialization))).toString('base64url'), Buffer.from(canonical(recordRows(b.records))).toString('base64url')]);
}
export function operationChallengeHash(accountId: string, kind: OperationKind, input: DAGAuthorityChallenge | DAGRecoveredChallenge): string {
  identifier(accountId);
  if (!Number.isSafeInteger(input.expiresAt) || input.expiresAt < 1) throw new Fault(400, 'fields_invalid');
  bytes(input.nonce, 32); identifier(input.challengeId); identifier(input.operationId); generation(input.accountGeneration); generation(input.expectedSequence);
  const base = ['harmonia/recovery-operation-challenge/v1', kind, accountId, input.accountGeneration, input.operationId, input.challengeId, input.nonce, String(input.expiresAt)];
  if (kind === 'transition-v2') {
    const c = input as DAGAuthorityChallenge;
    exact(c, ['operationId', 'challengeId', 'nonce', 'expiresAt', 'sessionHash', 'accountGeneration', 'authorizationKind', 'authorizerDeviceId', 'expectedSequence', 'previousTransitionHash', 'oldRecoveryGeneration', 'oldRecoverySigningPublicKey', 'oldRecoveryReceivingPublicKey', 'environmentManifest', 'authoritySet', 'issuerEvidence', 'dependencyBundle']);
    if (!['old-recovery', 'all-environments-admin'].includes(c.authorizationKind)) throw new Fault(400, 'fields_invalid');
    digest(c.sessionHash); digest(c.previousTransitionHash); generation(c.oldRecoveryGeneration);
    bytes(c.oldRecoverySigningPublicKey, 32); bytes(c.oldRecoveryReceivingPublicKey, 32);
    if (c.authorizationKind === 'old-recovery' ? c.authorizerDeviceId !== '' || c.issuerEvidence !== null || c.authoritySet.length !== 0 : c.authorizerDeviceId === '' || c.issuerEvidence === null) throw new Fault(400, 'fields_invalid');
    if (c.authorizerDeviceId) identifier(c.authorizerDeviceId);
    return hash([...base, c.sessionHash, c.authorizationKind, c.authorizerDeviceId, c.expectedSequence, c.previousTransitionHash, c.oldRecoveryGeneration, c.oldRecoverySigningPublicKey, c.oldRecoveryReceivingPublicKey, recoveryManifestHash(c.environmentManifest), c.authorizationKind === 'old-recovery' ? hash(['harmonia/recovery-admin-authorities/v1', []]) : recoveryAdminHash(c.authoritySet), c.issuerEvidence ? sourceHash(c.issuerEvidence) : '', dependencyBasisHash(c.dependencyBundle)]);
  }
  const c = input as DAGRecoveredChallenge;
  exact(c, ['operationId', 'challengeId', 'nonce', 'expiresAt', 'restrictedSessionHash', 'accountGeneration', 'expectedSequence', 'recoveryGeneration', 'recoveryTransitionHash', 'deviceId', 'deviceSigningPublicKey', 'deviceReceivingPublicKey', 'issuerEvidence', 'dependencyBundle']);
  digest(c.restrictedSessionHash); digest(c.recoveryTransitionHash); generation(c.recoveryGeneration); identifier(c.deviceId); bytes(c.deviceSigningPublicKey, 32); bytes(c.deviceReceivingPublicKey, 32);
  return hash([...base, c.restrictedSessionHash, c.expectedSequence, c.recoveryGeneration, c.recoveryTransitionHash, c.deviceId, c.deviceSigningPublicKey, c.deviceReceivingPublicKey, sourceHash(c.issuerEvidence), dependencyBasisHash(c.dependencyBundle)]);
}
