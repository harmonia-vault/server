import { Fault } from './model.js';
import type { Store } from './store.js';
import type { RecoveryAuth } from './lifecycle-wire.js';
import { bytes, generation, identifier } from './protocol.js';
import { next, sameAccount, session, tokenHash } from './service.js';
import { accountDAGBundle, accountDAGPin, verifiedAccountDAG } from './recovery-dag-account.js';
import { verifyRecoveryDependencyBundle, verifyIssuerRecoveryDAG } from './recovery-dag.js';
import { initializationReference, recoveryManifestHash } from './recovery-authority-wire.js';
import { issuerRecoveryDAGProfile, recordRow, type RecoveryDependencyBundle } from './recovery-dag-wire.js';
import type { DAGAuthorityChallenge, DAGRecoveredChallenge } from './recovery-dag-service.js';
import { assertRecoveryOperationCapacity, recoveryOperationDirectory, removeClosedChallenge, type RecoveryOperationAccount } from './recovery-operation-guards.js';
import { dependencyBasisHash, operationChallengeHash, resolutionProfile, resolutionTargetFields, resolutionTargetHash, verifyResolutionRequest, type ResolutionRequest, type ResolutionTarget, type ResolutionReceipt } from './recovery-operation-resolution-wire.js';

const conflict = (): never => { throw new Fault(409, 'idempotency_conflict'); };
/** 原基点按历史验；当前恢复代际只用于新受限会话，不覆写旧target。 */
function historicalBasis(a: RecoveryOperationAccount, t: ResolutionTarget): RecoveryDependencyBundle {
  const expected = Number(t.basis.expectedSequence);
  if (expected > a.sequence) return conflict();
  const all = accountDAGBundle(a), bundle = {initialization: all.initialization, records: all.records.filter(r => r.record.sequence <= expected)};
  const d = verifyRecoveryDependencyBundle(accountDAGPin(a), bundle), b = t.basis;
  if (initializationReference(bundle.initialization) !== b.initializationHash || dependencyBasisHash(bundle) !== b.dependencyBundleHash || d.head.sequence > expected || d.head.head !== b.recoveryHeadHash || d.head.generation !== b.recoveryGeneration || d.head.signing !== b.recoverySigningPublicKey || d.head.receiving !== b.recoveryReceivingPublicKey) return conflict();
  return bundle;
}
function matchChallenge(a: RecoveryOperationAccount, t: ResolutionTarget, value: unknown, bundle: RecoveryDependencyBundle): string {
  const c = value as DAGAuthorityChallenge | DAGRecoveredChallenge, b = t.basis;
  const observed = operationChallengeHash(a.id, t.kind, c);
  if (c.operationId !== t.operationId || c.accountGeneration !== t.accountGeneration || c.expectedSequence !== b.expectedSequence || dependencyBasisHash(c.dependencyBundle) !== b.dependencyBundleHash || t.knownChallengeHash && t.knownChallengeHash !== observed) return conflict();
  if (t.kind === 'transition-v2') {
    const old = c as DAGAuthorityChallenge;
    if (old.sessionHash !== t.originalSessionHash || old.authorizationKind !== t.authorizationKind || old.previousTransitionHash !== b.recoveryHeadHash || old.oldRecoveryGeneration !== b.recoveryGeneration || old.oldRecoverySigningPublicKey !== b.recoverySigningPublicKey || old.oldRecoveryReceivingPublicKey !== b.recoveryReceivingPublicKey || recoveryManifestHash(old.environmentManifest) !== b.environmentManifestHash) return conflict();
    if (old.issuerEvidence) {
      const p = verifyIssuerRecoveryDAG(accountDAGPin(a), {profile: issuerRecoveryDAGProfile, accountId: a.id, accountGeneration: a.generation, initialization: bundle.initialization, records: bundle.records, source: old.issuerEvidence});
      const identity = p.graph.identities.get(old.authorizerDeviceId);
      if (old.authorizerDeviceId !== t.deviceId || !identity || identity.signing !== t.deviceSigningPublicKey || identity.receiving !== t.deviceReceivingPublicKey) return conflict();
    }
  } else {
    const old = c as DAGRecoveredChallenge;
    if (old.restrictedSessionHash !== t.originalSessionHash || old.recoveryTransitionHash !== b.recoveryHeadHash || old.recoveryGeneration !== b.recoveryGeneration || old.deviceId !== t.deviceId || old.deviceSigningPublicKey !== t.deviceSigningPublicKey || old.deviceReceivingPublicKey !== t.deviceReceivingPublicKey) return conflict();
    verifyIssuerRecoveryDAG(accountDAGPin(a), {profile: issuerRecoveryDAGProfile, accountId: a.id, accountGeneration: a.generation, initialization: bundle.initialization, records: bundle.records, source: old.issuerEvidence});
  }
  return observed;
}
export class RecoveryOperationResolutionService {
  constructor(readonly store: Store, private readonly clock: () => number = () => Math.floor(Date.now() / 1000)) {}
  async resolve(accountId: string, auth: RecoveryAuth, request: ResolutionRequest): Promise<ResolutionReceipt> {
    identifier(accountId); generation(auth.accountGeneration); bytes(auth.token, 32);
    // 纯编码/签名不授予权限；所有当前授权和状态观察仍在唯一账号事务内。
    const h = await tokenHash(auth.token); verifyResolutionRequest(request, h);
    const t = structuredClone(request.target), targetHash = resolutionTargetHash(t);
    return this.store.transaction(accountId, raw => {
      const a = raw as RecoveryOperationAccount; sameAccount(a, auth.accountGeneration);
      const actor = session(a, h, this.clock(), true);
      if (actor.kind !== 'recovery' || actor.rotationRequired !== true) throw new Fault(403, 'recovery_rotation_required');
      if (actor.recoveryGeneration !== a.recoveryGeneration) throw new Fault(403, 'recovery_session_stale');
      if (t.accountId !== accountId || t.accountGeneration !== a.generation || t.originalSessionHash === h) return conflict();
      const d = recoveryOperationDirectory(a, t.operationId);
      const common = {version: 1, profile: resolutionProfile, accountId, accountGeneration: a.generation, kind: t.kind, operationId: t.operationId, targetHash} as const;
      // 持久closed已由统一Store验证。当前授权仍先验，但后续合法 DAG 换代
      // 造成的DAG gap不能改变此原终态；这里只读精确同target的固定收据。
      if (d.closure) {
        if (d.closure.targetHash !== targetHash || JSON.stringify(resolutionTargetFields(d.closure.target)) !== JSON.stringify(resolutionTargetFields(t))) return conflict();
        return {...common, state: 'closed', sequence: d.closure.sequence, observedChallengeHash: d.closure.observedChallengeHash};
      }
      // 新建closed和accepted仍要求完整当前DAG及原历史basis，没有终态豁免。
      verifiedAccountDAG(a);
      const bundle = historicalBasis(a, t);
      if (d.accepted.length) {
        const prior = d.accepted[0]!;
        if (prior.kind !== t.kind || !prior.record || d.challenges.length !== 1 || d.challenges[0]!.kind !== t.kind) return conflict();
        matchChallenge(a, t, d.challenges[0]!.value, bundle);
        const row = recordRow(prior.record);
        if (t.declaredContentHash && t.declaredContentHash !== row[1]) return conflict();
        return {...common, state: 'accepted', sequence: prior.record.record.sequence, contentHash: row[1]!};
      }
      if (d.challenges.some(c => c.kind !== t.kind)) return conflict();
      let observed: string | null = null;
      if (d.challenges.length) observed = matchChallenge(a, t, d.challenges[0]!.value, bundle);
      else if (t.knownChallengeHash) return conflict();
      if (request.mode === 'query') return {...common, state: 'pending'};
      assertRecoveryOperationCapacity(a, t.operationId);
      const sequence = next(a);
      removeClosedChallenge(a, t.kind, t.operationId);
      a.recoveryOperationClosures ??= {version: 1, entries: {}};
      a.recoveryOperationClosures.entries[t.operationId] = {version: 1, target: t, targetHash, sequence, observedChallengeHash: observed};
      return {...common, state: 'closed', sequence, observedChallengeHash: observed};
    });
  }
}
