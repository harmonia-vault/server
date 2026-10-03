import { Fault, type Account } from './model.js';
import { exact, own } from './enrollment-wire.js';
import { digest } from './recovery-authority-wire.js';
import type { RecoveryDAGAccount } from './recovery-dag-account.js';
import type { RecoveryDAGRecord } from './recovery-dag-wire.js';
import { resolutionTargetHash, validateResolutionTarget, type OperationKind, type ResolutionTarget } from './recovery-operation-resolution-wire.js';

// 新分配的联合预算；老五张各128挑战表可留下最多640个既有预留。
export const maxCloseableRecoveryOperations = 256;
const maxPersistedClosures = 5 * 128;
export interface RecoveryOperationClosure {
  version: 1; target: ResolutionTarget; targetHash: string; sequence: number; observedChallengeHash: string | null;
}
export interface RecoveryOperationClosures { version: 1; entries: Record<string, RecoveryOperationClosure> }
export type RecoveryOperationAccount = RecoveryDAGAccount & { recoveryOperationClosures?: RecoveryOperationClosures };
type DirectoryKind = RecoveryDAGRecord['kind'] | 'rotation-v1';
export interface RecoveryOperationDirectory {
  accepted: {kind: DirectoryKind; record?: RecoveryDAGRecord; rotation?: NonNullable<Account['recoveryRotations']>[string]}[];
  challenges: {kind: DirectoryKind; value: unknown}[];
  closure: RecoveryOperationClosure | undefined;
}
export function recoveryOperationId(r: RecoveryDAGRecord): string {
  return r.kind === 'transition-v1' || r.kind === 'transition-v2' ? r.record.submission.transition.operationId : r.record.submission.enrollment.operationId;
}
export function recoveryOperationDirectory(a: RecoveryOperationAccount, id: string): RecoveryOperationDirectory {
  const records: RecoveryDAGRecord[] = [
    ...(a.recoveryAuthorityTransitions ?? []).map(record => ({kind: 'transition-v1' as const, record})),
    ...Object.values(a.recoveredDevices ?? {}).map(record => ({kind: 'recovered-v1' as const, record})),
    ...(a.recoveryDAGHistory ?? []),
  ];
  const accepted: RecoveryOperationDirectory['accepted'] = records.filter(r => recoveryOperationId(r) === id).map(record => ({kind: record.kind, record}));
  const challenges: RecoveryOperationDirectory['challenges'] = [];
  for (const [kind, map] of [
    ['transition-v1', a.recoveryAuthorityChallenges], ['recovered-v1', a.recoveredDeviceChallenges],
    ['transition-v2', a.recoveryDAGChallenges], ['recovered-v2', a.recoveredDAGChallenges],
  ] as const) {
    const value = own(map as Record<string, unknown> | undefined, id);
    if (map && Object.hasOwn(map, id)) {
      if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Fault(409, 'recovery_operation_state_invalid');
      challenges.push({kind, value});
    }
  }
  const rotation = own(a.recoveryRotations, id);
  if (rotation?.state === 'complete') accepted.push({kind: 'rotation-v1', rotation});
  else if (rotation) challenges.push({kind: 'rotation-v1', value: rotation});
  const closure = own(a.recoveryOperationClosures?.entries, id);
  if (accepted.length > 1 || challenges.length > 1 || accepted.length && challenges.length && accepted[0]!.kind !== challenges[0]!.kind || closure && (accepted.length || challenges.length)) throw new Fault(409, 'recovery_operation_state_invalid');
  return {accepted, challenges, closure};
}
/** 所有恢复写入口均在当前账号事务内、原幂等/nonce分支以前调用。 */
export function assertRecoveryOperationOpen(a: RecoveryOperationAccount, id: string, kind: DirectoryKind): void {
  const d = recoveryOperationDirectory(a, id);
  if (d.closure) throw new Fault(409, 'operation_closed');
  if (d.accepted.some(x => x.kind !== kind) || d.challenges.some(x => x.kind !== kind)) throw new Fault(409, 'idempotency_conflict');
}
export function pendingRecoveryOperationIds(a: RecoveryOperationAccount): Set<string> {
  const ids = new Set<string>();
  for (const map of [a.recoveryAuthorityChallenges, a.recoveredDeviceChallenges, a.recoveryDAGChallenges, a.recoveredDAGChallenges, a.recoveryRotations]) for (const id of Object.keys(map ?? {})) {
    if (!recoveryOperationDirectory(a, id).accepted.length) ids.add(id);
  }
  return ids;
}
export function assertRecoveryOperationCapacity(a: RecoveryOperationAccount, id: string): void {
  const pending = pendingRecoveryOperationIds(a);
  // 已有挑战就是预留：即使旧数据超新预算，也允许同ID换为墓碑。
  if (pending.has(id)) return;
  if (Object.keys(a.recoveryOperationClosures?.entries ?? {}).length + pending.size >= maxCloseableRecoveryOperations) throw new Fault(503, 'account_capacity_reached');
}
/** 读和写统一校验；未知版本/损坏不能经旧路由被忽略。 */
export function validateRecoveryOperationClosures(account: Account): void {
  if (!Object.hasOwn(account, 'recoveryOperationClosures')) return;
  try {
    const a = account as RecoveryOperationAccount, c = a.recoveryOperationClosures;
    exact(c, ['version', 'entries']);
    if (c.version !== 1 || !c.entries || typeof c.entries !== 'object' || Array.isArray(c.entries) || Object.keys(c.entries).length > maxPersistedClosures) throw Error();
    const sequences = new Set<number>();
    for (const [id, entry] of Object.entries(c.entries)) {
      exact(entry, ['version', 'target', 'targetHash', 'sequence', 'observedChallengeHash']); validateResolutionTarget(entry.target); digest(entry.targetHash);
      if (entry.version !== 1 || entry.target.operationId !== id || entry.target.accountId !== a.id || entry.target.accountGeneration !== a.generation || resolutionTargetHash(entry.target) !== entry.targetHash || !Number.isSafeInteger(entry.sequence) || entry.sequence <= Number(entry.target.basis.expectedSequence) || entry.sequence > a.sequence || sequences.has(entry.sequence)) throw Error();
      sequences.add(entry.sequence);
      if (entry.observedChallengeHash !== null) digest(entry.observedChallengeHash);
      if (entry.target.knownChallengeHash && entry.target.knownChallengeHash !== entry.observedChallengeHash) throw Error();
      recoveryOperationDirectory(a, id);
    }
  } catch { throw new Fault(409, 'recovery_operation_state_invalid'); }
}
export function removeClosedChallenge(a: RecoveryOperationAccount, kind: OperationKind, id: string): void {
  if (kind === 'transition-v2') delete a.recoveryDAGChallenges?.[id];
  else delete a.recoveredDAGChallenges?.[id];
}
