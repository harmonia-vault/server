import { Fault, type SignedGrant } from './model.js';
import { exact } from './enrollment-wire.js';
import { grantBytes, verify } from './protocol.js';
import { issuerAuthorityHash } from './issuer-proof.js';
import { initialRecoveryAuthority, type RecoveryAuthorityHead } from './recovery-authority-history.js';
import { initializationReference, type RecoveryAuthorityTransition } from './recovery-authority-wire.js';
import { verifyRecoveryControlGraph, type RecoveryControlRecord } from './issuer-recovery.js';
import type { OriginalInitialization } from './initialization-evidence.js';
import { trustRootPayload } from './trust-root.js';
import { sourceCanonical, sourceHash, snapshotDAGValue, dagCanonical, dependencyRows, recordRow, transitionReferencesV2, recoveredReferencesV2, transitionBytesV2, recoveredEnrollmentBytesV2, dagArchiveFields, type DAGPairedEnrollment, type RecoveryDAGKind, type RecoveryDAGRecord, type RecoverySource, type RecoveryDependencyBundle, type IssuerRecoveryDAG } from './recovery-dag-wire.js';

function fail(): never { throw new Fault(403, 'recovery_dag_invalid'); }
export interface RecoveryDAGPin { accountId: string; accountGeneration: string; rootDeviceId: string; signingPublicKey: string; receivingPublicKey: string; initializationHash: string }
interface Identity { id: string; signing: string; receiving: string; archive?: string }
export interface DAGSourceGraph { identities: Map<string, Identity>; authorities: Map<string, { grant: SignedGrant }>; origins: Map<string, unknown> }
interface IndexedRecord { wire: RecoveryDAGRecord; hash: string; sequence: number; dependencies: string[]; operationId: string; expected: number }
const initKey = (o: OriginalInitialization): RecoveryDAGPin => ({ accountId: o.proof.accountId, accountGeneration: o.proof.accountGeneration, rootDeviceId: o.proposal.device.id, signingPublicKey: o.proposal.device.signingPublicKey, receivingPublicKey: o.proposal.device.receivingPublicKey, initializationHash: initializationReference(o) });
function operation(r: RecoveryDAGRecord) { return r.kind.startsWith('transition') ? (r as Extract<RecoveryDAGRecord, { kind: 'transition-v2' }>).record.submission.transition : (r as Extract<RecoveryDAGRecord, { kind: 'recovered-v2' }>).record.submission.enrollment; }
function recordSource(r: RecoveryDAGRecord): RecoverySource | null {
  switch (r.kind) {
    case 'transition-v2': return r.record.submission.issuerEvidence;
    case 'recovered-v2': return r.record.submission.issuerEvidence;
  }
}
/** 已验原初始化与平坦记录。所有record按接受序号迭代验证一次；不递归嵌入Proof4。 */
export class VerifiedRecoveryDAG {
  readonly #records = new Map<string, IndexedRecord>();
  readonly #recovered = new Map<string, RecoveryControlRecord>();
  readonly #heads = new Map<string, RecoveryAuthorityHead>();
  readonly #identities = new Map<string, Identity>();
  readonly #publicOwners = new Map<string, string>();
  readonly #operations = new Set<string>();
  readonly #processed = new Set<string>();
  readonly #sourceMemo = new Map<string, DAGSourceGraph>();
  #lastSequence = 1;
  #edges = 0;
  #head: RecoveryAuthorityHead;
  #recordChecks = 0;
  readonly #pin: RecoveryDAGPin;
  readonly #bundle: RecoveryDependencyBundle;
  // getter是公开材料快照，不暴露内部Map/Set或memo对象。
  get pin(): RecoveryDAGPin { return structuredClone(this.#pin); }
  get bundle(): RecoveryDependencyBundle { return structuredClone(this.#bundle); }
  get records(): Map<string, IndexedRecord> { return structuredClone(this.#records); }
  get recovered(): Map<string, RecoveryControlRecord> { return structuredClone(this.#recovered); }
  get heads(): Map<string, RecoveryAuthorityHead> { return structuredClone(this.#heads); }
  get identities(): Map<string, Identity> { return structuredClone(this.#identities); }
  get head(): RecoveryAuthorityHead { return structuredClone(this.#head); }
  get recordChecks(): number { return this.#recordChecks; }
  constructor(pin: RecoveryDAGPin, bundle: RecoveryDependencyBundle) {
    exact(pin, ['accountId', 'accountGeneration', 'rootDeviceId', 'signingPublicKey', 'receivingPublicKey', 'initializationHash']);
    this.#pin = snapshotDAGValue(pin); this.#bundle = snapshotDAGValue(bundle);
    pin = this.#pin; bundle = this.#bundle;
    exact(bundle, ['initialization', 'records']);
    if (!Array.isArray(bundle.records) || bundle.records.length > 256 || Buffer.byteLength(JSON.stringify(bundle)) > 2 * 1024 * 1024) fail();
    const expectedPin = initKey(bundle.initialization);
    if ((Object.keys(expectedPin) as (keyof RecoveryDAGPin)[]).some(key => pin[key] !== expectedPin[key])) fail();
    this.#head = initialRecoveryAuthority(bundle.initialization); this.#heads.set(this.#head.head, this.#head);
    const root = bundle.initialization.proposal.device, identity = { id: root.id, signing: root.signingPublicKey, receiving: root.receivingPublicKey };
    this.#identities.set(root.id, identity); this.#publicOwners.set(identity.signing, root.id); this.#publicOwners.set(identity.receiving, root.id);
    if (!Array.isArray(bundle.records) || bundle.records.length > 256 || Buffer.byteLength(JSON.stringify(bundle)) > 2 * 1024 * 1024) fail();
    const kinds = { transition: 0, recovered: 0 }, sequences = new Set<number>();
    for (const wire of bundle.records) {
      const row = recordRow(wire), t = operation(wire), expected = Number(t.expectedSequence), sequence = wire.record.sequence;
      if (this.#records.has(row[1]!) || sequences.has(sequence) || sequence !== expected + 1 || t.accountId !== pin.accountId || t.accountGeneration !== pin.accountGeneration || this.#operations.has(t.operationId)) fail();
      const family = wire.kind.startsWith('transition') ? 'transition' : 'recovered'; if (++kinds[family] > 128) fail();
      this.#operations.add(t.operationId); sequences.add(sequence);
      this.#records.set(row[1]!, { wire, hash: row[1]!, sequence, expected, operationId: t.operationId, dependencies: [] });
    }
    for (const node of this.#records.values()) {
      const t = operation(node.wire), parent = node.wire.kind.startsWith('transition') ? (t as RecoveryAuthorityTransition).previousTransitionHash : (t as import('./recovered-device-wire.js').RecoveredEnrollment).recoveryTransitionHash;
      node.dependencies = this.direct(recordSource(node.wire));
      if (parent !== pin.initializationHash) { const record = this.#records.get(parent); if (!record?.wire.kind.startsWith('transition')) fail(); node.dependencies.push(parent); }
      node.dependencies = [...new Set(node.dependencies)]; this.#edges += node.dependencies.length;
      if (this.#edges > 8192 || node.dependencies.some(hash => !this.#records.has(hash) || this.#records.get(hash)!.sequence > node.expected)) fail();
    }
    for (const node of [...this.#records.values()].sort((a, b) => a.sequence - b.sequence)) {
      if (node.dependencies.some(hash => !this.#processed.has(hash))) fail();
      this.#accept(node); this.#recordChecks++; this.#processed.add(node.hash); this.#lastSequence = node.sequence;
    }
  }
  direct(source: RecoverySource | null): string[] {
    if (!source) return []; sourceCanonical(source);
    const v = source.view, hashes = new Set<string>();
    if (v.recoveryHeadHash !== this.#pin.initializationHash) hashes.add(v.recoveryHeadHash);
    for (const n of [...v.path, ...v.identityPaths.flat()]) if (n.kind === 'recovered') hashes.add(n.recoveryEnrollmentHash);
    for (const n of v.authorities) if (n.recoveryEnrollmentHash) hashes.add(n.recoveryEnrollmentHash);
    const expected = [...hashes].map(hash => { const record = this.#records.get(hash); if (!record) fail(); return { kind: record.wire.kind, referenceHash: hash }; });
    if (JSON.stringify(dependencyRows(expected)) !== JSON.stringify(dependencyRows(v.dependencies))) fail(); return [...hashes];
  }
  #remember(graph: DAGSourceGraph): void {
    for (const [id, identity] of graph.identities) {
      const prior = this.#identities.get(id);
      if (prior && (prior.signing !== identity.signing || prior.receiving !== identity.receiving || prior.archive && identity.archive && prior.archive !== identity.archive)) fail();
      for (const pub of [identity.signing, identity.receiving]) {
        const owner = this.#publicOwners.get(pub);
        if (owner && owner !== id || id !== this.#pin.rootDeviceId && this.#head.seenKeys.has(pub)) fail(); this.#publicOwners.set(pub, id);
      }
      this.#identities.set(id, identity);
    }
  }
  sourceGraph(source: RecoverySource, cutoff: number): DAGSourceGraph {
    const graph = this.#sourceGraphOwned(snapshotDAGValue(source), cutoff);
    return structuredClone({ identities: graph.identities, authorities: graph.authorities, origins: graph.origins });
  }
  #sourceGraphOwned(source: RecoverySource, cutoff: number): DAGSourceGraph {
    const memoKey = sourceHash(source);
    if (!Number.isSafeInteger(cutoff) || cutoff < this.#head.sequence || this.direct(source).some(hash => !this.#processed.has(hash) || this.#records.get(hash)!.sequence > cutoff)) fail();
    const v = source.view;
    if (v.initializationHash !== this.#pin.initializationHash || v.recoveryHeadHash !== this.#head.head || v.accountId !== this.#pin.accountId || v.accountGeneration !== this.#pin.accountGeneration || v.origins.some(o => Number(o.origin.expectedSequence) + 1 > cutoff)) fail();
    const g = this.#sourceMemo.get(memoKey) ?? verifyRecoveryControlGraph(v, this.#bundle.initialization, this.#head, this.#recovered, n => dagArchiveFields(n as DAGPairedEnrollment));
    this.#remember(g); this.#sourceMemo.set(memoKey, g); return g;
  }
  #accept(node: IndexedRecord): void {
    const r = node.wire;
    if (node.expected < this.#lastSequence) fail();
    if (r.kind === 'transition-v2') {
      const s = r.record.submission, t = s.transition;
      transitionReferencesV2(r.record.submission);
      if (t.previousTransitionHash !== this.#head.head) fail();
      const seen = new Set(this.#head.seenKeys);
      if (t.oldRecoveryGeneration !== this.#head.generation || t.oldRecoverySigningPublicKey !== this.#head.signing || t.oldRecoveryReceivingPublicKey !== this.#head.receiving) fail();
      let authorizer = t.oldRecoverySigningPublicKey;
      if (t.authorizationKind === 'all-environments-admin') {
        const source = recordSource(r); if (!source) fail(); const graph = this.#sourceGraphOwned(source, node.expected), targets = source.view.targets;
        if (targets.length !== s.environmentManifest.length) fail(); const actor = graph.identities.get(t.authorizerDeviceId); if (!actor) fail(); authorizer = actor.signing;
        for (let i = 0; i < s.environmentManifest.length; i++) { const env = s.environmentManifest[i]!, row = s.authoritySet[i]!, g = graph.authorities.get(row.authorityHash)?.grant.grant, target = targets.find(t => t.environmentId === env.environmentId); if (!g || !target || target.authorityHash !== row.authorityHash || row.environmentId !== env.environmentId || row.keyVersion !== env.keyVersion || g.subjectDeviceId !== t.authorizerDeviceId || g.environmentId !== env.environmentId || g.keyVersion !== env.keyVersion || g.grantGeneration !== row.grantGeneration || g.role !== 'admin' || g.expiresAt !== row.expiresAt) fail(); }
      }
      const root = s.newTrustRoot;
      if (root.rootDeviceId !== this.#pin.rootDeviceId || root.rootSigningPublicKey !== this.#pin.signingPublicKey || root.rootReceivingPublicKey !== this.#pin.receivingPublicKey || root.recoveryGeneration !== t.newRecoveryGeneration || root.recoverySigningPublicKey !== t.newRecoverySigningPublicKey || root.recoveryReceivingPublicKey !== t.newRecoveryReceivingPublicKey) fail();
      for (const pub of [t.newRecoverySigningPublicKey, t.newRecoveryReceivingPublicKey]) { if (seen.has(pub) || this.#publicOwners.has(pub)) fail(); seen.add(pub); }
      const encoded = transitionBytesV2(t); verify(authorizer, encoded, s.authorizationSignature); verify(t.newRecoverySigningPublicKey, encoded, s.newRecoverySignature);
      this.#head = { ...this.#head, generation: t.newRecoveryGeneration, signing: t.newRecoverySigningPublicKey, receiving: t.newRecoveryReceivingPublicKey, head: node.hash, sequence: node.sequence, root: structuredClone(root), seenKeys: seen, operations: new Set([...this.#head.operations, t.operationId]) }; this.#heads.set(node.hash, this.#head);
    } else {
      const s = r.record.submission, e = s.enrollment;
      recoveredReferencesV2(r.record.submission);
      if (!this.#head.operations.size || e.recoveryTransitionHash !== this.#head.head || e.recoveryGeneration !== this.#head.generation || this.#identities.has(e.deviceId)) fail();
      const source = recordSource(r)!;
      const root = source.view.trustRoot;
      if (root.recoveryGeneration !== this.#head.generation || root.recoverySigningPublicKey !== this.#head.signing || root.recoveryReceivingPublicKey !== this.#head.receiving) fail();
      const graph = this.#sourceGraphOwned(source, node.expected), targets = source.view.targets;
      // 来源验过后才能知道本次新出现的归档身份，不能用新公钥重新登记其ID。
      if (graph.identities.has(e.deviceId)) fail();
      for (const pub of [e.deviceSigningPublicKey, e.deviceReceivingPublicKey]) if (this.#head.seenKeys.has(pub) || this.#publicOwners.has(pub)) fail();
      for (let i = 0; i < s.grants.length; i++) {
        const g = s.grants[i]!.grant, right = s.selectedRights[i]!, envelope = s.envelopes[i]!, target = targets.find(t => t.environmentId === right.environmentId), sourceGrant = target && graph.authorities.get(target.authorityHash)?.grant.grant;
        if (g.accountId !== e.accountId || g.accountGeneration !== e.accountGeneration || g.issuerDeviceId !== e.deviceId || g.subjectDeviceId !== e.deviceId || g.subjectSigningPublicKey !== e.deviceSigningPublicKey || g.subjectReceivingPublicKey !== e.deviceReceivingPublicKey || g.grantGeneration !== '1' || g.environmentId !== right.environmentId || g.keyVersion !== right.keyVersion || g.role !== right.role || g.expiresAt !== right.expiresAt || envelope.environmentId !== g.environmentId || envelope.keyVersion !== g.keyVersion || envelope.envelope !== g.envelope || !sourceGrant || sourceGrant.environmentId !== right.environmentId || sourceGrant.keyVersion !== right.keyVersion) fail();
        verify(e.deviceSigningPublicKey, grantBytes(g), s.grants[i]!.signature);
      }
      const encoded = recoveredEnrollmentBytesV2(e); verify(this.#head.signing, encoded, s.recoverySignature); verify(e.deviceSigningPublicKey, encoded, s.deviceSignature);
      this.#recovered.set(node.hash, r.record); const identity = { id: e.deviceId, signing: e.deviceSigningPublicKey, receiving: e.deviceReceivingPublicKey, archive: node.hash };
      this.#identities.set(e.deviceId, identity); this.#publicOwners.set(identity.signing, identity.id); this.#publicOwners.set(identity.receiving, identity.id);
    }
  }
  verifyClosure(source: RecoverySource): void {
    const stack = this.direct(source), reached = new Set<string>();
    if (this.#head.head !== this.#pin.initializationHash) stack.push(this.#head.head);
    while (stack.length) { const hash = stack.pop()!; if (reached.has(hash)) continue; const node = this.#records.get(hash); if (!node) fail(); reached.add(hash); stack.push(...node.dependencies); }
    if (reached.size !== this.#records.size) fail();
  }
}
export function verifyRecoveryDependencyBundle(pin: RecoveryDAGPin, bundle: RecoveryDependencyBundle): VerifiedRecoveryDAG {
  return new VerifiedRecoveryDAG(pin, bundle);
}
export function verifyIssuerRecoveryDAG(pin: RecoveryDAGPin, p: IssuerRecoveryDAG, knownHead?: { referenceHash: string; sequence: number }): { dag: VerifiedRecoveryDAG; graph: DAGSourceGraph } {
  p = snapshotDAGValue(p); dagCanonical(p); const dag = verifyRecoveryDependencyBundle(pin, { initialization: p.initialization, records: p.records });
  if (knownHead && dag.heads.get(knownHead.referenceHash)?.sequence !== knownHead.sequence) fail();
  const graph = dag.sourceGraph(p.source, Number.MAX_SAFE_INTEGER), root = p.source.view.trustRoot;
  if (root.recoveryGeneration !== dag.head.generation || root.recoverySigningPublicKey !== dag.head.signing || root.recoveryReceivingPublicKey !== dag.head.receiving) fail();
  dag.verifyClosure(p.source); return { dag, graph };
}
