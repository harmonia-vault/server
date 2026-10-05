import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { initializationReference } from '../src/recovery-authority-wire.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { recoveryKeys } from './fixtures.js';
import { recoveredGrantsHash } from '../src/recovered-device-wire.js';
import { mutationBytes, grantBytes, verify } from '../src/protocol.js';
import { issuerAuthorityHash } from '../src/issuer-proof.js';
import { environmentOriginHash } from '../src/environment-origin.js';
import { dagCanonical, dagHash, snapshotDAGValue, dagArchiveFields, sourceCanonical, sourceViewCanonical, transitionBytesV2, recoveredEnrollmentBytesV2, recordRow, decodeIssuerRecoveryDAG, decodeRecoveryDependencyBundle, decodeRecoveryTransitionCommandV2, decodeRecoveredDeviceCommandV2, type IssuerRecoveryDAG, type RecoveryDAGRecord, type DAGPairedEnrollment } from '../src/recovery-dag-wire.js';
import { verifyIssuerRecoveryDAG, verifyRecoveryDependencyBundle, type RecoveryDAGPin } from '../src/recovery-dag.js';
import { enrollmentV5Fields, verifyEnrollmentV5 } from '../src/issuer-dag.js';
const vector = JSON.parse(readFileSync(new URL('./vectors/recovery-dag-v1.json', import.meta.url), 'utf8'));
const proof: IssuerRecoveryDAG = vector.proof;
const pin: RecoveryDAGPin = { accountId: vector.rootPin.AccountID, accountGeneration: vector.rootPin.AccountGeneration, rootDeviceId: vector.rootPin.DeviceID, signingPublicKey: vector.rootPin.SigningPublicKey, receivingPublicKey: vector.rootPin.ReceivingPublicKey, initializationHash: initializationReference(proof.initialization) };
const clone = (): IssuerRecoveryDAG => structuredClone(proof);
const accepted = (p: IssuerRecoveryDAG = proof) => verifyIssuerRecoveryDAG(pin, p);
const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');
function family(p: IssuerRecoveryDAG, kind: RecoveryDAGRecord['kind']): any { return p.records.find(r => r.kind === kind)!.record; }

test('Go/Node黄金向量：平坦五节点两次恢复与G全环境Admin复轮，原根/genesis及E真实历史签名保留', () => {
  const decoded = decodeIssuerRecoveryDAG(Buffer.from(JSON.stringify(proof)));
  assert.equal(hex(dagCanonical(decoded)), vector.canonicalHex);
  assert.equal(dagHash(decoded), vector.hash);
  const v = accepted(decoded);
  assert.equal(v.dag.head.generation, '4'); assert.equal(v.dag.head.sequence, 42);
  assert.equal(v.dag.recordChecks, 5); assert.equal(v.dag.records.size, 5);
  assert.equal(v.dag.head.root.rootDeviceId, pin.rootDeviceId);
  assert.equal(v.graph.identities.has('recovered-E'), true);
  assert.equal(v.graph.identities.has('recovered-G'), true);
  assert.equal(v.graph.identities.has('unsigned-directory'), false);
  const author = v.graph.identities.get(vector.cipher.mutation.deviceId)!;
  const source = [...v.graph.authorities.values()].find(n => n.grant.grant.subjectDeviceId === author.id && n.grant.grant.environmentId === vector.cipher.mutation.environmentId && n.grant.grant.keyVersion === vector.cipher.mutation.keyVersion && n.grant.grant.grantGeneration === vector.cipher.mutation.grantGeneration)!.grant;
  assert.equal(source.grant.role, 'admin');
  verify(author.signing, mutationBytes(vector.cipher.mutation), vector.cipher.signature);
  assert.equal(v.graph.origins.has(environmentOriginHash(vector.creation.origin)), true);
  const third = decoded.records.at(-1)! as Extract<RecoveryDAGRecord, { kind: 'transition-v2' }>;
  assert.equal(hex(transitionBytesV2(third.record.submission.transition)), vector.transitionSigningHex);
  const g: any = decoded.records.find(r => r.kind === 'recovered-v2' && r.record.sequence === 41)!.record;
  assert.equal(hex(recoveredEnrollmentBytesV2(g.submission.enrollment)), vector.recoveredSigningHex);
  assert.equal(hex(new TextEncoder().encode(JSON.stringify(enrollmentV5Fields(vector.approval)))), vector.certificateSigningHex);
  assert.equal(JSON.parse(new TextDecoder().decode(dagCanonical(decoded))).length, 6);
  assert.ok(decoded.source.kind === 'proof3');
  assert.equal(JSON.parse(new TextDecoder().decode(sourceViewCanonical(decoded.source.view))).length, 12);
  assert.equal(JSON.parse(new TextDecoder().decode(sourceCanonical(decoded.source))).length, 4);
});

test('DAG依赖不能缺失、越过接受时间、替换种类/根/原初始化或用旧域重解释新签包', async t => {
  const names = ['missing-record', 'wrong-kind', 'forward-head', 'wrong-init', 'wrong-pin', 'changed-original', 'extra-dependency', 'missing-dependency', 'own-future-device', 'old-domain', 'changed-grant', 'wrong-sequence', 'source-identity-new-pub'];
  for (const name of names) await t.test(name, () => {
    const p: any = clone(), q = { ...pin };
    switch (name) {
      case 'missing-record': p.records.splice(0, 1); break;
      case 'wrong-kind': p.source.view.dependencies[0].kind = p.source.view.dependencies[0].kind === 'recovered-v2' ? 'transition-v2' : 'recovered-v2'; break;
      case 'forward-head': family(p, 'recovered-v2').submission.issuerEvidence.view.recoveryHeadHash = p.source.view.recoveryHeadHash; break;
      case 'wrong-init': p.source.view.initializationHash = 'f'.repeat(64); break;
      case 'wrong-pin': q.rootDeviceId = 'server-root'; break;
      case 'changed-original': p.initialization.proposal.device.id = 'server-root'; break;
      case 'extra-dependency': p.source.view.dependencies.push({ kind: 'transition-v1', referenceHash: 'a'.repeat(64) }); break;
      case 'missing-dependency': p.source.view.dependencies = p.source.view.dependencies.slice(0, 1); break;
      case 'own-future-device': family(p, 'recovered-v2').submission.issuerEvidence.view.path = p.source.view.path; break;
      case 'old-domain': p.records.find((r: any) => r.kind === 'transition-v2').kind = 'transition-v1'; break;
      case 'changed-grant': p.source.view.authorities.at(-1).grant.grant.role = 'ro'; break;
      case 'wrong-sequence': family(p, 'recovered-v2').sequence++; break;
      case 'source-identity-new-pub': {
        p.records = p.records.slice(0, 4);
        const s = family(p, 'recovered-v2').submission;
        const archived = s.issuerEvidence.view.identityPaths.flat().find((n: any) => n.kind === 'paired' && n.enrollment.certificateVersion === '5');
        const id = archived.enrollment.approval.context.initiatorDeviceId;
        const deviceSeed = Buffer.from(vector.syntheticSeedsHex.GEd, 'hex');
        s.enrollment.deviceId = id;
        for (const signed of s.grants) { signed.grant.issuerDeviceId = id; signed.grant.subjectDeviceId = id; signed.signature = Buffer.from(ed25519.sign(grantBytes(signed.grant), deviceSeed)).toString('base64url'); }
        s.enrollment.grantsHash = recoveredGrantsHash(s.grants);
        const encoded = recoveredEnrollmentBytesV2(s.enrollment), recovery = recoveryKeys(Buffer.from(vector.syntheticSeedsHex.secondRecovery, 'hex'), pin.accountId, '3');
        s.recoverySignature = Buffer.from(ed25519.sign(encoded, recovery.signingSeed)).toString('base64url');
        s.deviceSignature = Buffer.from(ed25519.sign(encoded, deviceSeed)).toString('base64url');
        assert.throws(() => verifyRecoveryDependencyBundle(q, { initialization: p.initialization, records: p.records }));
        return;
      }
    }
    assert.throws(() => verifyIssuerRecoveryDAG(q, p));
  });
});

test('全环境Admin不能用部分清单、根身份、旧版本/代际或缺封套；已知head不能回退', async t => {
  for (const name of ['partial', 'root-identity', 'wrong-kv', 'wrong-gg', 'omit-envelope', 'source-origin-after-cutoff']) await t.test(name, () => {
    const p: any = clone(), s = p.records.at(-1).record.submission;
    switch (name) {
      case 'partial': s.authoritySet = s.authoritySet.slice(0, 1); break;
      case 'root-identity': s.transition.authorizerDeviceId = pin.rootDeviceId; break;
      case 'wrong-kv': s.authoritySet[0].keyVersion = '999'; break;
      case 'wrong-gg': s.authoritySet[0].grantGeneration = '999'; break;
      case 'omit-envelope': s.envelopes = s.envelopes.slice(0, 1); break;
      case 'source-origin-after-cutoff': s.transition.expectedSequence = '3'; p.records.at(-1).record.sequence = 4; break;
    }
    assert.throws(() => accepted(p));
  });
  const checked = accepted(), point = { referenceHash: checked.dag.head.head, sequence: checked.dag.head.sequence };
  assert.doesNotThrow(() => verifyIssuerRecoveryDAG(pin, proof, point));
  assert.throws(() => verifyIssuerRecoveryDAG(pin, proof, { ...point, sequence: point.sequence + 1 }));
  const historical = { initialization: proof.initialization, records: proof.records.slice(0, 2) };
  const old = verifyRecoveryDependencyBundle(pin, historical);
  const p: any = clone(); p.records = historical.records; p.source.view.recoveryHeadHash = old.head.head; p.source.view.trustRoot = old.head.root;
  assert.throws(() => verifyIssuerRecoveryDAG(pin, p, point));
});

test('拒绝旧来源格式，不从旧证据推导原始初始化', () => {
  const p: any = clone(); p.source = {kind: 'proof2', proof: structuredClone(p.source.view)};
  assert.throws(() => accepted(p));
});

test('新DAG独立JSON schema拒绝重复/未知/null/深层/过量材料，旧P3不能吞新类型', async t => {
  const raw = JSON.stringify(proof);
  const cases: Record<string, Uint8Array> = {
    'duplicate-top': Buffer.from('{"profile":"harmonia/issuer-proof/v4",' + raw.slice(1)),
    'duplicate-nested': Buffer.from(raw.replace('"kind":"proof3"', '"kind":"proof3","kind":"proof3"')),
    'unknown': Buffer.from('{"unexpected":true,' + raw.slice(1)),
    'trailing': Buffer.from(raw + '{}'),
    'invalid-utf8': Buffer.concat([Buffer.from(raw), Buffer.from([255])]),
    'too-deep': Buffer.from('{"x":' + '['.repeat(65) + '0' + ']'.repeat(65) + '}'),
    'too-large': Buffer.alloc(2 * 1024 * 1024 + 1),
  };
  const n: any = clone(); n.records = null; cases['null-array'] = Buffer.from(JSON.stringify(n));
  const o: any = clone(); delete o.records; cases['omitted-array'] = Buffer.from(JSON.stringify(o));
  const u: any = clone(); u.records[0].record.submission.unexpected = true; cases['unknown-submission'] = Buffer.from(JSON.stringify(u));
  for (const [name, bytes] of Object.entries(cases)) await t.test(name, () => assert.throws(() => decodeIssuerRecoveryDAG(bytes)));
  const b = { initialization: proof.initialization, records: proof.records.slice(0, 2) };
  assert.equal(decodeRecoveryDependencyBundle(Buffer.from(JSON.stringify(b))).records.length, 2);
  const transition = { submission: family(proof, 'transition-v2').submission, dependencyBundle: b };
  const device = { submission: family(proof, 'recovered-v2').submission, dependencyBundle: b };
  assert.doesNotThrow(() => decodeRecoveryTransitionCommandV2(Buffer.from(JSON.stringify(transition))));
  assert.doesNotThrow(() => decodeRecoveredDeviceCommandV2(Buffer.from(JSON.stringify(device))));
  assert.throws(() => decodeRecoveryTransitionCommandV2(Buffer.from(JSON.stringify({ ...transition, proof }))));
  assert.throws(() => decodeRecoveredDeviceCommandV2(Buffer.from(JSON.stringify({ ...device, submission: {...family(proof, 'recovered-v2').submission, certificateVersion: '4'} }))));
});

test('平坦记录按接受序号单次核验，输入顺序不替换签名哈希；重复节点/操作及未使用分支拒绝', () => {
  const p = clone(); p.records.reverse();
  assert.equal(dagHash(p), vector.hash); assert.equal(accepted(p).dag.recordChecks, 5);
  const duplicate = clone(); duplicate.records.push(structuredClone(duplicate.records[0]!));
  assert.throws(() => accepted(duplicate));
  const bad: any = clone(); bad.records.find((r: any) => r.kind === 'recovered-v2' && r.record.sequence === 41).record.submission.enrollment.operationId = family(bad, 'recovered-v2').submission.enrollment.operationId;
  assert.throws(() => accepted(bad));
  const unused: any = clone(); unused.records = unused.records.slice(0, 4); unused.source = structuredClone(family(unused, 'recovered-v2').submission.issuerEvidence);
  assert.throws(() => accepted(unused));
  assert.equal(recordRow(proof.records[0]!).length, 6);
  assert.ok([...accepted().graph.authorities.values()].some(n => issuerAuthorityHash(n.grant) !== ''));
});


test('Go实际G→H cert5双签明确批准三环境RO，归档不嵌完整P4且H权限期限不超过G', async t => {
  const approval = vector.approval, confirmed = { context: structuredClone(approval.context), transcriptHash: approval.transcriptHash };
  assert.doesNotThrow(() => verifyEnrollmentV5(pin, approval, confirmed));
  const p: any = clone(), view = p.source.view;
  view.path.push({ kind: 'paired', enrollment: { certificateVersion: '5', issuerProofHash: dagHash(approval.issuerProof), approval: { context: approval.context, pairingProfile: approval.pairingProfile, transcriptHash: approval.transcriptHash, grants: approval.grants, approverSignature: approval.approverSignature, initiatorSignature: approval.initiatorSignature } } });
  for (const grant of approval.grants) {
    const parentHash = view.targets.find((v: any) => v.environmentId === grant.grant.environmentId).authorityHash;
    view.authorities.push({ grant, parentHash, originHash: '', previousGrantHash: '', recoveryEnrollmentHash: '' });
  }
  view.targets = approval.grants.map((grant: any) => ({ environmentId: grant.grant.environmentId, authorityHash: issuerAuthorityHash(grant) }));
  const checked = accepted(p); assert.equal(checked.graph.identities.has(approval.context.initiatorDeviceId), true);
  for (const target of view.targets) assert.equal(checked.graph.authorities.get(target.authorityHash)!.grant.grant.role, 'ro');
  assert.equal('issuerProof' in view.path.at(-1).enrollment.approval, false);
  for (const name of ['anchor-public-key', 'anchor-transcript', 'approver-signature', 'initiator-signature', 'root-pin', 'capability-downgrade', 'old-certificate-domain', 'expiry-escalation']) await t.test(name, () => {
    const a = structuredClone(approval), c = structuredClone(confirmed), q = { ...pin };
    switch (name) {
      case 'anchor-public-key': c.context.approverSigningPublicKey = c.context.initiatorSigningPublicKey; break;
      case 'anchor-transcript': c.transcriptHash = 'f'.repeat(64); break;
      case 'approver-signature': a.approverSignature = a.initiatorSignature; break;
      case 'initiator-signature': delete a.initiatorSignature; break;
      case 'root-pin': q.rootDeviceId = 'directory-root'; break;
      case 'capability-downgrade': a.capabilities = ['issuer-recovery-v1']; break;
      case 'old-certificate-domain': a.certificateVersion = '4'; break;
      case 'expiry-escalation': a.grants[0].grant.expiresAt = '0'; break;
    }
    assert.throws(() => verifyEnrollmentV5(q, a, c));
  });
});

test('新DAG构造持有受限独立pin/bundle；caller返后改原初始化/记录不能改变受信链', () => {
  const p = clone(), q = { ...pin }, bundle = { initialization: p.initialization, records: p.records }, expected = structuredClone(bundle);
  const dag = verifyRecoveryDependencyBundle(q, bundle);
  q.rootDeviceId = 'mutated-caller'; q.accountGeneration = '999';
  bundle.initialization.proposal.environments[0]!.recoveryEnvelope = 'changed';
  (bundle.records[0]!.record.submission as any).authorizationSignature = 'changed';
  bundle.records.splice(1);
  assert.deepEqual(dag.pin, pin); assert.deepEqual(dag.bundle, expected);
  assert.equal(dag.head.generation, '4'); assert.equal(dag.head.sequence, 42);
  assert.equal(dag.records.size, 5); assert.equal(dag.recordChecks, 5);
  assert.doesNotThrow(() => dag.sourceGraph(clone().source, Number.MAX_SAFE_INTEGER));
  assert.throws(() => snapshotDAGValue({ oversized: 'x'.repeat(2 * 1024 * 1024) }));
  let nested: any = {}; for (let i = 0; i < 65; i++) nested = { child: nested };
  assert.throws(() => snapshotDAGValue(nested));
});

test('Source输入与返回graph/公开Map/Set均为快照，返后修改不能污染memo或内部head', () => {
  const checked = accepted(), dag = checked.dag, source = clone().source;
  const graph = dag.sourceGraph(source, Number.MAX_SAFE_INTEGER), expected = structuredClone(graph);
  assert.ok(source.kind === 'proof3'); source.view.origins[0]!.signature = 'caller-changed';
  source.view.authorities[0]!.grant.grant.role = 'none'; source.view.trustRoot.recoveryGeneration = '999';
  (graph.origins.values().next().value as any).signature = 'returned-changed';
  graph.authorities.values().next().value!.grant.grant.role = 'none';
  graph.identities.values().next().value!.signing = 'returned-key'; graph.authorities.clear();
  const recordMap = dag.records, record = recordMap.values().next().value!;
  (record.wire.record.submission as any).transition.operationId = 'returned-op'; record.dependencies.push('returned-ref'); recordMap.clear();
  const recovered = dag.recovered; recovered.values().next().value!.submission.enrollment.deviceId = 'returned-device'; recovered.clear();
  const heads = dag.heads; heads.values().next().value!.seenKeys.clear(); heads.clear();
  const identities = dag.identities; identities.values().next().value!.signing = 'returned-key'; identities.clear();
  const head = dag.head; head.generation = '999'; head.seenKeys.clear(); head.operations.clear();
  const exposed = dag.bundle; exposed.records.splice(0);
  assert.equal(dag.head.generation, '4'); assert.equal(dag.head.sequence, 42); assert.equal(dag.recordChecks, 5);
  assert.equal(dag.records.size, 5); assert.equal(dag.bundle.records.length, 5);
  assert.ok(dag.head.seenKeys.size > 2); assert.ok(dag.recovered.size > 0); assert.ok(dag.identities.size > 1);
  assert.deepEqual(dag.sourceGraph(clone().source, Number.MAX_SAFE_INTEGER), expected);
  assert.deepEqual(Object.keys(expected).sort(), ['authorities', 'identities', 'origins']);
});

test('完整P4与V5返回结果不依赖原callerDTO；改原包/返回权限图后仍可读取同一受信快照', () => {
  const p = clone(), result = accepted(p), expected = structuredClone(result.graph);
  assert.ok(p.source.kind === 'proof3'); p.source.view.origins[0]!.signature = 'changed';
  p.initialization.proposal.device.id = 'changed-root'; p.records.splice(0);
  result.graph.authorities.clear(); result.graph.origins.clear(); result.graph.identities.clear();
  assert.deepEqual(result.dag.sourceGraph(clone().source, Number.MAX_SAFE_INTEGER), expected);
  assert.equal(result.dag.bundle.initialization.proposal.device.id, pin.rootDeviceId);
  const approval = structuredClone(vector.approval), confirmed = { context: structuredClone(approval.context), transcriptHash: approval.transcriptHash };
  const enrolled = verifyEnrollmentV5(pin, approval, confirmed);
  approval.issuerProof.records.splice(0); approval.issuerProof.source.view.origins[0].signature = 'changed';
  approval.context.approverSigningPublicKey = 'changed'; confirmed.context.approverDeviceId = 'changed';
  enrolled.graph.authorities.clear(); enrolled.graph.origins.clear();
  assert.equal(enrolled.dag.head.generation, '4'); assert.equal(enrolled.dag.records.size, 5);
  assert.deepEqual(enrolled.dag.sourceGraph(clone().source, Number.MAX_SAFE_INTEGER), expected);
});
