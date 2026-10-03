import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { nodeHarness, workerHarness, setupEnvironments, freshRecovery, revoke, sign, b64, seeds, type Harness } from "./recovery-origin-fixtures.js";
import { recoveryKeys } from "./fixtures.js";
import { transitionBytes, transitionHash, recoveryManifestHash, recoveryAdminHash, recoveryEvidenceHash, recoveryEnvelopesHash, recoveryRootHash, legacyStateHash, type RecoveryTransitionSubmission } from "../src/recovery-authority-wire.js";
import { recoveredEnrollmentBytes, recoveredRightsHash, recoveredGrantsHash, recoveredEnvelopesHash, recoveredDeviceHash, type RecoveredDeviceSubmission } from "../src/recovered-device-wire.js";
import { canonical, hash, pairingContextFields, pairingProfile } from "../src/enrollment-wire.js";
import { grantBytes, mutationBytes } from "../src/protocol.js";
import { trustRootPayload } from "../src/trust-root.js";
import { verifyIssuerRecoveryGraph, enrollmentV4Fields, type EnrollmentApprovalV4 } from "../src/issuer-recovery.js";
import { issuerAuthorityHash } from "../src/issuer-proof.js";
import { relayFields } from "../src/enrollment.js";
const cap = 'capability=issuer-recovery-v1';
const v = JSON.parse(readFileSync(new URL('./vectors/recovery-authority-v1.json', import.meta.url), 'utf8'));
export function transitionPacket(h: Harness, c: any, kind = 'old-recovery'): RecoveryTransitionSubmission {
    const s = structuredClone(v.oldRecoveryTransition.submission) as RecoveryTransitionSubmission, t = s.transition, newGeneration = String(BigInt(c.oldRecoveryGeneration) + 1n), keys = recoveryKeys(Buffer.alloc(32, newGeneration === '2' ? 89 : 90), h.account.id, newGeneration), old = recoveryKeys(Buffer.alloc(32, 88), h.account.id);
    const root = { rootDeviceId: c.originalInitialization.proposal.device.id, rootSigningPublicKey: c.originalInitialization.proposal.device.signingPublicKey, rootReceivingPublicKey: c.originalInitialization.proposal.device.receivingPublicKey, recoveryGeneration: newGeneration, recoverySigningPublicKey: keys.signingPublicKey, recoveryReceivingPublicKey: keys.receivingPublicKey, signature: '' };
    root.signature = sign(trustRootPayload(h.account.id, '1', root), keys.signingSeed);
    s.environmentManifest = c.environmentManifest;
    s.authoritySet = c.authoritySet;
    s.issuerEvidence = c.issuerEvidence;
    s.legacyState = c.legacyState;
    s.envelopes = c.environmentManifest.map((e: any) => ({ ...e, envelope: b64(Buffer.alloc(80, 29)) }));
    s.newTrustRoot = root;
    Object.assign(t, { accountId: h.account.id, accountGeneration: '1', operationId: 'continuous-1', challengeId: c.challengeId, nonce: c.nonce, expiresAt: String(c.expiresAt), sessionHash: c.sessionHash, expectedSequence: c.expectedSequence, previousTransitionHash: c.previousTransitionHash, oldRecoveryGeneration: c.oldRecoveryGeneration, oldRecoverySigningPublicKey: c.oldRecoverySigningPublicKey, oldRecoveryReceivingPublicKey: c.oldRecoveryReceivingPublicKey, newRecoveryGeneration: newGeneration, newRecoverySigningPublicKey: keys.signingPublicKey, newRecoveryReceivingPublicKey: keys.receivingPublicKey, authorizationKind: kind, authorizerDeviceId: kind === 'old-recovery' ? '' : 'device-B', environmentManifestHash: recoveryManifestHash(s.environmentManifest), authoritySetHash: kind === 'old-recovery' ? '' : recoveryAdminHash(s.authoritySet), issuerEvidenceHash: kind === 'old-recovery' ? '' : recoveryEvidenceHash(s.issuerEvidence!), envelopesHash: recoveryEnvelopesHash(s.envelopes), newTrustRootHash: recoveryRootHash(h.account.id, '1', root), chainMode: c.legacyState ? 'manager-reanchor' : 'continuous', legacyStateHash: c.legacyState ? legacyStateHash(h.account.id, '1', c.legacyState) : '' });
    s.authorizationSignature = b64(ed25519.sign(transitionBytes(t), kind === 'old-recovery' ? old.signingSeed : seeds.B!));
    s.newRecoverySignature = b64(ed25519.sign(transitionBytes(t), keys.signingSeed));
    return s;
}
export function devicePacket(h: Harness, c: any, transition: string): RecoveredDeviceSubmission {
    const s = structuredClone(v.recoveredDevice.submission) as RecoveredDeviceSubmission, e = s.enrollment, keys = recoveryKeys(Buffer.alloc(32, 89), h.account.id, '2'), ed = Buffer.alloc(32, 6), pub = b64(ed25519.getPublicKey(ed)), x = b64(x25519.getPublicKey(Buffer.alloc(32, 10)));
    s.selectedRights = c.issuerEvidence.targets.map((t: any) => ({ environmentId: t.environmentId, keyVersion: c.issuerEvidence.authorities.find((n: any) => issuerAuthorityHash(n.grant) === t.authorityHash).grant.grant.keyVersion, role: 'admin' as const, expiresAt: '0' })).sort((a: any, b: any) => a.environmentId < b.environmentId ? -1 : 1);
    s.envelopes = s.selectedRights.map(r => ({ environmentId: r.environmentId, keyVersion: r.keyVersion, envelope: b64(Buffer.alloc(80, 30)) }));
    s.grants = s.selectedRights.map((r, i) => { const grant = { accountId: h.account.id, accountGeneration: '1', issuerDeviceId: 'device-E', subjectDeviceId: 'device-E', subjectSigningPublicKey: pub, subjectReceivingPublicKey: x, environmentId: r.environmentId, keyVersion: r.keyVersion, grantGeneration: '1', role: r.role, expiresAt: r.expiresAt, idempotencyKey: `recovered-${i}`, envelope: s.envelopes[i]!.envelope }; return { grant, signature: b64(ed25519.sign(grantBytes(grant), ed)) }; });
    s.issuerEvidence = c.issuerEvidence;
    Object.assign(e, { accountId: h.account.id, accountGeneration: '1', recoveryGeneration: '2', recoveryTransitionHash: transition, operationId: 'recover-E', challengeId: c.challengeId, nonce: c.nonce, expiresAt: String(c.expiresAt), restrictedSessionHash: c.restrictedSessionHash, expectedSequence: c.expectedSequence, deviceId: 'device-E', deviceSigningPublicKey: pub, deviceReceivingPublicKey: x, selectedRightsHash: recoveredRightsHash(s.selectedRights), grantsHash: recoveredGrantsHash(s.grants), issuerEvidenceHash: recoveryEvidenceHash(s.issuerEvidence), envelopesHash: recoveredEnvelopesHash(s.envelopes) });
    s.recoverySignature = b64(ed25519.sign(recoveredEnrollmentBytes(e), keys.signingSeed));
    s.deviceSignature = b64(ed25519.sign(recoveredEnrollmentBytes(e), ed));
    return s;
}
export async function completeContinuous(h: Harness, allRevoked = false): Promise<{
    packet: RecoveryTransitionSubmission;
    sequence: number;
}> {
    await setupEnvironments(h);
    if (allRevoked) {
        await revoke(h, 'A');
        await revoke(h, 'C');
        await revoke(h, 'B');
    }
    await freshRecovery(h);
    assert.equal((await h.send(`/recovered-device-challenges?${cap}`, 'POST', { operationId: 'premature', deviceId: 'device-E', deviceSigningPublicKey: b64(ed25519.getPublicKey(Buffer.alloc(32, 6))), deviceReceivingPublicKey: b64(x25519.getPublicKey(Buffer.alloc(32, 10))) }, 'R')).status, 403);
    const c = await h.send(`/recovery-authority-challenges?${cap}`, 'POST', { operationId: 'continuous-1', authorizationKind: 'old-recovery', chainMode: 'continuous' }, 'R');
    assert.equal(c.status, 200, JSON.stringify(c.data));
    const packet = transitionPacket(h, c.data), response = await h.send(`/recovery-authority-transitions?${cap}`, 'POST', packet, 'R');
    assert.equal(response.status, 200, JSON.stringify(response.data));
    assert.equal(response.data.sequence, Number(c.data.expectedSequence) + 1);
    assert.equal(response.data.contentHash, transitionHash(packet));
    return { packet, sequence: response.data.sequence };
}
export async function completeRecovered(h: Harness, head: string): Promise<RecoveredDeviceSubmission> {
    const pub = b64(ed25519.getPublicKey(Buffer.alloc(32, 6))), x = b64(x25519.getPublicKey(Buffer.alloc(32, 10))), c = await h.send(`/recovered-device-challenges?${cap}`, 'POST', { operationId: 'recover-E', deviceId: 'device-E', deviceSigningPublicKey: pub, deviceReceivingPublicKey: x }, 'R');
    assert.equal(c.status, 200, JSON.stringify(c.data));
    const s = devicePacket(h, c.data, head);
    const response = await h.send(`/recovered-devices?${cap}`, 'POST', s, 'R');
    assert.equal(response.status, 200, JSON.stringify(response.data));
    assert.equal(response.data.sequence, Number(c.data.expectedSequence) + 1);
    assert.equal(response.data.contentHash, recoveredDeviceHash(s));
    const boot = await h.send('/boot-challenges', 'POST', { deviceId: 'device-E', accountGeneration: '1' }, 'login');
    assert.equal(boot.status, 200, JSON.stringify(boot.data));
    const session = await h.send('/boot-sessions', 'POST', { deviceId: 'device-E', accountGeneration: '1', challengeId: boot.data.challengeId, signature: sign(boot.data.signingPayload, Buffer.alloc(32, 6)) }, 'login');
    assert.equal(session.status, 200, JSON.stringify(session.data));
    h.setToken('E', session.data.token);
    return s;
}
for (const [runtime, create] of [['Node真实TCP', nodeHarness], ['workerd真实HTTP', workerHarness]] as const) {
    test(`${runtime} all设备撤销后连续双签轮换→受限→显式E登记→boot/proof3完整历史，原root不移动`, { timeout: 120000 }, async () => {
        const h = await create();
        try {
            const { packet, sequence } = await completeContinuous(h, true), retry = await h.send(`/recovery-authority-transitions?${cap}`, 'POST', packet, 'R');
            assert.equal(retry.status, 200, JSON.stringify(retry.data));
            assert.equal(retry.data.sequence, sequence);
            assert.equal(retry.data.replayed, true);
            const receipt = await h.send(`/recovery-authority-transitions/continuous-1?${cap}`, 'GET', undefined, 'R');
            assert.deepEqual(receipt.data, { operationId: 'continuous-1', accepted: true, sequence, contentHash: transitionHash(packet), transitionHash: transitionHash(packet) });
            const vault = await h.send(`/recovery-vault?${cap}&envelopeEvidence=recovery-envelope-v1`, 'GET', undefined, 'R');
            assert.equal(vault.status, 200, JSON.stringify(vault.data));
            assert.equal(vault.data.rotationRequired, false);
            assert.equal(vault.data.transitions.length, 1);
            assert.equal(vault.data.trustRoot.rootDeviceId, packet.newTrustRoot.rootDeviceId);
            assert.deepEqual(vault.data.environments, packet.envelopes);
            assert.equal((await h.send(`/pull?after=0&${cap}`, 'GET', undefined, 'R')).status, 401);
            assert.equal((await h.send('/pairings-v4', 'POST', {}, 'R')).status, 400);
            const device = await completeRecovered(h, transitionHash(packet)), pull = await h.send(`/pull?after=0&${cap}`, 'GET', undefined, 'E');
            assert.equal(pull.status, 200, JSON.stringify(pull.data));
            assert.equal(pull.data.issuerEvidence.profile, 'harmonia/issuer-proof/v3');
            const graph = verifyIssuerRecoveryGraph(pull.data.issuerEvidence);
            assert.equal(graph.identities.has('device-E'), true);
            assert.equal(graph.head.head, transitionHash(packet));
            assert.equal(graph.recovered.has(recoveredDeviceHash(device)), true);
            for (const event of pull.data.events)
                assert.ok(graph.authorities.has(issuerAuthorityHash(event.authorization)));
            assert.equal(pull.data.events.length, 2);
            assert.equal((await h.send(`/recovered-devices/recover-E?${cap}`, 'GET', undefined, 'R')).data.contentHash, recoveredDeviceHash(device));
            assert.equal((await h.send(`/recovered-devices?${cap}`, 'POST', device, 'R')).data.replayed, true);
            assert.equal((await h.send('/pull?after=0&capability=issuer-origin-v1', 'GET', undefined, 'E')).status, 403);
        }
        finally {
            await h.close();
        }
    });
    test(`${runtime} 当前ALL Admin双签过渡，新恢复会话不能跳过轮换登记且旧操作查询不扩权`, { timeout: 120000 }, async () => {
        const h = await create();
        try {
            await setupEnvironments(h);
            const c = await h.send(`/recovery-authority-challenges?${cap}`, 'POST', { operationId: 'continuous-1', authorizationKind: 'all-environments-admin', chainMode: 'continuous' }, 'B');
            assert.equal(c.status, 200, JSON.stringify(c.data));
            const packet = transitionPacket(h, c.data, 'all-environments-admin');
            const complete = await h.send(`/recovery-authority-transitions?${cap}`, 'POST', packet, 'B');
            assert.equal(complete.status, 200, JSON.stringify(complete.data));
            const challenge = await h.send('/recovery-challenges', 'POST', { accountGeneration: '1' }, 'login'), fields = challenge.data.signingPayload, recovery = await h.send('/recovery-sessions', 'POST', { accountGeneration: '1', challengeId: challenge.data.challengeId, signature: sign(fields, recoveryKeys(Buffer.alloc(32, 89), h.account.id, '2').signingSeed) }, 'login');
            assert.equal(recovery.status, 200);
            h.setToken('R', recovery.data.token);
            // fresh恢复仍要求显式轮换；此用已授权管理员过渡后的受限会话只用于查状态，不能跳过门槛登记。
            assert.equal((await h.send(`/recovered-device-challenges?${cap}`, 'POST', { operationId: 'recover-E', deviceId: 'device-E', deviceSigningPublicKey: b64(ed25519.getPublicKey(Buffer.alloc(32, 6))), deviceReceivingPublicKey: b64(x25519.getPublicKey(Buffer.alloc(32, 10))) }, 'R')).status, 403);
            assert.equal((await h.send(`/recovery-authority-transitions/continuous-1?${cap}`, 'GET', undefined, 'R')).data.accepted, true);
            assert.equal((await h.send(`/recovery-authority-transitions/continuous-1?${cap}`, 'GET', undefined, 'A')).status, 403);
        }
        finally {
            await h.close();
        }
    });
}
test('Node 双签nonce绑定/全清单缺项/新pub替换/期限/SQL失败拒绝，失败后原包可重试且旧账号代际失效', async () => {
    const h = await nodeHarness();
    try {
        await setupEnvironments(h);
        await freshRecovery(h);
        const c = await h.send(`/recovery-authority-challenges?${cap}`, 'POST', { operationId: 'continuous-1', authorizationKind: 'old-recovery', chainMode: 'continuous' }, 'R'), packet = transitionPacket(h, c.data), before = JSON.stringify(h.read());
        const replacement = structuredClone(packet);
        replacement.authorizationSignature = replacement.newRecoverySignature;
        assert.equal((await h.send(`/recovery-authority-transitions?${cap}`, 'POST', replacement, 'R')).status, 403);
        const incomplete = structuredClone(packet);
        incomplete.envelopes.pop();
        assert.equal((await h.send(`/recovery-authority-transitions?${cap}`, 'POST', incomplete, 'R')).status, 403);
        assert.equal(JSON.stringify(h.read()), before);
        const restore = h.failNextCommit!();
        try {
            assert.equal((await h.send(`/recovery-authority-transitions?${cap}`, 'POST', packet, 'R')).status, 500);
        }
        finally {
            restore();
        }
        assert.equal(JSON.stringify(h.read()), before);
        const ok = await h.send(`/recovery-authority-transitions?${cap}`, 'POST', packet, 'R');
        assert.equal(ok.status, 200, JSON.stringify(ok.data));
        const bad = structuredClone(packet);
        bad.newRecoverySignature = b64(Buffer.alloc(64, 9));
        assert.equal((await h.send(`/recovery-authority-transitions?${cap}`, 'POST', bad, 'R')).status, 409);
        const d = await completeRecovered(h, transitionHash(packet));
        const expired = structuredClone(d);
        expired.enrollment.operationId = 'other';
        assert.equal((await h.send(`/recovered-devices?${cap}`, 'POST', expired, 'R')).status, 403);
        h.change(a => { a.generation = '2'; a.sessions = []; a.devices = {}; a.environments = {}; a.grants = {}; a.events = []; a.recoverySigningPublicKey = null; a.recoveryReceivingPublicKey = null; delete a.trustRoot; a.vaultInitializations = {}; });
        assert.equal((await h.send(`/recovery-authority-transitions/continuous-1?${cap}`, 'GET', undefined, 'R')).status, 401);
    }
    finally {
        await h.close();
    }
});
async function approveF(h: Harness, key: string): Promise<EnrollmentApprovalV4> {
    const pub = b64(ed25519.getPublicKey(Buffer.alloc(32, 7))), x = b64(x25519.getPublicKey(Buffer.alloc(32, 24))), begin = await h.send('/pairings-v4', 'POST', { idempotencyKey: key, deviceId: 'device-F', signingPublicKey: pub, receivingPublicKey: x, approverDeviceId: 'device-E', certificateVersion: '4', capabilities: ['issuer-recovery-v1'] }, 'login');
    assert.equal(begin.status, 200, JSON.stringify(begin.data));
    assert.equal(begin.data.certificateVersion, '4');
    assert.deepEqual(begin.data.capabilities, ['issuer-recovery-v1']);
    const c = begin.data.context;
    for (const [side, kind, value, who] of [['initiator', 'message', 71, 'login'], ['approver', 'message', 72, 'E'], ['initiator', 'confirmation', 73, 'login'], ['approver', 'confirmation', 74, 'E']] as const) {
        const relay = { side, kind, payload: b64(Buffer.alloc(32, value)) };
        const response = await h.send(`/pairings-v4/${key}/relay`, 'POST', { ...relay, signature: sign(relayFields({ context: c } as any, relay), Buffer.alloc(32, side === 'initiator' ? 7 : 6)) }, who);
        assert.equal(response.status, 200, JSON.stringify(response.data));
    }
    const status = await h.send(`/pairings-v4/${key}`, 'GET', undefined, 'login'), pull = await h.send(`/pull?after=0&${cap}`, 'GET', undefined, 'E');
    assert.equal(pull.status, 200, JSON.stringify(pull.data));
    const proof = pull.data.issuerEvidence;
    proof.targets = proof.targets.filter((target: any) => target.environmentId === 'environment-Y');
    const grant = { accountId: h.account.id, accountGeneration: '1', issuerDeviceId: 'device-E', subjectDeviceId: 'device-F', subjectSigningPublicKey: pub, subjectReceivingPublicKey: x, environmentId: 'environment-Y', keyVersion: '1', grantGeneration: '1', role: 'ro' as const, expiresAt: '0', idempotencyKey: 'E-approve-F', envelope: b64(Buffer.alloc(80, 37)) }, signed = { grant, signature: b64(ed25519.sign(grantBytes(grant), Buffer.alloc(32, 6))) };
    const certificate: EnrollmentApprovalV4 = { certificateVersion: '4', capabilities: ['issuer-recovery-v1'], context: c, pairingProfile, transcriptHash: hash(['harmonia/pairing-transcript/v1', b64(canonical(pairingContextFields(c))), status.data.messages.initiator, status.data.messages.approver]), grants: [signed], issuerProof: proof, approverSignature: '' };
    certificate.approverSignature = sign(enrollmentV4Fields(certificate), Buffer.alloc(32, 6));
    const b = { certificateVersion: '4', capabilities: ['issuer-recovery-v1'], grants: certificate.grants, transcriptHash: certificate.transcriptHash, issuerProof: certificate.issuerProof, signature: certificate.approverSignature };
    assert.equal((await h.send(`/pairings-v4/${key}/approve`, 'POST', { ...b, capabilities: ['issuer-origin-v1'] }, 'E')).status, 400);
    const accepted = await h.send(`/pairings-v4/${key}/approve`, 'POST', b, 'E');
    assert.equal(accepted.status, 200, JSON.stringify(accepted.data));
    assert.deepEqual(accepted.data.approval.capabilities, ['issuer-recovery-v1']);
    return certificate;
}
for (const [runtime, create] of [['Node真实TCP', nodeHarness], ['workerd真实HTTP', workerHarness]] as const) {
    test(`${runtime} 恢复E Admin批准F RO：v4双方签、归档、boot与proof3只读Y且不泄X业务密文`, { timeout: 120000 }, async () => {
        const h = await create();
        try {
            const { packet } = await completeContinuous(h, true);
            await completeRecovered(h, transitionHash(packet));
            const certificate = await approveF(h, 'E-pair-F'), signature = sign(enrollmentV4Fields(certificate), Buffer.alloc(32, 7));
            const response = await h.send('/pairings-v4/E-pair-F/complete', 'POST', { signature }, 'login');
            assert.equal(response.status, 200, JSON.stringify(response.data));
            assert.equal(response.data.approval.initiatorSignature, signature);
            assert.equal((await h.send('/pairings-v4/E-pair-F/complete', 'POST', { signature }, 'login')).data.replayed, true);
            const boot = await h.send('/boot-challenges', 'POST', { deviceId: 'device-F', accountGeneration: '1' }, 'login'), session = await h.send('/boot-sessions', 'POST', { deviceId: 'device-F', accountGeneration: '1', challengeId: boot.data.challengeId, signature: sign(boot.data.signingPayload, Buffer.alloc(32, 7)) }, 'login');
            assert.equal(session.status, 200, JSON.stringify(session.data));
            h.setToken('F', session.data.token);
            const pull = await h.send(`/pull?after=0&${cap}`, 'GET', undefined, 'F');
            assert.equal(pull.status, 200, JSON.stringify(pull.data));
            const graph = verifyIssuerRecoveryGraph(pull.data.issuerEvidence);
            assert.equal(graph.identities.has('device-F'), true);
            assert.equal(graph.identities.has('device-C'), true);
            assert.deepEqual(pull.data.events.map((event: any) => event.mutation.mutation.environmentId), ['environment-Y']);
            assert.deepEqual(pull.data.grants.map((g: any) => g.grant.role), ['ro']);
            for (const event of pull.data.events)
                assert.ok(graph.authorities.has(issuerAuthorityHash(event.authorization)));
            assert.equal(pull.data.environmentEvents.every((e: any) => e.change.change.environmentId === 'environment-Y'), true);
            const mutation = { accountId: h.account.id, accountGeneration: '1', deviceId: 'device-F', environmentId: 'environment-Y', keyVersion: '1', grantGeneration: '1', operation: 'put' as const, idempotencyKey: 'F-denied-write', name: 'NO_WRITE', payload: b64(Buffer.alloc(40, 40)) };
            assert.equal((await h.send('/mutations', 'POST', { mutation, signature: b64(ed25519.sign(mutationBytes(mutation), Buffer.alloc(32, 7))) }, 'F')).status, 403);
        }
        finally {
            await h.close();
        }
    });
    test(`${runtime} v4批准后E丢Admin，complete逐次重查并原子拒绝，不以历史证书替代当前权`, { timeout: 120000 }, async () => {
        const h = await create();
        try {
            const { packet } = await completeContinuous(h, true), e = await completeRecovered(h, transitionHash(packet)), certificate = await approveF(h, 'E-F-revoked');
            const g = structuredClone(e.grants.find(g => g.grant.environmentId === 'environment-Y')!.grant);
            Object.assign(g, { grantGeneration: '2', role: 'none', idempotencyKey: 'E-Y-none', envelope: '' });
            const changed = await h.send('/grants', 'POST', { grant: g, signature: b64(ed25519.sign(grantBytes(g), Buffer.alloc(32, 6))) }, 'E');
            assert.equal(changed.status, 200, JSON.stringify(changed.data));
            const complete = await h.send('/pairings-v4/E-F-revoked/complete', 'POST', { signature: sign(enrollmentV4Fields(certificate), Buffer.alloc(32, 7)) }, 'login');
            assert.equal(complete.status, 403);
            assert.equal((await h.send('/boot-challenges', 'POST', { deviceId: 'device-F', accountGeneration: '1' }, 'login')).status, 403);
            const refresh = await h.send(`/pull?after=0&scope=authorizations&${cap}`, 'GET', undefined, 'E');
            assert.equal(refresh.status, 200, JSON.stringify(refresh.data));
            assert.deepEqual(refresh.data.events, []);
            verifyIssuerRecoveryGraph(refresh.data.issuerEvidence);
        }
        finally {
            await h.close();
        }
    });
}
import { nodeStore } from "../src/node-store.js";
import { RecoveryAuthorityService } from "../src/recovery-authority.js";
import { rotationPayload, fullEnvelopes, rotationTrustHash, type RotationRecord } from "../src/lifecycle-wire.js";
test('真实SQLite受控时钟：单次nonce到期、公钥复用及缺归档拒绝，仍无新设备权限', async () => {
    const h = await nodeHarness();
    const db = nodeStore(':memory:');
    try {
        await setupEnvironments(h);
        const rec = await freshRecovery(h);
        db.store.create(h.read());
        let clock = Math.floor(Date.now() / 1000);
        const service = new RecoveryAuthorityService(db.store, () => clock), auth = { token: rec.token, accountGeneration: '1' };
        const challenge = await service.challenge(h.account.id, auth, { operationId: 'continuous-1', authorizationKind: 'old-recovery', chainMode: 'continuous' }), packet = transitionPacket(h, challenge);
        clock += 121;
        await assert.rejects(service.transition(h.account.id, auth, packet), /challenge_invalid/);
        assert.equal(db.store.read(h.account.id)!.recoveryGeneration, '1');
        assert.deepEqual(await service.transitionStatus(h.account.id, auth, 'continuous-1'), { operationId: 'continuous-1', accepted: false });
        clock -= 121;
        const reused = structuredClone(packet);
        reused.transition.newRecoverySigningPublicKey = packet.transition.oldRecoverySigningPublicKey;
        assert.throws(() => transitionBytes(reused.transition));
        await service.transition(h.account.id, auth, packet);
        const context = await service.recoveredChallenge(h.account.id, auth, { operationId: 'recover-E', deviceId: 'device-E', deviceSigningPublicKey: b64(ed25519.getPublicKey(Buffer.alloc(32, 6))), deviceReceivingPublicKey: b64(x25519.getPublicKey(Buffer.alloc(32, 10))) }), device = devicePacket(h, context, transitionHash(packet));
        clock += 121;
        await assert.rejects(service.recoverDevice(h.account.id, auth, device), /challenge_invalid/);
        assert.equal(db.store.read(h.account.id)!.devices['device-E'], undefined);
        clock -= 121;
        const original = JSON.stringify(db.store.read(h.account.id));
        db.store.transaction(h.account.id, a => { delete (a as any).deviceEnrollments['device-C']; });
        await assert.rejects(service.recoverDevice(h.account.id, auth, device), /issuer_archive_mismatch/);
        assert.equal(db.store.read(h.account.id)!.devices['device-E'], undefined);
    }
    finally {
        db.sql.close();
        await h.close();
    }
});
for (const [runtime, create] of [['Node真实TCP', nodeHarness], ['workerd真实HTTP', workerHarness]] as const) {
    test(`${runtime} v1新钥单签造成断链：旧码路径拒绝，只有当前全部环境Admin显式双签reanchor`, { timeout: 120000 }, async () => {
        const h = await create();
        try {
            await setupEnvironments(h);
            await freshRecovery(h);
            const keys = recoveryKeys(Buffer.alloc(32, 89), h.account.id, '2'), old = h.read().trustRoot!, root = { ...old, recoveryGeneration: '2', recoverySigningPublicKey: keys.signingPublicKey, recoveryReceivingPublicKey: keys.receivingPublicKey, signature: '' };
            root.signature = sign(trustRootPayload(h.account.id, '1', root), keys.signingSeed);
            const snapshot = await h.send('/recovery-vault?capability=issuer-origin-v1', 'GET', undefined, 'R'), proposal = { idempotencyKey: 'legacy-v1-gap', newRecoveryGeneration: '2', newRecoverySigningPublicKey: keys.signingPublicKey, newRecoveryReceivingPublicKey: keys.receivingPublicKey, newTrustRoot: root, envelopes: snapshot.data.environments.map((e: any) => ({ ...e, envelope: b64(Buffer.alloc(80, 47)) })) };
            const pending = await h.send('/recovery-rotations', 'POST', proposal, 'R');
            assert.equal(pending.status, 200, JSON.stringify(pending.data));
            const complete = await h.send('/recovery-rotations/legacy-v1-gap/complete', 'POST', { challengeId: pending.data.challengeId, signature: sign(pending.data.signingPayload, keys.signingSeed) }, 'R');
            assert.equal(complete.status, 200, JSON.stringify(complete.data));
            assert.equal((await h.send(`/recovery-authority-challenges?${cap}`, 'POST', { operationId: 'old-cannot-escape', authorizationKind: 'old-recovery', chainMode: 'continuous' }, 'R')).data.error, 'recovery_chain_invalid');
            assert.equal((await h.send(`/recovery-vault?${cap}&envelopeEvidence=recovery-envelope-v1`, 'GET', undefined, 'R')).data.error, 'recovery_chain_invalid');
            const manager = await h.send(`/recovery-authority-challenges?${cap}`, 'POST', { operationId: 'continuous-1', authorizationKind: 'all-environments-admin', chainMode: 'manager-reanchor' }, 'B');
            assert.equal(manager.status, 200, JSON.stringify(manager.data));
            assert.equal(manager.data.legacyState.rotations.length, 1);
            const packet = transitionPacket(h, manager.data, 'all-environments-admin'), response = await h.send(`/recovery-authority-transitions?${cap}`, 'POST', packet, 'B');
            assert.equal(response.status, 200, JSON.stringify(response.data));
            assert.equal(packet.transition.newRecoveryGeneration, '3');
            assert.equal((await h.send(`/recovery-authority-transitions/continuous-1?${cap}`, 'GET', undefined, 'B')).data.contentHash, transitionHash(packet));
        }
        finally {
            await h.close();
        }
    });
}
for (const [runtime, create] of [['Node真实TCP', nodeHarness], ['workerd真实HTTP', workerHarness]] as const) {
    test(`${runtime} 新恢复POST严格2MiB外围、旧入口100k保持，unknown字段不写状态`, { timeout: 120000 }, async () => {
        const h = await create();
        try {
            const large = { padding: 'x'.repeat(150000) };
            assert.equal((await h.send(`/recovery-authority-transitions?${cap}`, 'POST', large, 'login')).status, 400);
            assert.equal((await h.send(`/recovered-devices?${cap}`, 'POST', large, 'login')).status, 400);
            assert.equal((await h.send('/grants', 'POST', large, 'B')).status, 413);
            assert.equal((await h.send(`/recovery-authority-transitions?${cap}`, 'POST', { padding: 'x'.repeat(2 * 1024 * 1024) }, 'login')).status, 413);
            assert.equal((await h.send(`/recovery-authority-challenges?${cap}&extra=1`, 'POST', { operationId: 'x', authorizationKind: 'old-recovery', chainMode: 'continuous' }, 'login')).status, 400);
            assert.equal((await h.send('/recovery-authority-challenges', 'POST', { operationId: 'x', authorizationKind: 'old-recovery', chainMode: 'continuous' }, 'login')).status, 400);
        }
        finally {
            await h.close();
        }
    });
}
