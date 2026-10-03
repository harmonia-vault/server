// 独立产品回归的公开合成输入；不导入会注册测试的 test.ts 文件。
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
