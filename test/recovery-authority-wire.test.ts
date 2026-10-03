import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ed25519 } from "@noble/curves/ed25519.js";
import { verify } from "../src/protocol.js";
import { initializationReference, submissionReferences, transitionBytes, transitionHash } from "../src/recovery-authority-wire.js";
import { recoveryAuthorityHead, verifyTransitionAuthorization } from "../src/recovery-authority-history.js";
import { recoveredDeviceHash, recoveredEnrollmentBytes, recoveredSubmissionReferences } from "../src/recovered-device-wire.js";
import { strictRecoveryJson } from "../src/strict-recovery-body.js";
const v = JSON.parse(readFileSync(new URL('./vectors/recovery-authority-v1.json', import.meta.url), 'utf8'));
test('Go静态原初始化/25域连续恢复/ALL Admin重连与18域恢复设备：Node独立Ed25519和摘要逐字互通', () => {
    assert.equal(initializationReference(v.originalInitialization), v.initializationHash);
    for (const [field, bytesField, hashField] of [['oldRecoveryTransition', 'transitionSigningHex', 'transitionHash'], ['allAdminTransition', 'allAdminSigningHex', 'allAdminHash'], ['managerReanchor', 'reanchorSigningHex', 'reanchorHash']]) {
        const s = v[field!].submission;
        submissionReferences(s);
        assert.equal(Buffer.from(transitionBytes(s.transition)).toString('hex'), v[bytesField!]);
        assert.equal(transitionHash(s), v[hashField!]);
        verifyTransitionAuthorization(v.originalInitialization, s);
    }
    const head = recoveryAuthorityHead(v.originalInitialization, [v.oldRecoveryTransition]);
    assert.equal(head.head, v.transitionHash);
    assert.equal(head.generation, '2');
    assert.equal(recoveryAuthorityHead(v.originalInitialization, [v.managerReanchor]).head, v.reanchorHash);
    const s = v.recoveredDevice.submission;
    recoveredSubmissionReferences(s);
    assert.equal(Buffer.from(recoveredEnrollmentBytes(s.enrollment)).toString('hex'), v.deviceSigningHex);
    assert.equal(recoveredDeviceHash(s), v.deviceHash);
    verify(head.signing, recoveredEnrollmentBytes(s.enrollment), s.recoverySignature);
    verify(s.enrollment.deviceSigningPublicKey, recoveredEnrollmentBytes(s.enrollment), s.deviceSignature);
});
test('连续恢复不能仅新钥签、自报根/genesis、重用旧钥、重复已见操作或改18域选择', () => {
    for (const key of Object.keys(v.oldRecoveryTransition.submission.transition)) {
        const bad = structuredClone(v.oldRecoveryTransition);
        bad.submission.transition[key] += 'x';
        assert.throws(() => recoveryAuthorityHead(v.originalInitialization, [bad]));
    }
    const onlyNew = structuredClone(v.oldRecoveryTransition);
    onlyNew.submission.authorizationSignature = onlyNew.submission.newRecoverySignature;
    assert.throws(() => recoveryAuthorityHead(v.originalInitialization, [onlyNew]));
    assert.throws(() => recoveryAuthorityHead(v.originalInitialization, [v.oldRecoveryTransition, v.oldRecoveryTransition]));
    const fake = structuredClone(v.originalInitialization);
    fake.proposal.environments[0].recoveryEnvelope = 'AA';
    assert.throws(() => recoveryAuthorityHead(fake, []));
    const changed = structuredClone(v.recoveredDevice.submission);
    changed.selectedRights[0].role = 'rw';
    assert.throws(() => recoveredSubmissionReferences(changed));
});
test('新恢复JSON入口拒绝顶层/嵌套/转义重复成员、非法UTF8、尾随数据与深度，标准数组/空串保留', () => {
    for (const text of ['{"a":1,"a":2}', '{"a":{"b":1,"b":2}}', '{"a":1,"\\u0061":2}', '{}{}', '{"x":' + '['.repeat(66) + '0' + ']'.repeat(66) + '}'])
        assert.throws(() => strictRecoveryJson(Buffer.from(text)));
    assert.throws(() => strictRecoveryJson(Uint8Array.from([123, 34, 120, 34, 58, 34, 255, 34, 125])));
    assert.deepEqual(strictRecoveryJson(Buffer.from('{"x":[{},[],null,"",true,12]}')), { x: [{}, [], null, '', true, 12] });
    assert.throws(() => strictRecoveryJson(Buffer.alloc(2 * 1024 * 1024 + 1)));
});
import { issuerRecoveryCanonical, issuerRecoveryHash, verifyIssuerRecoveryGraph } from "../src/issuer-recovery.js";
const pv = JSON.parse(readFileSync(new URL('./vectors/issuer-recovery-v1.json', import.meta.url), 'utf8'));
test('Go proof3规范12项、真实恢复双签归档和恢复Admin批准v4：Node完整来源图互通', () => {
    assert.equal(Buffer.from(issuerRecoveryCanonical(pv.proof)).toString('hex'), pv.canonicalHex);
    assert.equal(issuerRecoveryHash(pv.proof), pv.hash);
    const graph = verifyIssuerRecoveryGraph(pv.proof);
    assert.equal(graph.identities.has('recovered-E'), true);
    assert.equal(graph.identities.size >= 3, true);
    for (const key of ['transitions', 'recoveredDevices', 'initialization', 'path', 'authorities']) {
        const bad = structuredClone(pv.proof);
        if (Array.isArray(bad[key]))
            bad[key] = [];
        else
            bad[key].deviceSignature = 'AA';
        assert.throws(() => verifyIssuerRecoveryGraph(bad));
    }
});
