import { Fault, grantKey, type SignedGrant } from "./model.js";
import { bytes, generation, grantBytes, identifier, mutationBytes, verify } from "./protocol.js";
import { canonical, enrollmentFields, exact, hash, own, type EnrollmentCertificate, type PairingContext } from "./enrollment-wire.js";
import { issuerAuthorityHash } from "./issuer-proof.js";
import { issuerOriginNodeFields, archivedOriginEnrollment, type IssuerOriginEnrollment } from "./issuer-origin.js";
import { environmentOriginBytes, environmentOriginHash, environmentRights, rightsFields, environmentChangeHash } from "./environment-origin.js";
import type { SignedEnvironmentOrigin } from "./environment-origin.js";
import { environmentChangeBytes } from "./environments.js";
import { trustRootPayload, validateTrustRoot, type TrustRoot } from "./trust-root.js";
import { originalInitialization, type OriginalInitialization } from "./initialization-evidence.js";
import { initializationReference, transitionBytes, transitionHash, type AcceptedRecoveryTransition } from "./recovery-authority-wire.js";
import { recoveryAuthorityHead, verifyRecoverySource, type RecoveryAuthorityHead } from "./recovery-authority-history.js";
import { recoveredDeviceHash, recoveredEnrollmentBytes, recoveredSubmissionReferences, type AcceptedRecoveredDevice } from "./recovered-device-wire.js";
import type { RecoveryAuthorityAccount } from "./recovery-authority.js";
export const issuerRecoveryProfile = "harmonia/issuer-proof/v3";
export interface RecoveryPairedEnrollment extends Omit<IssuerOriginEnrollment, "certificateVersion"> {
    certificateVersion: "1" | "2" | "3" | "4";
}
export type IssuerRecoveryArchive = {
    kind: "paired";
    enrollment: RecoveryPairedEnrollment;
} | {
    kind: "recovered";
    recoveryEnrollmentHash: string;
};
export interface IssuerRecoveryAuthority {
    grant: SignedGrant;
    parentHash: string;
    originHash: string;
    previousGrantHash: string;
    recoveryEnrollmentHash: string;
}
export interface IssuerRecoveryProof {
    profile: "harmonia/issuer-proof/v3";
    accountId: string;
    accountGeneration: string;
    trustRoot: TrustRoot;
    initialization: OriginalInitialization;
    path: IssuerRecoveryArchive[];
    authorities: IssuerRecoveryAuthority[];
    targets: {
        environmentId: string;
        authorityHash: string;
    }[];
    origins: SignedEnvironmentOrigin[];
    identityPaths: IssuerRecoveryArchive[][];
    transitions: AcceptedRecoveryTransition[];
    recoveredDevices: AcceptedRecoveredDevice[];
}
export interface EnrollmentApprovalV4 extends EnrollmentCertificate {
    certificateVersion: "4";
    capabilities: [
        "issuer-recovery-v1"
    ];
    issuerProof: IssuerRecoveryProof;
}
interface Identity {
    id: string;
    signing: string;
    receiving: string;
    archive?: string;
}
interface VerifiedRecoveryGraph {
    authorities: Map<string, IssuerRecoveryAuthority>;
    identities: Map<string, Identity>;
    origins: Map<string, SignedEnvironmentOrigin>;
    head: RecoveryAuthorityHead;
    recovered: Map<string, AcceptedRecoveredDevice>;
}
function fail(code = "issuer_recovery_invalid"): never { throw new Fault(403, code); }
const b64 = (v: Uint8Array): string => Buffer.from(v).toString("base64url");
const compare = (a: string, b: string): number => a < b ? -1 : a > b ? 1 : 0;
function within(c: string, p: string): boolean { for (const v of [c, p]) {
    if (v !== "0")
        generation(v);
    if (BigInt(v) > 253402300799n)
        fail();
} return p === "0" || c !== "0" && BigInt(c) <= BigInt(p); }
function hex(h: string): void { if (typeof h !== "string" || !/^[0-9a-f]{64}$/.test(h))
    fail(); }
export function recoveryNodeFields(node: RecoveryPairedEnrollment): string[] {
    if (node.certificateVersion !== "4")
        return issuerOriginNodeFields(node as IssuerOriginEnrollment);
    exact(node, ["certificateVersion", "issuerProofHash", "approval"]);
    hex(node.issuerProofHash);
    exact(node.approval, ["context", "pairingProfile", "transcriptHash", "grants", "approverSignature", "initiatorSignature"]);
    const c = node.approval.context;
    exact(c, ["accountId", "accountGeneration", "purpose", "sessionId", "challengeNonce", "expiresAt", "initiatorDeviceId", "initiatorSigningPublicKey", "initiatorReceivingPublicKey", "approverDeviceId", "approverSigningPublicKey", "approverReceivingPublicKey"]);
    for (const id of [c.accountId, c.sessionId, c.initiatorDeviceId, c.approverDeviceId])
        identifier(id);
    generation(c.accountGeneration);
    generation(c.expiresAt);
    bytes(c.challengeNonce, 32);
    for (const key of [c.initiatorSigningPublicKey, c.initiatorReceivingPublicKey, c.approverSigningPublicKey, c.approverReceivingPublicKey])
        bytes(key, 32);
    if (c.purpose !== "enroll-device" || c.initiatorDeviceId === c.approverDeviceId || c.initiatorSigningPublicKey === c.initiatorReceivingPublicKey || c.approverSigningPublicKey === c.approverReceivingPublicKey || BigInt(c.expiresAt) > 253402300799n)
        fail();
    bytes(node.approval.approverSignature, 64);
    bytes(node.approval.initiatorSignature!, 64);
    const fields = enrollmentFields(node.approval);
    fields[0] = "harmonia/device-enrollment/v4";
    fields.push(node.issuerProofHash);
    return fields;
}
function pathRows(path: IssuerRecoveryArchive[]): string[][] {
    if (!Array.isArray(path) || path.length > 32)
        fail();
    return path.map((n, i) => {
        if (n.kind === "paired") {
            exact(n, ["kind", "enrollment"]);
            return ["paired", n.enrollment.certificateVersion, b64(canonical(recoveryNodeFields(n.enrollment))), n.enrollment.approval.approverSignature, n.enrollment.approval.initiatorSignature!];
        }
        if (n.kind !== "recovered" || i !== 0)
            fail();
        exact(n, ["kind", "recoveryEnrollmentHash"]);
        hex(n.recoveryEnrollmentHash);
        return ["recovered", n.recoveryEnrollmentHash];
    });
}
export function issuerRecoveryCanonical(p: IssuerRecoveryProof): Uint8Array {
    exact(p, ["profile", "accountId", "accountGeneration", "trustRoot", "initialization", "path", "authorities", "targets", "origins", "identityPaths", "transitions", "recoveredDevices"]);
    identifier(p.accountId);
    generation(p.accountGeneration);
    if (p.profile !== issuerRecoveryProfile || !Array.isArray(p.authorities) || !p.authorities.length || p.authorities.length > 1024 || !Array.isArray(p.targets) || p.targets.length > 256 || !Array.isArray(p.origins) || p.origins.length > 128 || !Array.isArray(p.identityPaths) || p.identityPaths.length > 32 || !Array.isArray(p.transitions) || p.transitions.length > 128 || !Array.isArray(p.recoveredDevices) || p.recoveredDevices.length > 128)
        fail();
    validateTrustRoot(p.accountId, p.accountGeneration, p.trustRoot);
    const main = pathRows(p.path), branches = p.identityPaths.map(pathRows).sort((a, b) => compare(JSON.stringify(a), JSON.stringify(b)));
    if (p.path.length + p.identityPaths.reduce((n, p) => n + p.length, 0) > 256)
        fail();
    for (let i = 0; i < branches.length; i++)
        if (!branches[i]!.length || i && JSON.stringify(branches[i]) === JSON.stringify(branches[i - 1]))
            fail();
    const ids = new Set<string>(), authorities = [...p.authorities].map(a => { exact(a, ["grant", "parentHash", "originHash", "previousGrantHash", "recoveryEnrollmentHash"]); issuerAuthorityHash(a.grant); if (a.grant.grant.role === 'none')
        fail(); for (const h of [a.parentHash, a.originHash, a.previousGrantHash, a.recoveryEnrollmentHash])
        if (h)
            hex(h); return a; }).sort((a, b) => compare(a.grant.grant.environmentId, b.grant.grant.environmentId) || compare(a.grant.grant.subjectDeviceId, b.grant.grant.subjectDeviceId) || (BigInt(a.grant.grant.grantGeneration) < BigInt(b.grant.grant.grantGeneration) ? -1 : BigInt(a.grant.grant.grantGeneration) > BigInt(b.grant.grant.grantGeneration) ? 1 : 0)).map(a => { const g = a.grant.grant, id = `${g.environmentId}/${g.subjectDeviceId}/${g.grantGeneration}`; if (ids.has(id))
        fail(); ids.add(id); return [g.environmentId, g.subjectDeviceId, g.grantGeneration, b64(grantBytes(g)), a.grant.signature, a.parentHash, a.originHash, a.previousGrantHash, a.recoveryEnrollmentHash]; });
    const targetIds = new Set<string>(), targets = [...p.targets].sort((a, b) => compare(a.environmentId, b.environmentId)).map(t => { exact(t, ["environmentId", "authorityHash"]); identifier(t.environmentId); hex(t.authorityHash); if (targetIds.has(t.environmentId))
        fail(); targetIds.add(t.environmentId); return [t.environmentId, t.authorityHash]; });
    function unique(rows: string[][]): string[][] { rows.sort((a, b) => compare(a[0]!, b[0]!)); for (let i = 1; i < rows.length; i++)
        if (rows[i]![0] === rows[i - 1]![0])
            fail(); return rows; }
    const origins = unique(p.origins.map(o => [environmentOriginHash(o), b64(environmentOriginBytes(o.origin)), o.signature]));
    const init = p.initialization, ih = initializationReference(init), pp = init.proposal, c = init.proof;
    const proposal = canonical(["harmonia/vault-initialization-proposal/v1", pp.idempotencyKey, pp.device.id, pp.device.signingPublicKey, pp.device.receivingPublicKey, pp.recoveryGeneration, pp.recoverySigningPublicKey, pp.recoveryReceivingPublicKey, pp.trustRootSignature, [...pp.environments].sort((a, b) => compare(a.environmentId, b.environmentId)).map(e => [e.environmentId, e.keyVersion, e.recoveryEnvelope, b64(grantBytes(e.grant.grant)), e.grant.signature])]);
    const proof = canonical(["harmonia/vault-initialize/v1", c.accountId, c.accountGeneration, c.loginTokenHash, c.challengeId, c.nonce, c.expiresAt, c.proposalHash]);
    const transitions = unique(p.transitions.map(r => { exact(r, ["submission", "sequence"]); if (!Number.isSafeInteger(r.sequence) || r.sequence < 2)
        fail(); return [transitionHash(r.submission), b64(transitionBytes(r.submission.transition)), r.submission.authorizationSignature, r.submission.newRecoverySignature, String(r.sequence)]; }));
    const recovered = unique(p.recoveredDevices.map(r => { exact(r, ["submission", "sequence"]); if (!Number.isSafeInteger(r.sequence) || r.sequence < 2)
        fail(); return [recoveredDeviceHash(r.submission), b64(recoveredEnrollmentBytes(r.submission.enrollment)), r.submission.recoverySignature, r.submission.deviceSignature, String(r.sequence)]; }));
    const out = canonical([p.profile, p.accountId, p.accountGeneration, [b64(canonical(trustRootPayload(p.accountId, p.accountGeneration, p.trustRoot))), p.trustRoot.signature], [ih, b64(proposal), b64(proof), init.deviceSignature, init.recoverySignature, "1"], main, authorities, targets, origins, branches, transitions, recovered]);
    if (out.length > 2 * 1024 * 1024 || Buffer.byteLength(JSON.stringify(p)) > 2 * 1024 * 1024)
        throw new Fault(413, "body_too_large");
    return out;
}
export const issuerRecoveryHash = (p: IssuerRecoveryProof): string => hash(JSON.parse(Buffer.from(issuerRecoveryCanonical(p)).toString("utf8")));
function verifyRecovered(original: OriginalInitialization, record: AcceptedRecoveredDevice, head: RecoveryAuthorityHead): void {
    const s = record.submission, e = s.enrollment;
    recoveredSubmissionReferences(s);
    if (e.accountId !== original.proof.accountId || e.accountGeneration !== original.proof.accountGeneration || e.recoveryGeneration !== head.generation || e.recoveryTransitionHash !== head.head || record.sequence !== Number(e.expectedSequence) + 1 || Number(e.expectedSequence) < head.sequence || head.operations.size === 0 || [e.deviceSigningPublicKey, e.deviceReceivingPublicKey].some(key => head.seenKeys.has(key)))
        fail();
    const root = s.issuerEvidence.trustRoot;
    if (root.recoveryGeneration !== head.generation || root.recoverySigningPublicKey !== head.signing || root.recoveryReceivingPublicKey !== head.receiving)
        fail();
    const graph = verifyRecoverySource(original, s.issuerEvidence);
    for (const row of s.selectedRights) {
        const target = s.issuerEvidence.targets.find(target => target.environmentId === row.environmentId), source = target && graph.authorities.get(target.authorityHash)?.grant.grant;
        if (!source || source.environmentId !== row.environmentId || source.keyVersion !== row.keyVersion)
            fail();
    }
    if (graph.identities.has(e.deviceId) || [...graph.identities.values()].some(id => [id.signing, id.receiving].some(key => key === e.deviceSigningPublicKey || key === e.deviceReceivingPublicKey)))
        fail();
    verify(head.signing, recoveredEnrollmentBytes(e), s.recoverySignature);
    verify(e.deviceSigningPublicKey, recoveredEnrollmentBytes(e), s.deviceSignature);
}
export function verifyIssuerRecoveryGraph(proof: IssuerRecoveryProof): VerifiedRecoveryGraph {
    issuerRecoveryCanonical(proof);
    const initial = proof.initialization;
    if (initial.proof.accountId !== proof.accountId || initial.proof.accountGeneration !== proof.accountGeneration)
        fail();
    const root: Identity = { id: initial.proposal.device.id, signing: initial.proposal.device.signingPublicKey, receiving: initial.proposal.device.receivingPublicKey };
    const records = [...proof.transitions].sort((a, b) => a.sequence - b.sequence), heads = new Map<string, RecoveryAuthorityHead>();
    let head = recoveryAuthorityHead(initial, []);
    heads.set(head.head, head);
    for (let i = 0; i < records.length; i++) {
        head = recoveryAuthorityHead(initial, records.slice(0, i + 1));
        heads.set(head.head, head);
    }
    const r = proof.trustRoot;
    if (r.rootDeviceId !== root.id || r.rootSigningPublicKey !== root.signing || r.rootReceivingPublicKey !== root.receiving || r.recoveryGeneration !== head.generation || r.recoverySigningPublicKey !== head.signing || r.recoveryReceivingPublicKey !== head.receiving)
        fail();
    const recovered = new Map<string, AcceptedRecoveredDevice>();
    for (const record of proof.recoveredDevices) {
        const h = recoveredDeviceHash(record.submission), source = heads.get(record.submission.enrollment.recoveryTransitionHash);
        if (!source || recovered.has(h))
            fail();
        verifyRecovered(initial, record, source);
        recovered.set(h, record);
    }
    const genesis = new Set(initial.proposal.environments.map(e => issuerAuthorityHash(e.grant))), identities = new Map<string, Identity>([[root.id, root]]), usedKeys = new Map<string, string>([[root.signing, root.id], [root.receiving, root.id]]);
    for (const key of head.seenKeys)
        if (key !== root.signing && key !== root.receiving)
            usedKeys.set(key, "recovery");
    function add(child: Identity): void { const prior = identities.get(child.id); if (prior && (prior.signing !== child.signing || prior.receiving !== child.receiving || prior.archive !== child.archive))
        fail(); for (const key of [child.signing, child.receiving])
        if (usedKeys.has(key) && usedKeys.get(key) !== child.id)
            fail(); if (child.signing === child.receiving)
        fail(); identities.set(child.id, child); usedKeys.set(child.signing, child.id); usedKeys.set(child.receiving, child.id); }
    function walk(path: IssuerRecoveryArchive[]): void {
        let current = root;
        const ids = new Set([root.id]);
        for (let i = 0; i < path.length; i++) {
            const node = path[i]!;
            if (node.kind === "recovered") {
                const record = recovered.get(node.recoveryEnrollmentHash);
                if (i !== 0 || !record)
                    fail();
                const e = record.submission.enrollment;
                if (ids.has(e.deviceId))
                    fail();
                const child: Identity = { id: e.deviceId, signing: e.deviceSigningPublicKey, receiving: e.deviceReceivingPublicKey, archive: node.recoveryEnrollmentHash };
                add(child);
                ids.add(child.id);
                current = child;
                continue;
            }
            const archived = node.enrollment, c = archived.approval.context;
            if (c.accountId !== proof.accountId || c.accountGeneration !== proof.accountGeneration || current.id !== c.approverDeviceId || current.signing !== c.approverSigningPublicKey || current.receiving !== c.approverReceivingPublicKey || ids.has(c.initiatorDeviceId))
                fail();
            const fields = canonical(recoveryNodeFields(archived));
            verify(current.signing, fields, archived.approval.approverSignature);
            verify(c.initiatorSigningPublicKey, fields, archived.approval.initiatorSignature!);
            for (const s of archived.approval.grants) {
                const g = s.grant;
                if (g.accountId !== proof.accountId || g.accountGeneration !== proof.accountGeneration || g.issuerDeviceId !== current.id || g.subjectDeviceId !== c.initiatorDeviceId || g.subjectSigningPublicKey !== c.initiatorSigningPublicKey || g.subjectReceivingPublicKey !== c.initiatorReceivingPublicKey || g.grantGeneration !== "1" || g.role === 'none')
                    fail();
                verify(current.signing, grantBytes(g), s.signature);
            }
            const child: Identity = { id: c.initiatorDeviceId, signing: c.initiatorSigningPublicKey, receiving: c.initiatorReceivingPublicKey, archive: JSON.stringify([b64(fields), archived.approval.approverSignature, archived.approval.initiatorSignature]) };
            add(child);
            ids.add(child.id);
            current = child;
        }
    }
    walk(proof.path);
    for (const branch of proof.identityPaths)
        walk(branch);
    const authorities = new Map<string, IssuerRecoveryAuthority>(), origins = new Map<string, SignedEnvironmentOrigin>();
    const generations = new Map<string, string>(), idempotencies = new Map<string, string>();
    for (const authority of proof.authorities) {
        const signed = authority.grant, g = signed.grant, issuer = identities.get(g.issuerDeviceId), subject = identities.get(g.subjectDeviceId), h = issuerAuthorityHash(signed);
        if (g.accountId !== proof.accountId || g.accountGeneration !== proof.accountGeneration || !issuer || !subject || g.subjectSigningPublicKey !== subject.signing || g.subjectReceivingPublicKey !== subject.receiving)
            fail();
        verify(issuer.signing, grantBytes(g), signed.signature);
        for (const [map, key] of [[generations, `${g.environmentId}/${g.subjectDeviceId}/${g.grantGeneration}`], [idempotencies, `${g.issuerDeviceId}/${g.idempotencyKey}`]] as const) {
            if (map.has(key) && map.get(key) !== h)
                fail();
            map.set(key, h);
        }
        authorities.set(h, authority);
    }
    for (const record of proof.recoveredDevices)
        for (const signed of record.submission.grants) {
            const g = signed.grant, h = issuerAuthorityHash(signed);
            for (const [map, key] of [[generations, `${g.environmentId}/${g.subjectDeviceId}/${g.grantGeneration}`], [idempotencies, `${g.issuerDeviceId}/${g.idempotencyKey}`]] as const) {
                if (map.has(key) && map.get(key) !== h)
                    fail();
                map.set(key, h);
            }
        }
    for (const node of [...proof.path, ...proof.identityPaths.flat()].filter(node => node.kind === "paired"))
        for (const signed of node.enrollment!.approval.grants) {
            const g = signed.grant, h = issuerAuthorityHash(signed);
            for (const [map, key] of [[generations, `${g.environmentId}/${g.subjectDeviceId}/${g.grantGeneration}`], [idempotencies, `${g.issuerDeviceId}/${g.idempotencyKey}`]] as const) {
                if (map.has(key) && map.get(key) !== h)
                    fail();
                map.set(key, h);
            }
        }
    for (const origin of proof.origins) {
        const o = origin.origin, actor = identities.get(o.actorDeviceId);
        if (o.accountId !== proof.accountId || o.accountGeneration !== proof.accountGeneration || !actor)
            fail();
        verify(actor.signing, environmentOriginBytes(o), origin.signature);
        origins.set(environmentOriginHash(origin), origin);
    }
    // 一个已签轮换清单是完整控制快照：不能只验证当前读者那一行。
    // 每行必须有精确签名授权和身份来源；来源证书本身不包含业务密文。
    for (const [originHash, signedOrigin] of origins) {
        const o = signedOrigin.origin;
        for (const row of o.before) {
            const node = authorities.get(row.grantHash);
            if (!node || node.grant.grant.environmentId !== o.environmentId || node.grant.grant.keyVersion !== o.previousKeyVersion || JSON.stringify(rightsFields([row])) !== JSON.stringify(rightsFields([environmentRights(node.grant)])))
                fail();
        }
        for (const row of o.after) {
            const node = authorities.get(row.grantHash), previous = o.before.find(prior => prior.subjectDeviceId === row.subjectDeviceId);
            if (!node || node.grant.grant.environmentId !== o.environmentId || node.grant.grant.keyVersion !== o.keyVersion || JSON.stringify(rightsFields([row])) !== JSON.stringify(rightsFields([environmentRights(node.grant)])) || node.originHash !== originHash || node.parentHash !== o.authorityHash || node.previousGrantHash !== (o.operation === "rotate" ? previous?.grantHash : ""))
                fail();
        }
    }
    function parentMatches(signed: SignedGrant, parent: SignedGrant): boolean {
        const g = signed.grant, p = parent.grant;
        return p.role === "admin" && p.environmentId === g.environmentId && p.keyVersion === g.keyVersion && p.subjectDeviceId === g.issuerDeviceId && within(g.expiresAt, p.expiresAt);
    }
    const visited = new Set<string>(), visiting = new Set<string>();
    function check(h: string): void {
        if (visited.has(h))
            return;
        if (visiting.has(h))
            fail();
        const node = authorities.get(h);
        if (!node)
            fail();
        visiting.add(h);
        const g = node.grant.grant;
        if (node.recoveryEnrollmentHash) {
            const record = recovered.get(node.recoveryEnrollmentHash);
            if (!record || node.parentHash || node.originHash || node.previousGrantHash || !record.submission.grants.some(signed => issuerAuthorityHash(signed) === h))
                fail();
        }
        else if (!node.parentHash) {
            if (!genesis.has(h) || node.originHash || node.previousGrantHash || g.role !== "admin" || g.issuerDeviceId !== root.id || g.subjectDeviceId !== root.id || g.keyVersion !== "1" || g.grantGeneration !== "1" || g.expiresAt !== "0")
                fail();
        }
        else {
            check(node.parentHash);
            const parent = authorities.get(node.parentHash)!.grant;
            if (!node.originHash) {
                if (node.previousGrantHash || !parentMatches(node.grant, parent))
                    fail();
            }
            else {
                const signedOrigin = origins.get(node.originHash);
                if (!signedOrigin)
                    fail();
                const o = signedOrigin.origin, p = parent.grant;
                if (p.role !== "admin" || p.subjectDeviceId !== o.actorDeviceId || p.environmentId !== o.authorityEnvironmentId || p.keyVersion !== o.authorityKeyVersion || p.grantGeneration !== o.authorityGrantGeneration || o.authorityHash !== node.parentHash || g.issuerDeviceId !== o.actorDeviceId || g.environmentId !== o.environmentId || g.keyVersion !== o.keyVersion)
                    fail();
                const after = o.after.find(row => row.subjectDeviceId === g.subjectDeviceId);
                if (!after || JSON.stringify(rightsFields([after])) !== JSON.stringify(rightsFields([environmentRights(node.grant)])))
                    fail();
                if (o.operation === "create") {
                    if (node.previousGrantHash || g.subjectDeviceId !== o.actorDeviceId || g.role !== "admin" || g.grantGeneration !== "1" || !within(g.expiresAt, p.expiresAt))
                        fail();
                }
                else {
                    check(node.previousGrantHash);
                    const previous = authorities.get(node.previousGrantHash)!.grant;
                    const before = o.before.find(row => row.subjectDeviceId === g.subjectDeviceId), actorBefore = o.before.find(row => row.subjectDeviceId === o.actorDeviceId);
                    if (!before || !actorBefore || actorBefore.role !== "admin" || actorBefore.grantHash !== node.parentHash || before.grantHash !== node.previousGrantHash || JSON.stringify(rightsFields([before])) !== JSON.stringify(rightsFields([environmentRights(previous)])) || previous.grant.environmentId !== o.environmentId || previous.grant.keyVersion !== o.previousKeyVersion || before.subjectSigningPublicKey !== after.subjectSigningPublicKey || before.subjectReceivingPublicKey !== after.subjectReceivingPublicKey || before.role !== after.role || before.expiresAt !== after.expiresAt || BigInt(after.grantGeneration) !== BigInt(before.grantGeneration) + 1n)
                        fail();
                }
            }
        }
        visiting.delete(h);
        visited.add(h);
    }
    for (const h of authorities.keys())
        check(h);
    // 归档身份链上的授权同样必须有受验证来源，不能仅以双方签名证明管理权。
    for (const node of [...proof.path, ...proof.identityPaths.flat()].filter(node => node.kind === "paired"))
        for (const grant of node.enrollment!.approval.grants) {
            const exactNode = authorities.get(issuerAuthorityHash(grant));
            if (exactNode)
                continue;
            if (![...authorities.values()].some(parent => parentMatches(grant, parent.grant)))
                fail();
        }
    for (const target of proof.targets) {
        const authority = authorities.get(target.authorityHash);
        if (!authority || authority.grant.grant.environmentId !== target.environmentId)
            fail();
    }
    return { authorities, identities, origins, head, recovered };
}
export function archivedRecoveryEnrollment(c: EnrollmentCertificate | EnrollmentApprovalV4): RecoveryPairedEnrollment {
    if (!('certificateVersion' in c) || c.certificateVersion !== "4")
        return archivedOriginEnrollment(c as Parameters<typeof archivedOriginEnrollment>[0]);
    if (!c.initiatorSignature)
        fail("issuer_archive_mismatch");
    return { certificateVersion: "4", issuerProofHash: issuerRecoveryHash(c.issuerProof), approval: { context: structuredClone(c.context), pairingProfile: c.pairingProfile, transcriptHash: c.transcriptHash, grants: structuredClone(c.grants), approverSignature: c.approverSignature, initiatorSignature: c.initiatorSignature } };
}
function storedArchive(a: RecoveryAuthorityAccount, id: string): EnrollmentCertificate | EnrollmentApprovalV4 | undefined { return own(a.deviceEnrollments, id) as EnrollmentCertificate | EnrollmentApprovalV4 | undefined; }
export function verifyAcceptedIssuerRecoveryEvidence(a: RecoveryAuthorityAccount, p: IssuerRecoveryProof): VerifiedRecoveryGraph {
    const init = originalInitialization(a);
    if (!init || initializationReference(init) !== initializationReference(p.initialization) || p.accountId !== a.id || p.accountGeneration !== a.generation)
        fail("initialization_evidence_invalid");
    const graph = verifyIssuerRecoveryGraph(p);
    if (!a.trustRoot || JSON.stringify(trustRootPayload(a.id, a.generation, a.trustRoot)) !== JSON.stringify(trustRootPayload(a.id, a.generation, p.trustRoot)) || a.trustRoot.signature !== p.trustRoot.signature)
        fail("trust_root_stale");
    const accepted = a.recoveryAuthorityTransitions ?? [];
    if (accepted.length !== p.transitions.length || accepted.some(r => !p.transitions.some(other => transitionHash(r.submission) === transitionHash(other.submission) && r.sequence === other.sequence)))
        fail("recovery_chain_invalid");
    for (const r of p.recoveredDevices) {
        const h = recoveredDeviceHash(r.submission), stored = Object.values(a.recoveredDevices ?? {}).find(record => recoveredDeviceHash(record.submission) === h);
        if (!stored || stored.sequence !== r.sequence || JSON.stringify(stored.submission) !== JSON.stringify(r.submission))
            fail("issuer_archive_mismatch");
    }
    for (const node of [...p.path, ...p.identityPaths.flat()]) {
        if (node.kind === 'recovered') {
            if (!Object.values(a.recoveredDevices ?? {}).some(r => recoveredDeviceHash(r.submission) === node.recoveryEnrollmentHash))
                fail("issuer_archive_mismatch");
            continue;
        }
        const stored = storedArchive(a, node.enrollment.approval.context.initiatorDeviceId);
        if (!stored)
            fail("issuer_archive_mismatch");
        const archived = archivedRecoveryEnrollment(stored);
        if (JSON.stringify(recoveryNodeFields(archived)) !== JSON.stringify(recoveryNodeFields(node.enrollment)) || archived.approval.approverSignature !== node.enrollment.approval.approverSignature || archived.approval.initiatorSignature !== node.enrollment.approval.initiatorSignature)
            fail("issuer_archive_mismatch");
    }
    const initial = new Set(init.proposal.environments.map(e => issuerAuthorityHash(e.grant)));
    for (const [h, node] of graph.authorities) {
        const found = a.grantHistory?.find(event => issuerAuthorityHash(event.grant) === h);
        if (!found)
            fail("issuer_authority_unaccepted");
        const rec = (found as typeof found & {
            recoveryEnrollmentHash?: string;
        }).recoveryEnrollmentHash;
        if (node.recoveryEnrollmentHash) {
            const record = Object.values(a.recoveredDevices ?? {}).find(r => recoveredDeviceHash(r.submission) === node.recoveryEnrollmentHash);
            if (rec !== node.recoveryEnrollmentHash || found.authorization !== null || found.originHash || !record || record.sequence !== found.sequence)
                fail("issuer_authority_parent_mismatch");
        }
        else if (rec)
            fail("issuer_authority_parent_mismatch");
        else if (node.originHash) {
            const origin = a.environmentHistory?.find(e => e.origin && environmentOriginHash(e.origin) === node.originHash);
            if (found.originHash !== node.originHash || !found.authorization || issuerAuthorityHash(found.authorization) !== node.parentHash || !origin || origin.sequence !== found.sequence)
                fail("issuer_authority_parent_mismatch");
        }
        else if (!node.parentHash) {
            if (found.authorization !== null || found.originHash || !initial.has(h))
                fail("issuer_environment_evidence_required");
        }
        else if (found.originHash || !found.authorization || issuerAuthorityHash(found.authorization) !== node.parentHash)
            fail("issuer_authority_parent_mismatch");
    }
    for (const [h, origin] of graph.origins) {
        const found = a.environmentHistory?.find(e => e.origin && environmentOriginHash(e.origin) === h);
        if (!found?.origin || found.sequence !== Number(origin.origin.expectedSequence) + 1 || issuerAuthorityHash(found.authorization) !== origin.origin.authorityHash || found.origin.signature !== origin.signature || b64(environmentOriginBytes(found.origin.origin)) !== b64(environmentOriginBytes(origin.origin)) || environmentChangeHash(environmentChangeBytes(found.change.change), found.change.signature) !== origin.origin.changeHash)
            fail("issuer_origin_unaccepted");
        verify(graph.identities.get(origin.origin.actorDeviceId)!.signing, environmentChangeBytes(found.change.change), found.change.signature);
    }
    return graph;
}
export function buildIssuerRecoveryEvidence(a: RecoveryAuthorityAccount, deviceId: string, sources: SignedGrant[], targets: SignedGrant[] = sources, identityIds: string[] = []): IssuerRecoveryProof | null {
    if (!sources.length)
        return null;
    const initialization = originalInitialization(a);
    if (!initialization || !a.trustRoot)
        fail("initialization_evidence_required");
    const initial = new Set(initialization.proposal.environments.map(e => issuerAuthorityHash(e.grant))), root = a.trustRoot, authorities = new Map<string, IssuerRecoveryAuthority>(), origins = new Map<string, SignedEnvironmentOrigin>(), paths = new Map<string, IssuerRecoveryArchive[]>(), recovered = new Map<string, AcceptedRecoveredDevice>(), visiting = new Set<string>(), expanded = new Set<string>();
    function identityPath(id: string, stack = new Set<string>()): IssuerRecoveryArchive[] {
        if (id === root.rootDeviceId)
            return [];
        const previous = paths.get(id);
        if (previous)
            return previous;
        if (stack.has(id))
            fail();
        stack.add(id);
        const rec = own(a.recoveredDevices, id);
        let path: IssuerRecoveryArchive[];
        if (rec) {
            const h = recoveredDeviceHash(rec.submission);
            recovered.set(h, structuredClone(rec));
            path = [{ kind: 'recovered', recoveryEnrollmentHash: h }];
        }
        else {
            const archive = storedArchive(a, id);
            if (!archive?.initiatorSignature)
                fail('issuer_archive_mismatch');
            path = [...identityPath(archive.context.approverDeviceId, stack), { kind: 'paired', enrollment: archivedRecoveryEnrollment(archive) }];
        }
        paths.set(id, path);
        stack.delete(id);
        return path;
    }
    function source(signed: SignedGrant): void {
        const h = issuerAuthorityHash(signed);
        if (authorities.has(h))
            return;
        if (visiting.has(h))
            fail();
        visiting.add(h);
        const accepted = a.grantHistory?.find(event => issuerAuthorityHash(event.grant) === h);
        if (!accepted)
            fail('issuer_authority_unaccepted');
        identityPath(signed.grant.issuerDeviceId);
        identityPath(signed.grant.subjectDeviceId);
        const recoveryEnrollmentHash = (accepted as typeof accepted & {
            recoveryEnrollmentHash?: string;
        }).recoveryEnrollmentHash ?? '', node: IssuerRecoveryAuthority = { grant: structuredClone(signed), parentHash: '', originHash: '', previousGrantHash: '', recoveryEnrollmentHash };
        if (recoveryEnrollmentHash) {
            const rec = Object.values(a.recoveredDevices ?? {}).find(r => recoveredDeviceHash(r.submission) === recoveryEnrollmentHash);
            if (!rec || accepted.authorization || accepted.originHash)
                fail();
            recovered.set(recoveryEnrollmentHash, structuredClone(rec));
        }
        else if (!accepted.authorization) {
            if (accepted.originHash || !initial.has(h))
                fail('issuer_environment_evidence_required');
        }
        if (accepted.authorization) {
            node.parentHash = issuerAuthorityHash(accepted.authorization);
            source(accepted.authorization);
        }
        if (accepted.originHash) {
            const event = a.environmentHistory?.find(event => event.origin && environmentOriginHash(event.origin) === accepted.originHash);
            if (!event?.origin)
                fail('issuer_origin_unaccepted');
            node.originHash = accepted.originHash;
            origins.set(node.originHash, structuredClone(event.origin));
            if (event.origin.origin.operation === 'rotate') {
                const before = event.origin.origin.before.find(row => row.subjectDeviceId === signed.grant.subjectDeviceId), previous = before && a.grantHistory?.find(row => issuerAuthorityHash(row.grant) === before.grantHash);
                if (!before || !previous)
                    fail();
                node.previousGrantHash = before.grantHash;
                source(previous.grant);
            }
        }
        authorities.set(h, node);
        visiting.delete(h);
        if (node.originHash && !expanded.has(node.originHash)) {
            expanded.add(node.originHash);
            for (const row of [...origins.get(node.originHash)!.origin.before, ...origins.get(node.originHash)!.origin.after]) {
                const accepted = a.grantHistory?.find(e => issuerAuthorityHash(e.grant) === row.grantHash);
                if (!accepted)
                    fail();
                source(accepted.grant);
            }
        }
    }
    const path = identityPath(deviceId);
    // 未获本环境授权的既有设备也须通过完整受签归档绑定，不能从目录建立公钥信任。
    for (const id of identityIds)
        identityPath(id);
    for (const signed of sources)
        source(signed);
    let processed = 0;
    while (processed < paths.size) {
        const all = [...paths.values()];
        for (; processed < all.length; processed++)
            for (const node of all[processed]!)
                if (node.kind === 'paired')
                    for (const grant of node.enrollment.approval.grants)
                        source(grant);
                else
                    for (const grant of recovered.get(node.recoveryEnrollmentHash)!.submission.grants)
                        source(grant);
    }
    const main = JSON.stringify(pathRows(path)), branches = [...paths.values()].filter(p => JSON.stringify(pathRows(p)) !== main), leaves = branches.filter(p => !branches.some(other => other.length > p.length && JSON.stringify(pathRows(other.slice(0, p.length))) === JSON.stringify(pathRows(p))));
    const proof: IssuerRecoveryProof = { profile: issuerRecoveryProfile, accountId: a.id, accountGeneration: a.generation, trustRoot: structuredClone(root), initialization: structuredClone(initialization), path: structuredClone(path), authorities: [...authorities.values()], targets: targets.map(s => ({ environmentId: s.grant.environmentId, authorityHash: issuerAuthorityHash(s) })), origins: [...origins.values()], identityPaths: structuredClone(leaves), transitions: structuredClone(a.recoveryAuthorityTransitions ?? []), recoveredDevices: [...recovered.values()] };
    verifyAcceptedIssuerRecoveryEvidence(a, proof);
    return proof;
}
export function enrollmentV4Fields(certificate: EnrollmentApprovalV4): string[] {
    exact(certificate, ["certificateVersion", "capabilities", "context", "pairingProfile", "transcriptHash", "grants", "issuerProof", "approverSignature", ...(Object.hasOwn(certificate ?? {}, "initiatorSignature") ? ["initiatorSignature"] : [])]);
    if (certificate.certificateVersion !== "4" || JSON.stringify(certificate.capabilities) !== JSON.stringify(["issuer-recovery-v1"]))
        fail("recovery_capability_required");
    const c = certificate.context;
    exact(c, ["accountId", "accountGeneration", "purpose", "sessionId", "challengeNonce", "expiresAt", "initiatorDeviceId", "initiatorSigningPublicKey", "initiatorReceivingPublicKey", "approverDeviceId", "approverSigningPublicKey", "approverReceivingPublicKey"]);
    for (const id of [c.accountId, c.sessionId, c.initiatorDeviceId, c.approverDeviceId])
        identifier(id);
    generation(c.accountGeneration);
    generation(c.expiresAt);
    bytes(c.challengeNonce, 32);
    for (const key of [c.initiatorSigningPublicKey, c.initiatorReceivingPublicKey, c.approverSigningPublicKey, c.approverReceivingPublicKey])
        bytes(key, 32);
    if (c.purpose !== "enroll-device" || c.initiatorDeviceId === c.approverDeviceId || c.initiatorSigningPublicKey === c.initiatorReceivingPublicKey || c.approverSigningPublicKey === c.approverReceivingPublicKey || BigInt(c.expiresAt) > 253402300799n || certificate.issuerProof.accountId !== c.accountId || certificate.issuerProof.accountGeneration !== c.accountGeneration)
        fail();
    const fields = enrollmentFields(certificate);
    fields[0] = "harmonia/device-enrollment/v4";
    fields.push(issuerRecoveryHash(certificate.issuerProof));
    return fields;
}
export function verifyEnrollmentV4(certificate: EnrollmentApprovalV4): VerifiedRecoveryGraph {
    const fields = canonical(enrollmentV4Fields(certificate)), c = certificate.context;
    verify(c.approverSigningPublicKey, fields, certificate.approverSignature);
    if (certificate.initiatorSignature !== undefined)
        verify(c.initiatorSigningPublicKey, fields, certificate.initiatorSignature);
    const p = certificate.issuerProof, graph = verifyIssuerRecoveryGraph(p), terminal = p.path.at(-1);
    let current = graph.identities.get(p.trustRoot.rootDeviceId)!;
    if (terminal?.kind === 'paired')
        current = graph.identities.get(terminal.enrollment.approval.context.initiatorDeviceId)!;
    else if (terminal?.kind === 'recovered')
        current = graph.identities.get(graph.recovered.get(terminal.recoveryEnrollmentHash)!.submission.enrollment.deviceId)!;
    if (current.id !== c.approverDeviceId || current.signing !== c.approverSigningPublicKey || current.receiving !== c.approverReceivingPublicKey || graph.identities.has(c.initiatorDeviceId) || graph.head.seenKeys.has(c.initiatorSigningPublicKey) || graph.head.seenKeys.has(c.initiatorReceivingPublicKey) || [...graph.identities.values()].some(id => [id.signing, id.receiving].some(key => key === c.initiatorSigningPublicKey || key === c.initiatorReceivingPublicKey)) || p.targets.length !== certificate.grants.length)
        fail();
    const hashes = new Map<string, string>();
    for (const signed of [...p.authorities.map(n => n.grant), ...certificate.grants]) {
        const g = signed.grant, h = issuerAuthorityHash(signed);
        for (const key of [`${g.environmentId}/${g.subjectDeviceId}/${g.grantGeneration}`, `${g.issuerDeviceId}/${g.idempotencyKey}`]) {
            if (hashes.has(key) && hashes.get(key) !== h)
                fail();
            hashes.set(key, h);
        }
    }
    for (const signed of certificate.grants) {
        const g = signed.grant, target = p.targets.find(t => t.environmentId === g.environmentId), parent = target && graph.authorities.get(target.authorityHash)?.grant.grant;
        if (!parent || parent.role !== 'admin' || parent.subjectDeviceId !== current.id || parent.subjectSigningPublicKey !== current.signing || parent.subjectReceivingPublicKey !== current.receiving || parent.environmentId !== g.environmentId || parent.keyVersion !== g.keyVersion || !within(g.expiresAt, parent.expiresAt) || g.accountId !== p.accountId || g.accountGeneration !== p.accountGeneration || g.issuerDeviceId !== current.id || g.subjectDeviceId !== c.initiatorDeviceId || g.subjectSigningPublicKey !== c.initiatorSigningPublicKey || g.subjectReceivingPublicKey !== c.initiatorReceivingPublicKey || g.grantGeneration !== "1" || g.role === 'none')
            fail();
        verify(current.signing, grantBytes(g), signed.signature);
    }
    return graph;
}
export function issuerRecoveryStillCurrent(a: RecoveryAuthorityAccount, c: EnrollmentApprovalV4): void {
    verifyEnrollmentV4(c);
    verifyAcceptedIssuerRecoveryEvidence(a, c.issuerProof);
    for (const t of c.issuerProof.targets) {
        const signed = own(a.grants, grantKey(t.environmentId, c.context.approverDeviceId));
        if (!signed || issuerAuthorityHash(signed) !== t.authorityHash)
            fail('issuer_authority_changed');
    }
}
