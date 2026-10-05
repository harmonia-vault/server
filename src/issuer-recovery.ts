import { Fault, type SignedGrant } from './model.js';
import { generation, grantBytes, verify } from './protocol.js';
import { canonical, type EnrollmentCertificate } from './enrollment-wire.js';
import { issuerAuthorityHash } from './issuer-proof.js';
import { environmentOriginBytes, environmentOriginHash, environmentRights, rightsFields, type SignedEnvironmentOrigin } from './environment-origin.js';
import { trustRootPayload, type TrustRoot } from './trust-root.js';
import type { OriginalInitialization } from './initialization-evidence.js';
import { initializationReference } from './recovery-authority-wire.js';
import type { RecoveryAuthorityHead } from './recovery-authority-history.js';
export interface IssuerRecoveryAuthority {
    grant: SignedGrant;
    parentHash: string;
    originHash: string;
    previousGrantHash: string;
    recoveryEnrollmentHash: string;
}
interface Identity {
    id: string;
    signing: string;
    receiving: string;
    archive?: string;
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
export interface RecoveryControlPaired { certificateVersion: "5"; issuerProofHash: string; approval: EnrollmentCertificate }
export type RecoveryControlArchive = { kind: "paired"; enrollment: RecoveryControlPaired } | { kind: "recovered"; recoveryEnrollmentHash: string };
export interface RecoveryControlInput {
    accountId: string; accountGeneration: string; trustRoot: TrustRoot;
    path: RecoveryControlArchive[]; authorities: IssuerRecoveryAuthority[];
    targets: { environmentId: string; authorityHash: string }[];
    origins: SignedEnvironmentOrigin[]; identityPaths: RecoveryControlArchive[][];
}
export interface RecoveryControlRecord { submission: { enrollment: import("./recovered-device-wire.js").RecoveredEnrollment; grants: SignedGrant[] }; sequence: number }
/** 只验控制面。调用方须先验证原初始化、恢复链尾与记录双签；叶不包装成旧完整Proof3。 */
export function verifyRecoveryControlGraph<R extends RecoveryControlRecord>(proof: RecoveryControlInput, initial: OriginalInitialization, head: RecoveryAuthorityHead, recovered: Map<string, R>, archiveFields: (n: RecoveryControlPaired) => string[]): { authorities: Map<string, IssuerRecoveryAuthority>; identities: Map<string, Identity>; origins: Map<string, SignedEnvironmentOrigin>; head: RecoveryAuthorityHead; recovered: Map<string, R> } {
    initializationReference(initial);
    const root: Identity = { id: initial.proposal.device.id, signing: initial.proposal.device.signingPublicKey, receiving: initial.proposal.device.receivingPublicKey }, r = proof.trustRoot;
    if (proof.accountId !== initial.proof.accountId || proof.accountGeneration !== initial.proof.accountGeneration || r.rootDeviceId !== root.id || r.rootSigningPublicKey !== root.signing || r.rootReceivingPublicKey !== root.receiving || JSON.stringify(trustRootPayload(proof.accountId, proof.accountGeneration, r)) !== JSON.stringify(trustRootPayload(proof.accountId, proof.accountGeneration, head.root)) || r.signature !== head.root.signature) fail();
    const genesis = new Set(initial.proposal.environments.map(e => issuerAuthorityHash(e.grant))), identities = new Map<string, Identity>([[root.id, root]]), usedKeys = new Map<string, string>([[root.signing, root.id], [root.receiving, root.id]]);
    for (const key of head.seenKeys)
        if (key !== root.signing && key !== root.receiving)
            usedKeys.set(key, "recovery");
    function add(child: Identity): void { const prior = identities.get(child.id); if (prior && (prior.signing !== child.signing || prior.receiving !== child.receiving || prior.archive !== child.archive))
        fail(); for (const key of [child.signing, child.receiving])
        if (usedKeys.has(key) && usedKeys.get(key) !== child.id)
            fail(); if (child.signing === child.receiving)
        fail(); identities.set(child.id, child); usedKeys.set(child.signing, child.id); usedKeys.set(child.receiving, child.id); }
    function walk(path: RecoveryControlArchive[]): void {
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
            const fields = canonical(archiveFields(archived));
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
    for (const record of recovered.values())
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
