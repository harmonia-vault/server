import { originalInitialization } from "./initialization-evidence.js";
import { environmentChangeBytes } from "./environments.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { Fault, grantKey, type SignedGrant } from "./model.js";
import { bytes, generation, grantBytes, identifier, mutationBytes, verify } from "./protocol.js";
import { canonical, enrollmentFields, exact, own, type EnrollmentAccount, type EnrollmentCertificate, type PairingContext } from "./enrollment-wire.js";
import { issuerAuthorityHash, issuerNodeFields, issuerProofCanonical as importLegacyCanonical, type IssuerEnrollment } from "./issuer-proof.js";
import { environmentChangeHash, environmentOriginBytes, environmentOriginHash, environmentRights, originDigest, rightsFields, type SignedEnvironmentOrigin } from "./environment-origin.js";
import { trustRootPayload, validateTrustRoot, type TrustRoot } from "./trust-root.js";

export const issuerOriginCapability = "issuer-origin-v1";
export const maxIssuerOriginBytes = 1_000_000;
export interface IssuerOriginEnrollment extends Omit<IssuerEnrollment, "certificateVersion"> { certificateVersion: "1" | "2" | "3" }
export interface IssuerOriginAuthority {
  grant: SignedGrant;
  parentHash: string;
  originHash: string;
  previousGrantHash: string;
}
export interface IssuerOriginProof {
  profile: "harmonia/issuer-proof/v2";
  accountId: string;
  accountGeneration: string;
  trustRoot: TrustRoot;
  path: IssuerOriginEnrollment[];
  authorities: IssuerOriginAuthority[];
  targets: { environmentId: string; authorityHash: string }[];
  origins: SignedEnvironmentOrigin[];
  identityPaths: IssuerOriginEnrollment[][];
}
export interface EnrollmentApprovalV3 extends EnrollmentCertificate { certificateVersion: "3"; issuerProof: IssuerOriginProof }
function fail(code = "issuer_origin_invalid"): never { throw new Fault(403, code); }
const b64 = (value: Uint8Array): string => Buffer.from(value).toString("base64url");
const digest = (value: Uint8Array): string => Buffer.from(sha256(value)).toString("hex");
const compare = (first: string, second: string): number => first < second ? -1 : first > second ? 1 : 0;
function within(child: string, parent: string): boolean {
  for (const value of [child, parent]) { if (value !== "0") generation(value); if (BigInt(value) > 253402300799n) fail(); }
  return parent === "0" || child !== "0" && BigInt(child) <= BigInt(parent);
}
export function issuerOriginNodeFields(node: IssuerOriginEnrollment): string[] {
  if (node.certificateVersion !== "3") return issuerNodeFields(node as IssuerEnrollment);
  const fields = issuerNodeFields({ ...node, certificateVersion: "2" });
  fields[0] = "harmonia/device-enrollment/v3";
  return fields;
}
function pathRows(path: IssuerOriginEnrollment[]): string[][] {
  if (!Array.isArray(path) || path.length > 32) throw new Fault(400, "issuer_origin_invalid");
  return path.map(node => [node.certificateVersion, b64(canonical(issuerOriginNodeFields(node))), node.approval.approverSignature, node.approval.initiatorSignature!]);
}
export function issuerOriginCanonical(proof: IssuerOriginProof): Uint8Array {
  exact(proof, ["profile", "accountId", "accountGeneration", "trustRoot", "path", "authorities", "targets", "origins", "identityPaths"]);
  identifier(proof.accountId); generation(proof.accountGeneration);
  if (proof.profile !== "harmonia/issuer-proof/v2" || !Array.isArray(proof.authorities) || !proof.authorities.length || proof.authorities.length > 512 || !Array.isArray(proof.targets) || !proof.targets.length || proof.targets.length > 256 || !Array.isArray(proof.origins) || proof.origins.length > 128 || !Array.isArray(proof.identityPaths) || proof.identityPaths.length > 16) throw new Fault(400, "issuer_origin_invalid");
  validateTrustRoot(proof.accountId, proof.accountGeneration, proof.trustRoot);
  const path = pathRows(proof.path), identityPaths = proof.identityPaths.map(pathRows).sort((first, second) => compare(JSON.stringify(first), JSON.stringify(second)));
  if (proof.path.length + proof.identityPaths.reduce((sum, branch) => sum + branch.length, 0) > 128) throw new Fault(413, "issuer_origin_too_large");
  for (let index = 0; index < identityPaths.length; index++) if (!identityPaths[index]!.length || index > 0 && JSON.stringify(identityPaths[index]) === JSON.stringify(identityPaths[index - 1])) fail();
  const seen = new Set<string>();
  const authorities = [...proof.authorities].map(authority => {
    exact(authority, ["grant", "parentHash", "originHash", "previousGrantHash"]);
    issuerAuthorityHash(authority.grant);
    if (authority.grant.grant.role === "none") fail();
    for (const value of [authority.parentHash, authority.originHash, authority.previousGrantHash]) if (value !== "") originDigest(value);
    return authority;
  }).sort((first, second) => {
    const a = first.grant.grant, b = second.grant.grant;
    return compare(a.environmentId, b.environmentId) || compare(a.subjectDeviceId, b.subjectDeviceId) || (BigInt(a.grantGeneration) < BigInt(b.grantGeneration) ? -1 : BigInt(a.grantGeneration) > BigInt(b.grantGeneration) ? 1 : 0);
  }).map(authority => {
    const g = authority.grant.grant, key = `${g.environmentId}/${g.subjectDeviceId}/${g.grantGeneration}`;
    if (seen.has(key)) fail(); seen.add(key);
    return [g.environmentId, g.subjectDeviceId, g.grantGeneration, b64(grantBytes(g)), authority.grant.signature, authority.parentHash, authority.originHash, authority.previousGrantHash];
  });
  const targetIds = new Set<string>();
  const targets = [...proof.targets].map(target => {
    exact(target, ["environmentId", "authorityHash"]); identifier(target.environmentId); originDigest(target.authorityHash); return target;
  }).sort((first, second) => compare(first.environmentId, second.environmentId)).map(target => {
    if (targetIds.has(target.environmentId)) fail(); targetIds.add(target.environmentId); return [target.environmentId, target.authorityHash];
  });
  const originIds = new Set<string>();
  const origins = proof.origins.map(origin => {
    const h = environmentOriginHash(origin);
    if (originIds.has(h)) fail(); originIds.add(h);
    return [h, b64(environmentOriginBytes(origin.origin)), origin.signature];
  }).sort((first, second) => compare(first[0]!, second[0]!));
  const result = canonical([proof.profile, proof.accountId, proof.accountGeneration,
    [b64(canonical(trustRootPayload(proof.accountId, proof.accountGeneration, proof.trustRoot))), proof.trustRoot.signature],
    path, authorities, targets, origins, identityPaths]);
  if (result.length > maxIssuerOriginBytes) throw new Fault(413, "issuer_origin_too_large");
  return result;
}
export const issuerOriginProofHash = (proof: IssuerOriginProof): string => digest(issuerOriginCanonical(proof));
export function enrollmentV3Fields(certificate: EnrollmentApprovalV3): string[] {
  exact(certificate, ["certificateVersion", "context", "pairingProfile", "transcriptHash", "grants", "issuerProof", "approverSignature", ...(Object.hasOwn(certificate ?? {}, "initiatorSignature") ? ["initiatorSignature"] : [])]);
  const context = certificate.context;
  exact(context, ["accountId", "accountGeneration", "purpose", "sessionId", "challengeNonce", "expiresAt", "initiatorDeviceId", "initiatorSigningPublicKey", "initiatorReceivingPublicKey", "approverDeviceId", "approverSigningPublicKey", "approverReceivingPublicKey"]);
  for (const value of [context.accountId, context.sessionId, context.initiatorDeviceId, context.approverDeviceId]) identifier(value);
  generation(context.accountGeneration); generation(context.expiresAt); bytes(context.challengeNonce, 32);
  for (const value of [context.initiatorSigningPublicKey, context.initiatorReceivingPublicKey, context.approverSigningPublicKey, context.approverReceivingPublicKey]) bytes(value, 32);
  if (context.purpose !== "enroll-device" || context.initiatorDeviceId === context.approverDeviceId || context.initiatorSigningPublicKey === context.initiatorReceivingPublicKey || context.approverSigningPublicKey === context.approverReceivingPublicKey || BigInt(context.expiresAt) > 253402300799n) fail();
  const fields = enrollmentFields(certificate);
  fields[0] = "harmonia/device-enrollment/v3";
  fields.push(issuerOriginProofHash(certificate.issuerProof));
  if (certificate.certificateVersion !== "3" || certificate.issuerProof.accountId !== certificate.context.accountId || certificate.issuerProof.accountGeneration !== certificate.context.accountGeneration) fail();
  return fields;
}
export function archivedOriginEnrollment(certificate: EnrollmentCertificate | import("./issuer-proof.js").EnrollmentApprovalV2 | EnrollmentApprovalV3): IssuerOriginEnrollment {
  const approval: EnrollmentCertificate = { context: structuredClone(certificate.context), pairingProfile: certificate.pairingProfile, transcriptHash: certificate.transcriptHash,
    grants: structuredClone(certificate.grants), approverSignature: certificate.approverSignature, ...(certificate.initiatorSignature ? { initiatorSignature: certificate.initiatorSignature } : {}) };
  if (!('certificateVersion' in certificate)) return { certificateVersion: "1", issuerProofHash: "", approval };
  return { certificateVersion: certificate.certificateVersion, issuerProofHash: certificate.certificateVersion === "3" ? issuerOriginProofHash(certificate.issuerProof) : digest(importLegacyCanonical(certificate.issuerProof)), approval };
}
// 保留 v1 摘要的原编码，不能通过新 profile 隐式升级旧归档。
interface Identity { id: string; signing: string; receiving: string; archive?: string }
interface VerifiedOriginGraph { authorities: Map<string, IssuerOriginAuthority>; identities: Map<string, Identity>; origins: Map<string, SignedEnvironmentOrigin> }
function contextMatches(identity: Identity, context: PairingContext): boolean {
  return identity.id === context.approverDeviceId && identity.signing === context.approverSigningPublicKey && identity.receiving === context.approverReceivingPublicKey;
}
function boundGrant(signed: SignedGrant, context: PairingContext): void {
  const g = signed.grant;
  if (g.accountId !== context.accountId || g.accountGeneration !== context.accountGeneration || g.issuerDeviceId !== context.approverDeviceId || g.subjectDeviceId !== context.initiatorDeviceId || g.subjectSigningPublicKey !== context.initiatorSigningPublicKey || g.subjectReceivingPublicKey !== context.initiatorReceivingPublicKey || g.grantGeneration !== "1" || g.role === "none") fail();
  verify(context.approverSigningPublicKey, grantBytes(g), signed.signature);
}
/** 这里只核验历史控制面来源；不把历史角色当作当前在线管理权。 */
export function verifyIssuerOriginGraph(proof: IssuerOriginProof): VerifiedOriginGraph {
  issuerOriginCanonical(proof);
  const root: Identity = { id: proof.trustRoot.rootDeviceId, signing: proof.trustRoot.rootSigningPublicKey, receiving: proof.trustRoot.rootReceivingPublicKey };
  const identities = new Map<string, Identity>([[root.id, root]]), usedKeys = new Map<string, string>([[root.signing, root.id], [root.receiving, root.id], [proof.trustRoot.recoverySigningPublicKey, "recovery"], [proof.trustRoot.recoveryReceivingPublicKey, "recovery"]]);
  function walk(path: IssuerOriginEnrollment[]): Identity {
    let current = root; const ids = new Set([root.id]);
    for (const node of path) {
      const context = node.approval.context;
      if (context.accountId !== proof.accountId || context.accountGeneration !== proof.accountGeneration || !contextMatches(current, context) || ids.has(context.initiatorDeviceId)) fail();
      ids.add(context.initiatorDeviceId);
      const fields = canonical(issuerOriginNodeFields(node));
      verify(current.signing, fields, node.approval.approverSignature);
      verify(context.initiatorSigningPublicKey, fields, node.approval.initiatorSignature!);
      for (const grant of node.approval.grants) boundGrant(grant, context);
      const child: Identity = { id: context.initiatorDeviceId, signing: context.initiatorSigningPublicKey, receiving: context.initiatorReceivingPublicKey,
        archive: JSON.stringify([b64(fields), node.approval.approverSignature, node.approval.initiatorSignature]) };
      const previous = identities.get(child.id);
      if (previous && (previous.signing !== child.signing || previous.receiving !== child.receiving || previous.archive !== child.archive)) fail();
      for (const key of [child.signing, child.receiving]) if (usedKeys.has(key) && usedKeys.get(key) !== child.id) fail();
      if (child.signing === child.receiving) fail();
      identities.set(child.id, child); usedKeys.set(child.signing, child.id); usedKeys.set(child.receiving, child.id); current = child;
    }
    return current;
  }
  walk(proof.path); for (const branch of proof.identityPaths) walk(branch);
  const authorities = new Map<string, IssuerOriginAuthority>(), origins = new Map<string, SignedEnvironmentOrigin>();
  const generations = new Map<string, string>(), idempotencies = new Map<string, string>();
  for (const authority of proof.authorities) {
    const signed = authority.grant, g = signed.grant, issuer = identities.get(g.issuerDeviceId), subject = identities.get(g.subjectDeviceId), h = issuerAuthorityHash(signed);
    if (g.accountId !== proof.accountId || g.accountGeneration !== proof.accountGeneration || !issuer || !subject || g.subjectSigningPublicKey !== subject.signing || g.subjectReceivingPublicKey !== subject.receiving) fail();
    verify(issuer.signing, grantBytes(g), signed.signature);
    for (const [map, key] of [[generations, `${g.environmentId}/${g.subjectDeviceId}/${g.grantGeneration}`], [idempotencies, `${g.issuerDeviceId}/${g.idempotencyKey}`]] as const) {
      if (map.has(key) && map.get(key) !== h) fail(); map.set(key, h);
    }
    authorities.set(h, authority);
  }
  for (const node of [...proof.path, ...proof.identityPaths.flat()]) for (const signed of node.approval.grants) {
    const g = signed.grant, h = issuerAuthorityHash(signed);
    for (const [map, key] of [[generations, `${g.environmentId}/${g.subjectDeviceId}/${g.grantGeneration}`], [idempotencies, `${g.issuerDeviceId}/${g.idempotencyKey}`]] as const) {
      if (map.has(key) && map.get(key) !== h) fail(); map.set(key, h);
    }
  }
  for (const origin of proof.origins) {
    const o = origin.origin, actor = identities.get(o.actorDeviceId);
    if (o.accountId !== proof.accountId || o.accountGeneration !== proof.accountGeneration || !actor) fail();
    verify(actor.signing, environmentOriginBytes(o), origin.signature);
    origins.set(environmentOriginHash(origin), origin);
  }
  // 一个已签轮换清单是完整控制快照：不能只验证当前读者那一行。
  // 每行必须有精确签名授权和身份来源；来源证书本身不包含业务密文。
  for (const [originHash, signedOrigin] of origins) {
    const o = signedOrigin.origin;
    for (const row of o.before) {
      const node = authorities.get(row.grantHash);
      if (!node || node.grant.grant.environmentId !== o.environmentId || node.grant.grant.keyVersion !== o.previousKeyVersion || JSON.stringify(rightsFields([row])) !== JSON.stringify(rightsFields([environmentRights(node.grant)]))) fail();
    }
    for (const row of o.after) {
      const node = authorities.get(row.grantHash), previous = o.before.find(prior => prior.subjectDeviceId === row.subjectDeviceId);
      if (!node || node.grant.grant.environmentId !== o.environmentId || node.grant.grant.keyVersion !== o.keyVersion || JSON.stringify(rightsFields([row])) !== JSON.stringify(rightsFields([environmentRights(node.grant)])) || node.originHash !== originHash || node.parentHash !== o.authorityHash || node.previousGrantHash !== (o.operation === "rotate" ? previous?.grantHash : "")) fail();
    }
  }
  function parentMatches(signed: SignedGrant, parent: SignedGrant): boolean {
    const g = signed.grant, p = parent.grant;
    return p.role === "admin" && p.environmentId === g.environmentId && p.keyVersion === g.keyVersion && p.subjectDeviceId === g.issuerDeviceId && within(g.expiresAt, p.expiresAt);
  }
  const visited = new Set<string>(), visiting = new Set<string>();
  function check(h: string): void {
    if (visited.has(h)) return;
    if (visiting.has(h)) fail();
    const node = authorities.get(h); if (!node) fail();
    visiting.add(h); const g = node.grant.grant;
    if (!node.parentHash) {
      if (node.originHash || node.previousGrantHash || g.role !== "admin" || g.issuerDeviceId !== root.id || g.subjectDeviceId !== root.id || g.keyVersion !== "1" || g.grantGeneration !== "1" || g.expiresAt !== "0") fail();
    } else {
      check(node.parentHash); const parent = authorities.get(node.parentHash)!.grant;
      if (!node.originHash) {
        if (node.previousGrantHash || !parentMatches(node.grant, parent)) fail();
      } else {
        const signedOrigin = origins.get(node.originHash); if (!signedOrigin) fail(); const o = signedOrigin.origin, p = parent.grant;
        if (p.role !== "admin" || p.subjectDeviceId !== o.actorDeviceId || p.environmentId !== o.authorityEnvironmentId || p.keyVersion !== o.authorityKeyVersion || p.grantGeneration !== o.authorityGrantGeneration || o.authorityHash !== node.parentHash || g.issuerDeviceId !== o.actorDeviceId || g.environmentId !== o.environmentId || g.keyVersion !== o.keyVersion) fail();
        const after = o.after.find(row => row.subjectDeviceId === g.subjectDeviceId);
        if (!after || JSON.stringify(rightsFields([after])) !== JSON.stringify(rightsFields([environmentRights(node.grant)]))) fail();
        if (o.operation === "create") {
          if (node.previousGrantHash || g.subjectDeviceId !== o.actorDeviceId || g.role !== "admin" || g.grantGeneration !== "1" || !within(g.expiresAt, p.expiresAt)) fail();
        } else {
          check(node.previousGrantHash); const previous = authorities.get(node.previousGrantHash)!.grant;
          const before = o.before.find(row => row.subjectDeviceId === g.subjectDeviceId), actorBefore = o.before.find(row => row.subjectDeviceId === o.actorDeviceId);
          if (!before || !actorBefore || actorBefore.role !== "admin" || actorBefore.grantHash !== node.parentHash || before.grantHash !== node.previousGrantHash || JSON.stringify(rightsFields([before])) !== JSON.stringify(rightsFields([environmentRights(previous)])) || previous.grant.environmentId !== o.environmentId || previous.grant.keyVersion !== o.previousKeyVersion || before.subjectSigningPublicKey !== after.subjectSigningPublicKey || before.subjectReceivingPublicKey !== after.subjectReceivingPublicKey || before.role !== after.role || before.expiresAt !== after.expiresAt || BigInt(after.grantGeneration) !== BigInt(before.grantGeneration) + 1n) fail();
        }
      }
    }
    visiting.delete(h); visited.add(h);
  }
  for (const h of authorities.keys()) check(h);
  // 归档身份链上的授权同样必须有受验证来源，不能仅以双方签名证明管理权。
  for (const node of [...proof.path, ...proof.identityPaths.flat()]) for (const grant of node.approval.grants) {
    const exactNode = authorities.get(issuerAuthorityHash(grant));
    if (exactNode) continue;
    if (![...authorities.values()].some(parent => parentMatches(grant, parent.grant))) fail();
  }
  for (const target of proof.targets) {
    const authority = authorities.get(target.authorityHash);
    if (!authority || authority.grant.grant.environmentId !== target.environmentId) fail();
  }
  return { authorities, identities, origins };
}
export function verifyIssuerOriginProof(certificate: EnrollmentApprovalV3): VerifiedOriginGraph {
  const fields = enrollmentV3Fields(certificate);
  verify(certificate.context.approverSigningPublicKey, canonical(fields), certificate.approverSignature);
  if (certificate.initiatorSignature !== undefined) verify(certificate.context.initiatorSigningPublicKey, canonical(fields), certificate.initiatorSignature);
  const graph = verifyIssuerOriginGraph(certificate.issuerProof), p = certificate.issuerProof;
  const terminal = p.path.at(-1)?.approval.context;
  const current = terminal ? { id: terminal.initiatorDeviceId, signing: terminal.initiatorSigningPublicKey, receiving: terminal.initiatorReceivingPublicKey } : { id: p.trustRoot.rootDeviceId, signing: p.trustRoot.rootSigningPublicKey, receiving: p.trustRoot.rootReceivingPublicKey };
  if (!contextMatches(current, certificate.context) || graph.identities.has(certificate.context.initiatorDeviceId) || [...graph.identities.values()].some(identity => [identity.signing, identity.receiving].some(key => key === certificate.context.initiatorSigningPublicKey || key === certificate.context.initiatorReceivingPublicKey)) || certificate.context.initiatorSigningPublicKey === p.trustRoot.recoverySigningPublicKey || certificate.context.initiatorSigningPublicKey === p.trustRoot.recoveryReceivingPublicKey || certificate.context.initiatorReceivingPublicKey === p.trustRoot.recoverySigningPublicKey || certificate.context.initiatorReceivingPublicKey === p.trustRoot.recoveryReceivingPublicKey) fail();
  if (p.targets.length !== certificate.grants.length) fail();
  const acceptedHashes = new Map<string, string>();
  for (const signed of [...p.authorities.map(node => node.grant), ...p.path.flatMap(node => node.approval.grants), ...p.identityPaths.flat().flatMap(node => node.approval.grants), ...certificate.grants]) {
    const g = signed.grant, h = issuerAuthorityHash(signed);
    for (const key of [`generation/${g.environmentId}/${g.subjectDeviceId}/${g.grantGeneration}`, `idempotency/${g.issuerDeviceId}/${g.idempotencyKey}`]) {
      if (acceptedHashes.has(key) && acceptedHashes.get(key) !== h) fail(); acceptedHashes.set(key, h);
    }
  }
  for (const signed of certificate.grants) {
    boundGrant(signed, certificate.context);
    const g = signed.grant, target = p.targets.find(item => item.environmentId === g.environmentId), parent = target && graph.authorities.get(target.authorityHash)?.grant.grant;
    if (!parent || parent.role !== "admin" || parent.subjectDeviceId !== g.issuerDeviceId || parent.keyVersion !== g.keyVersion || !within(g.expiresAt, parent.expiresAt)) fail();
  }
  return graph;
}
/** 单账号事务：历史逐字匹配，与本次目标的当前权限分别检查。 */
/** 新来源能力只接受原双签初始化固定的精确初始授权，缺记录不能回退。 */
function initialAuthorityHashes(account: EnrollmentAccount): Set<string> {
  const original = originalInitialization(account);
  if (!original) fail("initialization_evidence_required");
  return new Set(original.proposal.environments.map(environment => issuerAuthorityHash(environment.grant)));
}
/** 精确已接受历史只证明来源；不检查当前设备角色，也不赋予当前在线权限。 */
function acceptedIssuerHistory(account: EnrollmentAccount, proof: IssuerOriginProof, graph: VerifiedOriginGraph, initial: Set<string>): void {
  const root = account.trustRoot;
  if (!root || root.rootDeviceId !== proof.trustRoot.rootDeviceId || root.rootSigningPublicKey !== proof.trustRoot.rootSigningPublicKey || root.rootReceivingPublicKey !== proof.trustRoot.rootReceivingPublicKey) fail();
  for (const node of [...proof.path, ...proof.identityPaths.flat()]) {
    const stored = own(account.deviceEnrollments, node.approval.context.initiatorDeviceId);
    if (!stored || JSON.stringify(issuerOriginNodeFields(archivedOriginEnrollment(stored))) !== JSON.stringify(issuerOriginNodeFields(node)) || stored.approverSignature !== node.approval.approverSignature || stored.initiatorSignature !== node.approval.initiatorSignature) fail("issuer_archive_mismatch");
  }
  for (const [h, origin] of graph.origins) {
    const found = account.environmentHistory?.find(event => event.origin && environmentOriginHash(event.origin) === h);
    if (found && (environmentChangeHash(environmentChangeBytes(found.change.change), found.change.signature) !== origin.origin.changeHash || JSON.stringify(rightsFields(found.change.change.grants.map(environmentRights).sort((first, second) => compare(first.subjectDeviceId, second.subjectDeviceId)))) !== JSON.stringify(rightsFields(origin.origin.after)))) fail("issuer_origin_unaccepted");
    if (found) {
      const c = found.change.change, o = origin.origin;
      const bindings = [[o.accountId, c.accountId], [o.accountGeneration, c.accountGeneration], [o.actorDeviceId, c.deviceId], [o.environmentId, c.environmentId], [o.operation, c.operation], [o.authorityEnvironmentId, c.authorityEnvironmentId], [o.authorityKeyVersion, c.authorityKeyVersion], [o.authorityGrantGeneration, c.authorityGrantGeneration], [o.previousKeyVersion, c.previousKeyVersion], [o.keyVersion, c.keyVersion], [o.expectedSequence, c.expectedSequence], [o.idempotencyKey, c.idempotencyKey]];
      if (bindings.some(([first, second]) => first !== second)) fail("issuer_origin_unaccepted");
      verify(graph.identities.get(o.actorDeviceId)!.signing, environmentChangeBytes(c), found.change.signature);
    }
    if (!found || JSON.stringify(environmentOriginBytes(found.origin!.origin)) !== JSON.stringify(environmentOriginBytes(origin.origin)) || found.origin!.signature !== origin.signature || found.sequence !== Number(BigInt(origin.origin.expectedSequence) + 1n) || issuerAuthorityHash(found.authorization) !== origin.origin.authorityHash) fail("issuer_origin_unaccepted");
  }
  for (const [h, node] of graph.authorities) {
    const found = account.grantHistory?.find(event => issuerAuthorityHash(event.grant) === h);
    if (!found) fail("issuer_authority_unaccepted");
    if (node.originHash) {
      const acceptedOrigin = account.environmentHistory?.find(event => event.origin && environmentOriginHash(event.origin) === node.originHash);
      const parent = account.grantHistory?.find(event => issuerAuthorityHash(event.grant) === node.parentHash);
      const previous = node.previousGrantHash ? account.grantHistory?.find(event => issuerAuthorityHash(event.grant) === node.previousGrantHash) : undefined;
      if (found.originHash !== node.originHash || !found.authorization || issuerAuthorityHash(found.authorization) !== node.parentHash || !acceptedOrigin || found.sequence !== acceptedOrigin.sequence || !parent || parent.sequence >= found.sequence || node.previousGrantHash && (!previous || previous.sequence >= found.sequence)) fail("issuer_authority_parent_mismatch");
    } else if (!node.parentHash) {
      if (found.authorization !== null || found.originHash || !initial.has(h)) fail("issuer_environment_evidence_required");
    } else if (found.originHash || !found.authorization || issuerAuthorityHash(found.authorization) !== node.parentHash) fail("issuer_authority_parent_mismatch");
  }
}
export function issuerOriginStillCurrent(account: EnrollmentAccount, certificate: EnrollmentApprovalV3): void {
  const graph = verifyIssuerOriginProof(certificate), proof = certificate.issuerProof;
  acceptedIssuerHistory(account, proof, graph, initialAuthorityHashes(account));
  for (const target of proof.targets) {
    const current = own(account.grants, grantKey(target.environmentId, certificate.context.approverDeviceId));
    if (!current || issuerAuthorityHash(current) !== target.authorityHash) fail("issuer_authority_changed");
  }
}

/** 按显式控制目标与必要历史身份构造依赖闭包；候选不能替代客户端已保护的根 pin。 */
export function buildIssuerEvidence(account: EnrollmentAccount, deviceId: string, grants: SignedGrant[], targets: SignedGrant[] = grants, identityIds: string[] = []): IssuerOriginProof | null {
  if (!grants.length) return null;
  const root = account.trustRoot; if (!root) fail("trust_root_required");
  const initial = initialAuthorityHashes(account);
  const authorities = new Map<string, IssuerOriginAuthority>(), origins = new Map<string, SignedEnvironmentOrigin>();
  const identityPaths = new Map<string, IssuerOriginEnrollment[]>(), inProgress = new Set<string>(), expandedOrigins = new Set<string>();
  function identityPath(id: string, stack = new Set<string>()): IssuerOriginEnrollment[] {
    if (id === root!.rootDeviceId) return [];
    const prior = identityPaths.get(id); if (prior) return prior;
    if (stack.has(id)) fail(); stack.add(id);
    const archive = own(account.deviceEnrollments, id); if (!archive || !archive.initiatorSignature) fail("issuer_archive_mismatch");
    const path = [...identityPath(archive.context.approverDeviceId, stack), archivedOriginEnrollment(archive)];
    identityPaths.set(id, path); stack.delete(id); return path;
  }
  function source(signed: SignedGrant): void {
    const h = issuerAuthorityHash(signed); if (authorities.has(h)) return;
    if (inProgress.has(h)) fail(); inProgress.add(h);
    const accepted = account.grantHistory?.find(row => issuerAuthorityHash(row.grant) === h);
    if (!accepted) fail("issuer_authority_unaccepted");
    if (!accepted.authorization && (accepted.originHash || !initial.has(h))) fail("issuer_environment_evidence_required");
    identityPath(signed.grant.issuerDeviceId); identityPath(signed.grant.subjectDeviceId);
    const node: IssuerOriginAuthority = { grant: structuredClone(signed), parentHash: "", originHash: "", previousGrantHash: "" };
    if (accepted.authorization) { node.parentHash = issuerAuthorityHash(accepted.authorization); source(accepted.authorization); }
    if (accepted.originHash) {
      const event = account.environmentHistory?.find(event => event.origin && environmentOriginHash(event.origin) === accepted.originHash);
      if (!event?.origin) fail("issuer_origin_unaccepted");
      node.originHash = accepted.originHash; origins.set(node.originHash, structuredClone(event.origin));
      if (event.origin.origin.operation === "rotate") {
        const before = event.origin.origin.before.find(row => row.subjectDeviceId === signed.grant.subjectDeviceId);
        const previous = before && account.grantHistory?.find(row => issuerAuthorityHash(row.grant) === before.grantHash);
        if (!before || !previous) fail("issuer_authority_unaccepted");
        node.previousGrantHash = before.grantHash; source(previous.grant);
      }
    }
    authorities.set(h, node); inProgress.delete(h);
    if (node.originHash && !expandedOrigins.has(node.originHash)) {
      // 先登记当前节点和来源，再扩完整清单，避免同一来源的并列新授权互相递归。
      // 所有完整授权只能取自已接受历史，不能由清单行或目录补造。
      expandedOrigins.add(node.originHash);
      const origin = origins.get(node.originHash)!.origin;
      for (const row of [...origin.before, ...origin.after]) {
        const historical = account.grantHistory?.find(event => issuerAuthorityHash(event.grant) === row.grantHash);
        if (!historical) fail("issuer_authority_unaccepted");
        source(historical.grant);
      }
    }
  }
  const path = identityPath(deviceId);
  for (const id of identityIds) identityPath(id);
  for (const grant of grants) source(grant);
  // 身份归档里的全部受签授权同样需要闭包。新增身份可能增加分支，迭代直到收敛。
  let processed = 0;
  while (processed < identityPaths.size) {
    const branches = [...identityPaths.values()];
    for (; processed < branches.length; processed++) for (const node of branches[processed]!) for (const grant of node.approval.grants) source(grant);
  }
  const main = JSON.stringify(pathRows(path)), branches = [...identityPaths.values()].filter(branch => JSON.stringify(pathRows(branch)) !== main);
  // 去掉被另一条路径精确包含的前缀，减少相同归档引用。
  const leaves = branches.filter(branch => !branches.some(other => other.length > branch.length && JSON.stringify(pathRows(other.slice(0, branch.length))) === JSON.stringify(pathRows(branch))));
  const proof: IssuerOriginProof = { profile: "harmonia/issuer-proof/v2", accountId: account.id, accountGeneration: account.generation, trustRoot: structuredClone(root),
    path: structuredClone(path), authorities: [...authorities.values()], targets: targets.map(grant => ({ environmentId: grant.grant.environmentId, authorityHash: issuerAuthorityHash(grant) })),
    origins: [...origins.values()], identityPaths: structuredClone(leaves) };
  acceptedIssuerHistory(account, proof, verifyIssuerOriginGraph(proof), initial);
  return proof;
}

/**
 * 受限恢复已证明持恢复钥；图仅核验历史来源，不要求任一设备当前存活或Admin。
 * 每个target只是现存环境当前keyVersion的历史验证入口，不是新设备授权。
 */
export function buildRecoveryIssuerEvidence(account: EnrollmentAccount): IssuerOriginProof | null {
  const original = originalInitialization(account);
  if (!original) return null;
  const environments = Object.values(account.environments).sort((first, second) => compare(first.id, second.id));
  if (!environments.length) return null;
  const current = Object.values(account.grants).filter(signed => {
    const g = signed.grant;
    return g.accountGeneration === account.generation && g.role !== "none" && account.environments[g.environmentId]?.keyVersion === g.keyVersion;
  });
  const sources = [...original.proposal.environments.map(environment => environment.grant), ...current];
  const targets: SignedGrant[] = [];
  for (const environment of environments) {
    const candidates = current.filter(signed => signed.grant.environmentId === environment.id);
    if (!candidates.length) {
      // 全部设备撤销或currentGrants均none时，保留的精确历史仍可证明数据来源。
      const historical = (account.grantHistory ?? []).filter(event => {
        const g = event.grant.grant;
        return g.accountGeneration === account.generation && g.environmentId === environment.id && g.keyVersion === environment.keyVersion && g.role !== "none";
      }).sort((first, second) => second.sequence - first.sequence || compare(issuerAuthorityHash(first.grant), issuerAuthorityHash(second.grant)));
      if (historical[0]) candidates.push(historical[0].grant);
    }
    if (!candidates.length) fail("issuer_authority_unaccepted");
    candidates.sort((first, second) => compare(issuerAuthorityHash(first), issuerAuthorityHash(second)));
    targets.push(candidates[0]!); sources.push(candidates[0]!);
  }
  for (const event of account.events) {
    const m = event.mutation.mutation;
    if (account.environments[m.environmentId]?.keyVersion !== m.keyVersion) continue;
    const g = event.authorization.grant;
    if (m.accountId !== account.id || m.accountGeneration !== account.generation || g.accountId !== account.id || g.accountGeneration !== account.generation || g.subjectDeviceId !== m.deviceId || g.environmentId !== m.environmentId || g.keyVersion !== m.keyVersion || g.grantGeneration !== m.grantGeneration || (g.role !== "rw" && g.role !== "admin")) fail("mutation_binding_invalid");
    verify(g.subjectSigningPublicKey, mutationBytes(m), event.mutation.signature);
    sources.push(event.authorization);
  }
  return buildIssuerEvidence(account, original.proposal.device.id, sources, targets);
}

/** 对独立业务包的精确历史来源核验，不构造占位审批证书，不授当前角色。 */
export function verifyAcceptedIssuerOriginEvidence(account: EnrollmentAccount, proof: IssuerOriginProof): ReturnType<typeof verifyIssuerOriginGraph> {
  if (proof.accountId !== account.id || proof.accountGeneration !== account.generation) fail("account_binding_invalid");
  const graph = verifyIssuerOriginGraph(proof);
  acceptedIssuerHistory(account, proof, graph, initialAuthorityHashes(account));
  return graph;
}
