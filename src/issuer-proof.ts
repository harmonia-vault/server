import { sha256 } from "@noble/hashes/sha2.js";
import { Fault, grantKey, type SignedGrant } from "./model.js";
import { bytes, generation, grantBytes, identifier, verify } from "./protocol.js";
import { canonical, enrollmentFields, exact, hash, own, type EnrollmentAccount, type EnrollmentCertificate, type PairingContext } from "./enrollment-wire.js";
import { trustRootPayload, validateTrustRoot, type TrustRoot } from "./trust-root.js";
export const issuerProofCapability = "issuer-proof-v1";
export const maxIssuerProofBytes = 262144;
export interface IssuerEnrollment {
  certificateVersion: "1" | "2";
  issuerProofHash: string;
  approval: EnrollmentCertificate;
}
export interface IssuerAuthority {
  grant: SignedGrant;
  parentHash: string;
}
export interface IssuerProof {
  profile: "harmonia/issuer-proof/v1";
  accountId: string;
  accountGeneration: string;
  trustRoot: TrustRoot;
  path: IssuerEnrollment[];
  authorities: IssuerAuthority[];
  targets: {
    environmentId: string;
    authorityHash: string;
  }[];
}
export interface EnrollmentApprovalV2 extends EnrollmentCertificate {
  certificateVersion: "2";
  issuerProof: IssuerProof;
}
function b64(v: Uint8Array): string {
  return Buffer.from(v).toString("base64url");
}
function digest(v: Uint8Array): string {
  return Buffer.from(sha256(v)).toString("hex");
}
function hex(v: string): void {
  if (typeof v !== "string" || !/^[0-9a-f]{64}$/.test(v))
    throw new Fault(400, "issuer_proof_invalid");
}
function fail(): never {
  throw new Fault(403, "issuer_proof_invalid");
}
function compareText(a: string, b: string): number {
  if (a < b)
    return -1;
  if (a > b)
    return 1;
  return 0;
}
function compareAuthorities(a: IssuerAuthority, b: IssuerAuthority): number {
  const first = a.grant.grant, second = b.grant.grant;
  const environmentOrder = compareText(first.environmentId, second.environmentId);
  if (environmentOrder)
    return environmentOrder;
  const subjectOrder = compareText(first.subjectDeviceId, second.subjectDeviceId);
  if (subjectOrder)
    return subjectOrder;
  const firstGeneration = BigInt(first.grantGeneration), secondGeneration = BigInt(second.grantGeneration);
  if (firstGeneration < secondGeneration)
    return -1;
  if (firstGeneration > secondGeneration)
    return 1;
  return 0;
}
function expiry(value: string): bigint {
  if (value !== "0")
    generation(value);
  const n = BigInt(value);
  if (n > 253402300799n)
    throw new Fault(400, "expiry_invalid");
  return n;
}
function within(child: string, parent: string): boolean {
  const c = expiry(child), p = expiry(parent);
  return p === 0n || (c !== 0n && c <= p);
}
function context(c: PairingContext): void {
  exact(c, ["accountId", "accountGeneration", "purpose", "sessionId", "challengeNonce", "expiresAt", "initiatorDeviceId", "initiatorSigningPublicKey", "initiatorReceivingPublicKey", "approverDeviceId", "approverSigningPublicKey", "approverReceivingPublicKey"]);
  for (const id of [c.accountId, c.sessionId, c.initiatorDeviceId, c.approverDeviceId])
    identifier(id);
  generation(c.accountGeneration);
  generation(c.expiresAt);
  expiry(c.expiresAt);
  bytes(c.challengeNonce, 32);
  for (const key of [c.initiatorSigningPublicKey, c.initiatorReceivingPublicKey, c.approverSigningPublicKey, c.approverReceivingPublicKey])
    bytes(key, 32);
  if (c.purpose !== "enroll-device" || c.initiatorDeviceId === c.approverDeviceId || c.initiatorSigningPublicKey === c.initiatorReceivingPublicKey || c.approverSigningPublicKey === c.approverReceivingPublicKey)
    fail();
}
function strictCertificate(c: EnrollmentCertificate, completed: boolean): void {
  exact(c, ["context", "pairingProfile", "transcriptHash", "grants", "approverSignature", ...(Object.hasOwn(c ?? {}, "initiatorSignature") ? ["initiatorSignature"] : [])]);
  context(c.context);
  enrollmentFields(c);
  bytes(c.approverSignature, 64);
  if (completed || c.initiatorSignature !== undefined)
    bytes(c.initiatorSignature!, 64);
}
export function issuerAuthorityHash(s: SignedGrant): string {
  exact(s, ["grant", "signature"]);
  bytes(s.signature, 64);
  return hash(["harmonia/issuer-authority/v1", b64(grantBytes(s.grant)), s.signature]);
}
export function issuerNodeFields(n: IssuerEnrollment): string[] {
  exact(n, ["certificateVersion", "issuerProofHash", "approval"]);
  strictCertificate(n.approval, true);
  const fields = enrollmentFields(n.approval);
  if (n.certificateVersion === "1") {
    if (n.issuerProofHash !== "")
      fail();
    return fields;
  }
  if (n.certificateVersion !== "2")
    fail();
  hex(n.issuerProofHash);
  fields[0] = "harmonia/device-enrollment/v2";
  return [...fields, n.issuerProofHash];
}
export function issuerProofCanonical(p: IssuerProof): Uint8Array {
  exact(p, ["profile", "accountId", "accountGeneration", "trustRoot", "path", "authorities", "targets"]);
  identifier(p.accountId);
  generation(p.accountGeneration);
  if (p.profile !== "harmonia/issuer-proof/v1" || !Array.isArray(p.path) || p.path.length > 32 || !Array.isArray(p.authorities) || p.authorities.length < 1 || p.authorities.length > 256 || !Array.isArray(p.targets) || p.targets.length < 1 || p.targets.length > 256)
    throw new Fault(400, "issuer_proof_invalid");
  validateTrustRoot(p.accountId, p.accountGeneration, p.trustRoot);
  const path = p.path.map(n => [n.certificateVersion, b64(canonical(issuerNodeFields(n))), n.approval.approverSignature, n.approval.initiatorSignature!]);
  for (const a of p.authorities) {
    exact(a, ["grant", "parentHash"]);
    issuerAuthorityHash(a.grant);
    if (a.grant.grant.role !== "admin")
      fail();
    if (a.parentHash !== "")
      hex(a.parentHash);
  }
  const seen = new Set<string>();
  const authorities = [...p.authorities].sort(compareAuthorities).map(a => {
    const g = a.grant.grant, key = `${g.environmentId}/${g.subjectDeviceId}/${g.grantGeneration}`;
    if (seen.has(key))
      fail();
    seen.add(key);
    return [g.environmentId, g.subjectDeviceId, g.grantGeneration, b64(grantBytes(g)), a.grant.signature, a.parentHash];
  });
  const targetIds = new Set<string>();
  const targets = [...p.targets].map(t => {
    exact(t, ["environmentId", "authorityHash"]);
    identifier(t.environmentId);
    hex(t.authorityHash);
    return t;
  }).sort((a, b) => compareText(a.environmentId, b.environmentId)).map(t => {
    if (targetIds.has(t.environmentId))
      fail();
    targetIds.add(t.environmentId);
    return [t.environmentId, t.authorityHash];
  });
  const result = canonical([p.profile, p.accountId, p.accountGeneration, [b64(canonical(trustRootPayload(p.accountId, p.accountGeneration, p.trustRoot))), p.trustRoot.signature], path, authorities, targets]);
  if (result.length > maxIssuerProofBytes)
    throw new Fault(413, "issuer_proof_too_large");
  return result;
}
export function issuerProofHash(p: IssuerProof): string {
  return digest(issuerProofCanonical(p));
}
export function enrollmentV2Fields(c: EnrollmentApprovalV2): string[] {
  exact(c, ["certificateVersion", "context", "pairingProfile", "transcriptHash", "grants", "issuerProof", "approverSignature", ...(Object.hasOwn(c ?? {}, "initiatorSignature") ? ["initiatorSignature"] : [])]);
  context(c.context);
  const proofHash = issuerProofHash(c.issuerProof);
  if (c.certificateVersion !== "2" || c.issuerProof.accountId !== c.context.accountId || c.issuerProof.accountGeneration !== c.context.accountGeneration)
    fail();
  const fields = enrollmentFields(c);
  fields[0] = "harmonia/device-enrollment/v2";
  return [...fields, proofHash];
}
export function archivedIssuerEnrollment(c: EnrollmentCertificate | EnrollmentApprovalV2): IssuerEnrollment {
  const approval: EnrollmentCertificate = { context: structuredClone(c.context), pairingProfile: c.pairingProfile, transcriptHash: c.transcriptHash, grants: structuredClone(c.grants), approverSignature: c.approverSignature, ...(c.initiatorSignature ? { initiatorSignature: c.initiatorSignature } : {}) };
  return "certificateVersion" in c ? { certificateVersion: "2", issuerProofHash: issuerProofHash(c.issuerProof), approval } : { certificateVersion: "1", issuerProofHash: "", approval };
}
interface Identity {
  id: string;
  signing: string;
  receiving: string;
}
const match = (i: Identity, c: PairingContext): boolean => i.id === c.approverDeviceId && i.signing === c.approverSigningPublicKey && i.receiving === c.approverReceivingPublicKey;
/** 历史签名只证明来源；当前授权检查由事务内调用者另做。 */
export function verifyIssuerProof(c: EnrollmentApprovalV2): Map<string, IssuerAuthority> {
  const p = c.issuerProof, fields = enrollmentV2Fields(c);
  verify(c.context.approverSigningPublicKey, canonical(fields), c.approverSignature);
  if (c.initiatorSignature !== undefined)
    verify(c.context.initiatorSigningPublicKey, canonical(fields), c.initiatorSignature);
  const root: Identity = { id: p.trustRoot.rootDeviceId, signing: p.trustRoot.rootSigningPublicKey, receiving: p.trustRoot.rootReceivingPublicKey };
  const identities = new Map<string, Identity>(), used = new Set([p.trustRoot.recoverySigningPublicKey, p.trustRoot.recoveryReceivingPublicKey]);
  function add(i: Identity): void {
    if (identities.has(i.id) || used.has(i.signing) || used.has(i.receiving) || i.signing === i.receiving)
      fail();
    identities.set(i.id, i);
    used.add(i.signing);
    used.add(i.receiving);
  }
  add(root);
  let current = root;
  const generations = new Map<string, string>(), idempotencies = new Map<string, string>();
  const allGrants = [...p.path.flatMap(n => n.approval.grants), ...p.authorities.map(a => a.grant), ...c.grants];
  for (const signed of allGrants) {
    const g = signed.grant, h = issuerAuthorityHash(signed);
    if (g.accountId !== p.accountId || g.accountGeneration !== p.accountGeneration)
      fail();
    for (const [map, key] of [[generations, `${g.environmentId}/${g.subjectDeviceId}/${g.grantGeneration}`], [idempotencies, `${g.issuerDeviceId}/${g.idempotencyKey}`]] as const) {
      if (map.has(key) && map.get(key) !== h)
        fail();
      map.set(key, h);
    }
  }
  for (const n of p.path) {
    const old = n.approval.context;
    if (old.accountId !== p.accountId || old.accountGeneration !== p.accountGeneration || !match(current, old))
      fail();
    const bytes = canonical(issuerNodeFields(n));
    verify(current.signing, bytes, n.approval.approverSignature);
    const child = { id: old.initiatorDeviceId, signing: old.initiatorSigningPublicKey, receiving: old.initiatorReceivingPublicKey };
    add(child);
    verify(child.signing, bytes, n.approval.initiatorSignature!);
    validateEnrollmentGrants(n.approval);
    current = child;
  }
  if (!match(current, c.context) || identities.has(c.context.initiatorDeviceId) || used.has(c.context.initiatorSigningPublicKey) || used.has(c.context.initiatorReceivingPublicKey))
    fail();
  const authorities = new Map<string, IssuerAuthority>();
  for (const a of p.authorities) {
    const g = a.grant.grant, s = identities.get(g.subjectDeviceId), issuer = identities.get(g.issuerDeviceId);
    if (!s || !issuer || g.subjectSigningPublicKey !== s.signing || g.subjectReceivingPublicKey !== s.receiving)
      fail();
    verify(issuer.signing, grantBytes(g), a.grant.signature);
    expiry(g.expiresAt);
    const h = issuerAuthorityHash(a.grant);
    if (authorities.has(h))
      fail();
    authorities.set(h, a);
  }
  function matchesDelegation(s: SignedGrant, h: string): boolean {
    const parent = authorities.get(h)?.grant.grant, g = s.grant;
    return !!parent && parent.environmentId === g.environmentId && parent.keyVersion === g.keyVersion && parent.subjectDeviceId === g.issuerDeviceId && within(g.expiresAt, parent.expiresAt);
  }
  function delegated(s: SignedGrant, h: string): void {
    if (!matchesDelegation(s, h))
      fail();
    verify(authorities.get(h)!.grant.grant.subjectSigningPublicKey, grantBytes(s.grant), s.signature);
  }
  const visited = new Set<string>(), visiting = new Set<string>();
  function check(h: string): void {
    if (visited.has(h))
      return;
    if (visiting.has(h))
      fail();
    const a = authorities.get(h);
    if (!a)
      fail();
    visiting.add(h);
    const g = a.grant.grant;
    if (a.parentHash === "") {
      if (g.issuerDeviceId !== root.id || g.subjectDeviceId !== root.id || g.subjectSigningPublicKey !== root.signing || g.subjectReceivingPublicKey !== root.receiving)
        fail();
    }
    else {
      check(a.parentHash);
      delegated(a.grant, a.parentHash);
    }
    visiting.delete(h);
    visited.add(h);
  }
  for (const h of authorities.keys())
    check(h);
  for (const n of p.path)
    for (const g of n.approval.grants) {
      const source = [...authorities.keys()].find(h => matchesDelegation(g, h));
      if (!source)
        fail();
      delegated(g, source);
    }
  validateEnrollmentGrants(c);
  if (p.targets.length !== c.grants.length)
    fail();
  for (const g of c.grants) {
    const target = p.targets.find(t => t.environmentId === g.grant.environmentId);
    if (!target)
      fail();
    delegated(g, target.authorityHash);
  }
  return authorities;
}
function validateEnrollmentGrants(c: EnrollmentCertificate): void {
  for (const s of c.grants) {
    const g = s.grant, x = c.context;
    if (g.accountId !== x.accountId || g.accountGeneration !== x.accountGeneration || g.issuerDeviceId !== x.approverDeviceId || g.subjectDeviceId !== x.initiatorDeviceId || g.subjectSigningPublicKey !== x.initiatorSigningPublicKey || g.subjectReceivingPublicKey !== x.initiatorReceivingPublicKey || g.grantGeneration !== "1" || g.role === "none" || g.subjectSigningPublicKey === g.subjectReceivingPublicKey)
      fail();
    verify(x.approverSigningPublicKey, grantBytes(g), s.signature);
  }
}
/** 单账号权威事务中运行：归档来源与当前目标授权缺一不可。 */
export function issuerProofStillCurrent(a: EnrollmentAccount, c: EnrollmentApprovalV2): void {
  const authorities = verifyIssuerProof(c), root = a.trustRoot, p = c.issuerProof;
  if (!root || root.rootDeviceId !== p.trustRoot.rootDeviceId || root.rootSigningPublicKey !== p.trustRoot.rootSigningPublicKey || root.rootReceivingPublicKey !== p.trustRoot.rootReceivingPublicKey)
    fail();
  for (const n of p.path) {
    const stored = own(a.deviceEnrollments, n.approval.context.initiatorDeviceId);
    if (!stored || JSON.stringify(issuerNodeFields(archivedIssuerEnrollment(stored))) !== JSON.stringify(issuerNodeFields(n)) || stored.approverSignature !== n.approval.approverSignature || stored.initiatorSignature !== n.approval.initiatorSignature)
      throw new Fault(403, "issuer_archive_mismatch");
  }
  for (const [h, authority] of authorities) {
    const found = a.grantHistory?.find(row => issuerAuthorityHash(row.grant) === h);
    if (!found)
      throw new Fault(403, "issuer_authority_unaccepted");
    if (authority.parentHash === "") {
      if (found.authorization !== null)
        throw new Fault(403, "issuer_environment_evidence_required");
    }
    else if (!found.authorization || issuerAuthorityHash(found.authorization) !== authority.parentHash)
      throw new Fault(403, "issuer_authority_parent_mismatch");
  }
  for (const target of p.targets) {
    const current = own(a.grants, grantKey(target.environmentId, c.context.approverDeviceId));
    if (!current || issuerAuthorityHash(current) !== target.authorityHash)
      throw new Fault(403, "issuer_authority_changed");
  }
}
