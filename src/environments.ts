import { buildIssuerRecoveryDAGEvidence, type RecoveryDAGAccount } from "./recovery-dag-account.js";
import type { IssuerRecoveryDAG } from "./recovery-dag-wire.js";
import { environmentChangeHash, environmentOriginBytes, environmentOriginHash, environmentRights, rightsFields, type SignedEnvironmentOrigin } from "./environment-origin.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { Fault, grantKey, type Account, type Auth, type SignedGrant, type SignedMutation } from "./model.js";
import { bytes, generation, grantBytes, identifier, mutationBytes, verify } from "./protocol.js";
import { device, next, permission, randomToken, sameAccount, session, tokenHash } from "./service.js";
import type { Store } from "./store.js";
export interface EnvironmentChange {
  accountId: string; accountGeneration: string; deviceId: string; environmentId: string;
  operation: "create" | "rename" | "delete" | "rotate";
  authorityEnvironmentId: string; authorityKeyVersion: string; authorityGrantGeneration: string;
  previousKeyVersion: string; keyVersion: string; expectedSequence: string; idempotencyKey: string;
  labelPayload: string; recoveryGeneration: string; recoveryEnvelope: string;
  grants: SignedGrant[]; mutations: SignedMutation[];
}
export interface SignedEnvironmentChange { change: EnvironmentChange; signature: string }
export interface SignedEnvironmentChangeV2 extends SignedEnvironmentChange { origin: SignedEnvironmentOrigin }
export interface EnvironmentEvent {
  sequence: number; change: SignedEnvironmentChange; authorization: SignedGrant; subjects: string[]; origin?: SignedEnvironmentOrigin;
}
export interface RevocationAuthority { environmentId: string; keyVersion: string; grantGeneration: string }
export interface DeviceRevocation {
  accountId: string; accountGeneration: string; deviceId: string; subjectDeviceId: string;
  subjectSigningPublicKey: string; subjectReceivingPublicKey: string; idempotencyKey: string;
  challengeId: string; sessionHash: string; nonce: string; expiresAt: string; authorities: RevocationAuthority[];
}
export interface SignedDeviceRevocation { revocation: DeviceRevocation; signature: string }
export interface RevocationRecord {
  revocation: DeviceRevocation; authorizations: SignedGrant[]; signature?: string; sequence?: number;
}
export interface EnvironmentAccount extends Account {
  environmentHistory?: EnvironmentEvent[];
  deletedEnvironmentIds?: Record<string, string>;
  environmentLabels?: Record<string, string>;
  deviceRevocations?: Record<string, RevocationRecord>;
}
function exact(v: unknown, names: string[]): asserts v is Record<string, unknown> {
  if (!v || typeof v !== "object" || Array.isArray(v) || Object.keys(v).sort().join("|") !== [...names].sort().join("|")) throw new Fault(400, "fields_invalid");
}
function decimal(v: string, positive = false): void {
  if (positive || v !== "0") generation(v);
  if (typeof v !== "string") throw new Fault(400, "generation_invalid");
}
const canonical = (fields: string[]): Uint8Array => new TextEncoder().encode(JSON.stringify(fields));
const hash = (value: unknown): string => Buffer.from(sha256(new TextEncoder().encode(JSON.stringify(value)))).toString("hex");
function boundedCiphertext(v: string, empty = false): void {
  const value = bytes(v); if (!(empty && !value.length) && (value.length < 40 || value.length > 65576)) throw new Fault(400, "payload_invalid");
}
export function environmentGrantsHash(grants: SignedGrant[]): string {
  if (!Array.isArray(grants) || grants.length > 256) throw new Fault(400, "grants_invalid");
  const seen = new Set<string>();
  const sorted = [...grants].sort((a, b) => String(a?.grant?.subjectDeviceId) < String(b?.grant?.subjectDeviceId) ? -1 : String(a?.grant?.subjectDeviceId) > String(b?.grant?.subjectDeviceId) ? 1 : 0);
  return hash(sorted.map(s => {
    exact(s, ["grant", "signature"]); const encoded = grantBytes(s.grant); bytes(s.signature, 64);
    if (seen.has(s.grant.subjectDeviceId)) throw new Fault(400, "grant_duplicate"); seen.add(s.grant.subjectDeviceId);
    return [s.grant.subjectDeviceId, Buffer.from(encoded).toString("base64url"), s.signature];
  }));
}
export function environmentMutationsHash(mutations: SignedMutation[]): string {
  if (!Array.isArray(mutations) || mutations.length > 1024) throw new Fault(400, "mutations_invalid");
  const seen = new Set<string>();
  const sorted = [...mutations].sort((a, b) => String(a?.mutation?.name) < String(b?.mutation?.name) ? -1 : String(a?.mutation?.name) > String(b?.mutation?.name) ? 1 : 0);
  return hash(sorted.map(s => {
    exact(s, ["mutation", "signature"]); const encoded = mutationBytes(s.mutation); bytes(s.signature, 64);
    if (seen.has(s.mutation.name)) throw new Fault(400, "mutation_duplicate"); seen.add(s.mutation.name);
    return [s.mutation.name, Buffer.from(encoded).toString("base64url"), s.signature];
  }));
}
export function environmentChangeBytes(c: EnvironmentChange): Uint8Array {
  exact(c, ["accountId", "accountGeneration", "deviceId", "environmentId", "operation", "authorityEnvironmentId", "authorityKeyVersion", "authorityGrantGeneration", "previousKeyVersion", "keyVersion", "expectedSequence", "idempotencyKey", "labelPayload", "recoveryGeneration", "recoveryEnvelope", "grants", "mutations"]);
  for (const v of [c.accountId, c.deviceId, c.environmentId, c.authorityEnvironmentId, c.idempotencyKey]) identifier(v);
  for (const v of [c.accountGeneration, c.authorityKeyVersion, c.authorityGrantGeneration, c.keyVersion, c.recoveryGeneration]) generation(v);
  decimal(c.previousKeyVersion); decimal(c.expectedSequence);
  if (!Number.isSafeInteger(Number(c.expectedSequence))) throw new Fault(400, "checkpoint_invalid");
  if (!["create", "rename", "delete", "rotate"].includes(c.operation)) throw new Fault(400, "operation_invalid");
  boundedCiphertext(c.labelPayload, c.operation === "delete" || c.operation === "rotate");
  if (c.operation === "create" || c.operation === "rotate") bytes(c.recoveryEnvelope, 80);
  else if (c.recoveryEnvelope !== "") throw new Fault(400, "envelope_invalid");
  if (!Array.isArray(c.grants) || !Array.isArray(c.mutations)) throw new Fault(400, "manifest_invalid");
  if ((c.operation === "rename" || c.operation === "delete") && (c.grants.length || c.mutations.length)) throw new Fault(400, "manifest_invalid");
  return canonical(["harmonia/environment-change/v1", c.accountId, c.accountGeneration, c.deviceId, c.environmentId, c.operation,
    c.authorityEnvironmentId, c.authorityKeyVersion, c.authorityGrantGeneration, c.previousKeyVersion, c.keyVersion,
    c.expectedSequence, c.idempotencyKey, c.labelPayload, c.recoveryGeneration, c.recoveryEnvelope,
    environmentGrantsHash(c.grants), environmentMutationsHash(c.mutations)]);
}
export function revocationAuthorityHash(authorities: RevocationAuthority[]): string {
  if (!Array.isArray(authorities) || !authorities.length || authorities.length > 256) throw new Fault(400, "authorities_invalid");
  const seen = new Set<string>();
  for (const a of authorities) exact(a, ["environmentId", "keyVersion", "grantGeneration"]);
  const sorted = [...authorities].sort((a, b) => a.environmentId < b.environmentId ? -1 : a.environmentId > b.environmentId ? 1 : 0);
  return hash(sorted.map(a => {
    exact(a, ["environmentId", "keyVersion", "grantGeneration"]); identifier(a.environmentId); generation(a.keyVersion); generation(a.grantGeneration);
    if (seen.has(a.environmentId)) throw new Fault(400, "authority_duplicate"); seen.add(a.environmentId);
    return [a.environmentId, a.keyVersion, a.grantGeneration];
  }));
}
export function deviceRevocationBytes(r: DeviceRevocation): Uint8Array {
  exact(r, ["accountId", "accountGeneration", "deviceId", "subjectDeviceId", "subjectSigningPublicKey", "subjectReceivingPublicKey", "idempotencyKey", "challengeId", "sessionHash", "nonce", "expiresAt", "authorities"]);
  for (const v of [r.accountId, r.deviceId, r.subjectDeviceId, r.idempotencyKey, r.challengeId]) identifier(v);
  generation(r.accountGeneration); generation(r.expiresAt); bytes(r.subjectSigningPublicKey, 32); bytes(r.subjectReceivingPublicKey, 32); bytes(r.nonce, 32);
  if (typeof r.sessionHash !== "string" || !/^[0-9a-f]{64}$/.test(r.sessionHash)) throw new Fault(400, "hash_invalid");
  return canonical(["harmonia/device-revocation/v1", r.accountId, r.accountGeneration, r.deviceId, r.subjectDeviceId,
    r.subjectSigningPublicKey, r.subjectReceivingPublicKey, r.idempotencyKey, r.challengeId, r.sessionHash, r.nonce, r.expiresAt, revocationAuthorityHash(r.authorities)]);
}
const content = (encoded: Uint8Array, signature: string): string => Buffer.from(encoded).toString("base64url") + "." + signature;
export function environmentSubmissionContent(encoded: Uint8Array, signature: string, origin: SignedEnvironmentOrigin): string {
  return JSON.stringify(["harmonia/environment-submission/v2", Buffer.from(encoded).toString("base64url"), signature,
    Buffer.from(environmentOriginBytes(origin.origin)).toString("base64url"), origin.signature]);
}
const nowSeconds = (): number => Math.floor(Date.now() / 1000);
const active = (g: SignedGrant, a: Account, now: number): boolean => g.grant.role !== "none" && g.grant.accountGeneration === a.generation && !a.devices[g.grant.subjectDeviceId]?.revoked && !!a.devices[g.grant.subjectDeviceId] && (g.grant.expiresAt === "0" || BigInt(g.grant.expiresAt) > BigInt(now));
function own<T>(obj: Record<string, T> | undefined, key: string): T | undefined { return obj && Object.hasOwn(obj, key) ? obj[key] : undefined; }
export class EnvironmentService {
  constructor(readonly store: Store, private readonly clock: () => number = nowSeconds) {}
  private async authenticated<T>(accountId: string, auth: Auth, operation: (a: EnvironmentAccount, now: number, hash: string) => T): Promise<T> {
    identifier(accountId); identifier(auth.deviceId); generation(auth.accountGeneration); bytes(auth.token, 32); const hash = await tokenHash(auth.token);
    return this.store.transaction(accountId, a => {
      const now = this.clock(); sameAccount(a, auth.accountGeneration); device(a, auth.deviceId);
      if (session(a, hash, now).deviceId !== auth.deviceId) throw new Fault(403, "device_proof_required");
      return operation(a, now, hash);
    });
  }
  async list(accountId: string, auth: Auth): Promise<{ accountId: string; accountGeneration: string; sequence: number; environments: { environmentId: string; keyVersion: string; labelPayload: string; grant: SignedGrant }[] }> {
    return this.authenticated(accountId, auth, (a, now) => {
      const environments = [];
      for (const e of Object.values(a.environments)) {
        try { permission(a, auth.deviceId, e.id, now); } catch { continue; }
        environments.push({ environmentId: e.id, keyVersion: e.keyVersion, labelPayload: own(a.environmentLabels, e.id) ?? "", grant: a.grants[grantKey(e.id, auth.deviceId)]! });
      }
      return structuredClone({ accountId, accountGeneration: a.generation, sequence: a.sequence, environments });
    });
  }
  async controlDAG(accountId: string, auth: Auth, environmentId: string): Promise<{ sequence: number; grants: SignedGrant[]; issuerEvidence: IssuerRecoveryDAG }> {
    identifier(environmentId);
    return this.authenticated(accountId, auth, (account, now) => {
      if (permission(account, auth.deviceId, environmentId, now).role !== "admin") throw new Fault(403, "admin_required");
      const grants = Object.values(account.grants).filter(grant => grant.grant.environmentId === environmentId && active(grant, account, now) && grant.grant.keyVersion === account.environments[environmentId]!.keyVersion);
      const current = account.grants[grantKey(environmentId, auth.deviceId)]!;
      const issuerEvidence = buildIssuerRecoveryDAGEvidence(account as RecoveryDAGAccount, auth.deviceId, grants, [current]);
      if (!issuerEvidence) throw new Fault(403, "issuer_origin_invalid");
      return structuredClone({ sequence: account.sequence, grants, issuerEvidence });
    });
  }
  async changeStatus(accountId: string, auth: Auth, idempotencyKey: string): Promise<{ state: "complete" | "unknown"; sequence?: number; contentHash?: string }> {
    identifier(idempotencyKey);
    return this.authenticated(accountId, auth, a => {
      const found = own(a.idempotency, `environment/${auth.deviceId}/${idempotencyKey}`);
      if (!found) return { state: "unknown" };
      return { state: "complete", sequence: found.sequence, contentHash: Buffer.from(sha256(new TextEncoder().encode(found.content))).toString("hex") };
    });
  }
  async changeV4(accountId: string, auth: Auth, signed: SignedEnvironmentChange | SignedEnvironmentChangeV2): Promise<{ sequence: number; replayed: boolean }> {
    if (signed.change.operation === "create" || signed.change.operation === "rotate") {
      exact(signed, ["change", "signature", "origin"]);
      const origin = (signed as SignedEnvironmentChangeV2).origin;
      exact(origin, ["origin", "signature"]);
      environmentOriginBytes(origin.origin); bytes(origin.signature, 64);
      return this.applyChange(accountId, auth, { change: signed.change, signature: signed.signature }, origin);
    }
    exact(signed, ["change", "signature"]);
    return this.applyChange(accountId, auth, signed);
  }
  private async applyChange(accountId: string, auth: Auth, signed: SignedEnvironmentChange, origin?: SignedEnvironmentOrigin): Promise<{ sequence: number; replayed: boolean }> {
    const encoded = environmentChangeBytes(signed.change); bytes(signed.signature, 64);
    return this.authenticated(accountId, auth, (a, now) => {
      const c = signed.change;
      if (c.accountId !== a.id || c.accountGeneration !== a.generation || c.deviceId !== auth.deviceId) throw new Fault(403, "binding_invalid");
      verify(a.devices[auth.deviceId]!.signingPublicKey, encoded, signed.signature);
      const key = `environment/${auth.deviceId}/${c.idempotencyKey}`, wire = origin ? environmentSubmissionContent(encoded, signed.signature, origin) : content(encoded, signed.signature), old = own(a.idempotency, key);
      const authority = permission(a, auth.deviceId, c.authorityEnvironmentId, now);
      if (authority.role !== "admin") throw new Fault(403, "admin_required");
      const source = a.grants[grantKey(c.authorityEnvironmentId, auth.deviceId)]!;
      buildIssuerRecoveryDAGEvidence(a as RecoveryDAGAccount, auth.deviceId, [source]);
      if (old) { if (old.content !== wire) throw new Fault(409, "idempotency_conflict"); return { sequence: old.sequence, replayed: true }; }
      if (authority.keyVersion !== c.authorityKeyVersion || authority.grantGeneration !== c.authorityGrantGeneration) throw new Fault(403, "grant_stale");
      if (c.expectedSequence !== String(a.sequence)) throw new Fault(409, "environment_snapshot_stale");
      if (a.recoveryGeneration !== c.recoveryGeneration || !a.recoverySigningPublicKey || !a.recoveryReceivingPublicKey) throw new Fault(409, "recovery_generation_stale");
      const env = own(a.environments, c.environmentId);
      if (c.operation === "create") {
        if (env || own(a.deletedEnvironmentIds, c.environmentId)) throw new Fault(409, "environment_id_spent");
        if (c.previousKeyVersion !== "0" || c.keyVersion !== "1" || c.grants.length !== 1 || c.mutations.length) throw new Fault(400, "create_manifest_invalid");
        if (Object.keys(a.environments).length >= 256) throw new Fault(503, "account_capacity_reached");
      } else {
        if (!env) throw new Fault(404, "environment_not_found");
        if (c.operation === "delete" && Object.keys(a.environments).length === 1) throw new Fault(409, "last_environment_requires_account_management");
        if (c.authorityEnvironmentId !== c.environmentId) throw new Fault(403, "environment_admin_required");
        if (c.previousKeyVersion !== env.keyVersion) throw new Fault(409, "key_version_stale");
        const expected = c.operation === "rotate" ? BigInt(env.keyVersion) + 1n : BigInt(env.keyVersion);
        if (BigInt(c.keyVersion) !== expected) throw new Fault(409, "key_version_conflict");
      }
      const authorization = structuredClone(a.grants[grantKey(c.authorityEnvironmentId, auth.deviceId)]!);
      const subjects = Object.values(a.grants).filter(g => g.grant.environmentId === c.environmentId).map(g => g.grant.subjectDeviceId).sort();
      if (c.operation === "create" || c.operation === "rotate") this.validateManifest(a, now, c, authority.expiresAt);
      if (origin) this.validateOrigin(a, now, signed, encoded, authorization, origin);
      if (c.operation === "rotate" && !!own(a.environmentLabels, c.environmentId) !== !!c.labelPayload) throw new Fault(409, "label_reencryption_required");
      if ((a.environmentHistory?.length ?? 0) >= 10000 || a.events.length + c.mutations.length > 10000) throw new Fault(503, "account_capacity_reached");
      const sequence = next(a);
      a.environmentHistory ??= []; a.environmentLabels ??= {}; a.deletedEnvironmentIds ??= {}; a.grantHistory ??= [];
      a.environmentHistory.push({ sequence, change: { change: structuredClone(signed.change), signature: signed.signature }, authorization, subjects: c.operation === "create" ? [auth.deviceId] : subjects, ...(origin ? { origin: structuredClone(origin) } : {}) });
      if (c.operation === "delete") {
        delete a.environments[c.environmentId]; delete a.environmentLabels[c.environmentId];
        a.deletedEnvironmentIds[c.environmentId] = key;
        for (const [id, g] of Object.entries(a.grants)) if (g.grant.environmentId === c.environmentId) delete a.grants[id];
        // 旧密文与封套不再留在权威可恢复集合；保留签名墓碑和历史授权用于客户端检查。
        a.events = a.events.filter(e => e.mutation.mutation.environmentId !== c.environmentId);
      } else {
        if (c.operation !== "rename") {
          a.environments[c.environmentId] = { id: c.environmentId, keyVersion: c.keyVersion, recoveryEnvelope: c.recoveryEnvelope, recoveryGeneration: a.recoveryGeneration, recoveryKeyVersion: c.keyVersion };
          for (const g of c.grants) {
            a.grants[grantKey(c.environmentId, g.grant.subjectDeviceId)] = structuredClone(g);
            a.grantHistory.push({ sequence, grant: structuredClone(g), authorization, ...(origin ? { originHash: environmentOriginHash(origin) } : {}) });
            a.idempotency[`grant/${g.grant.issuerDeviceId}/${g.grant.idempotencyKey}`] = { content: content(grantBytes(g.grant), g.signature), sequence };
          }
          const writer = c.grants.find(g => g.grant.subjectDeviceId === auth.deviceId)!;
          for (const m of c.mutations) {
            const valueSequence = next(a);
            a.events.push({ sequence: valueSequence, mutation: structuredClone(m), authorization: structuredClone(writer) });
            a.idempotency[`mutation/${m.mutation.deviceId}/${m.mutation.idempotencyKey}`] = { content: content(mutationBytes(m.mutation), m.signature), sequence: valueSequence };
          }
        }
        a.environmentLabels[c.environmentId] = c.labelPayload;
      }
      a.idempotency[key] = { content: wire, sequence: a.sequence };
      return { sequence: a.sequence, replayed: false };
    });
  }
  private validateOrigin(a: EnvironmentAccount, now: number, signed: SignedEnvironmentChange, encoded: Uint8Array, authority: SignedGrant, signedOrigin: SignedEnvironmentOrigin): void {
    const c = signed.change, o = signedOrigin.origin;
    if (c.operation !== "create" && c.operation !== "rotate") throw new Fault(400, "environment_origin_operation_invalid");
    const pairs = [[o.accountId, c.accountId], [o.accountGeneration, c.accountGeneration], [o.actorDeviceId, c.deviceId],
      [o.environmentId, c.environmentId], [o.operation, c.operation], [o.authorityEnvironmentId, c.authorityEnvironmentId],
      [o.authorityKeyVersion, c.authorityKeyVersion], [o.authorityGrantGeneration, c.authorityGrantGeneration],
      [o.previousKeyVersion, c.previousKeyVersion], [o.keyVersion, c.keyVersion], [o.expectedSequence, c.expectedSequence],
      [o.idempotencyKey, c.idempotencyKey]];
    if (pairs.some(([first, second]) => first !== second) || o.changeHash !== environmentChangeHash(encoded, signed.signature) || o.authorityHash !== environmentRights(authority).grantHash) throw new Fault(403, "environment_origin_binding_invalid");
    verify(a.devices[c.deviceId]!.signingPublicKey, environmentOriginBytes(o), signedOrigin.signature);
    const sort = (rows: ReturnType<typeof environmentRights>[]) => rows.sort((first, second) => first.subjectDeviceId < second.subjectDeviceId ? -1 : first.subjectDeviceId > second.subjectDeviceId ? 1 : 0);
    const before = c.operation === "create" ? [] : sort(Object.values(a.grants).filter(g => g.grant.environmentId === c.environmentId && active(g, a, now)).map(environmentRights));
    const after = sort(c.grants.map(environmentRights));
    if (JSON.stringify(rightsFields(o.before)) !== JSON.stringify(rightsFields(before)) || JSON.stringify(rightsFields(o.after)) !== JSON.stringify(rightsFields(after))) throw new Fault(403, "environment_origin_snapshot_invalid");
    if (c.operation === "rotate" && !o.before.some(row => row.subjectDeviceId === c.deviceId && row.role === "admin" && row.grantHash === o.authorityHash)) throw new Fault(403, "environment_origin_actor_invalid");
  }
  private validateManifest(a: EnvironmentAccount, now: number, c: EnvironmentChange, issuerExpiry: string): void {
    const old = Object.values(a.grants).filter(g => g.grant.environmentId === c.environmentId && active(g, a, now));
    if (c.operation === "rotate" && (old.length !== c.grants.length || old.some(g => !c.grants.some(n => n.grant.subjectDeviceId === g.grant.subjectDeviceId)))) throw new Fault(409, "device_envelope_set_incomplete");
    const publicKey = a.devices[c.deviceId]!.signingPublicKey;
    const grantIds = new Set<string>();
    for (const signed of c.grants) {
      const g = signed.grant, subject = a.devices[g.subjectDeviceId];
      if (grantIds.has(g.idempotencyKey)) throw new Fault(400, "grant_idempotency_duplicate"); grantIds.add(g.idempotencyKey);
      if (own(a.idempotency, `grant/${g.issuerDeviceId}/${g.idempotencyKey}`)) throw new Fault(409, "grant_idempotency_spent");
      if (!subject || subject.revoked || g.accountId !== a.id || g.accountGeneration !== a.generation || g.issuerDeviceId !== c.deviceId || g.environmentId !== c.environmentId || g.keyVersion !== c.keyVersion || g.subjectSigningPublicKey !== subject.signingPublicKey || g.subjectReceivingPublicKey !== subject.receivingPublicKey) throw new Fault(403, "grant_binding_invalid");
      verify(publicKey, grantBytes(g), signed.signature);
      if (g.role === "none" || (g.expiresAt !== "0" && BigInt(g.expiresAt) <= BigInt(now))) throw new Fault(400, "grant_already_expired");
      if (c.operation === "create" && issuerExpiry !== "0" && (g.expiresAt === "0" || BigInt(g.expiresAt) > BigInt(issuerExpiry))) throw new Fault(403, "expiry_escalation");
      if (c.operation === "create") {
        if (g.subjectDeviceId !== c.deviceId || g.role !== "admin" || g.grantGeneration !== "1") throw new Fault(403, "initial_admin_invalid");
      } else {
        const previous = a.grants[grantKey(c.environmentId, g.subjectDeviceId)]!.grant;
        if (g.role !== previous.role || g.expiresAt !== previous.expiresAt || BigInt(g.grantGeneration) !== BigInt(previous.grantGeneration) + 1n) throw new Fault(409, "rotation_grant_changed");
      }
    }
    const writer = c.grants.find(g => g.grant.subjectDeviceId === c.deviceId);
    if (!writer || writer.grant.role !== "admin") throw new Fault(403, "initial_admin_invalid");
    if (c.operation !== "rotate") return;
    const live = new Map<string, SignedMutation>();
    for (const event of a.events) if (event.mutation.mutation.environmentId === c.environmentId && event.mutation.mutation.keyVersion === c.previousKeyVersion) {
      const m = event.mutation.mutation; if (m.operation === "put") live.set(m.name, event.mutation); else live.delete(m.name);
    }
    if (live.size !== c.mutations.length || c.mutations.some(m => !live.has(m.mutation.name))) throw new Fault(409, "value_reencryption_set_incomplete");
    const mutationIds = new Set<string>();
    for (const signed of c.mutations) {
      const m = signed.mutation;
      if (mutationIds.has(m.idempotencyKey)) throw new Fault(400, "mutation_idempotency_duplicate"); mutationIds.add(m.idempotencyKey);
      if (m.accountId !== a.id || m.accountGeneration !== a.generation || m.deviceId !== c.deviceId || m.environmentId !== c.environmentId || m.keyVersion !== c.keyVersion || m.grantGeneration !== writer.grant.grantGeneration || m.operation !== "put") throw new Fault(403, "mutation_binding_invalid");
      verify(publicKey, mutationBytes(m), signed.signature);
      if (own(a.idempotency, `mutation/${m.deviceId}/${m.idempotencyKey}`)) throw new Fault(409, "mutation_idempotency_spent");
    }
  }
  private allAuthorities(a: Account, deviceId: string, now: number): SignedGrant[] {
    const envs = Object.keys(a.environments).sort(); if (!envs.length) throw new Fault(403, "all_environment_admin_required");
    return envs.map(id => { const g = permission(a, deviceId, id, now); if (g.role !== "admin") throw new Fault(403, "all_environment_admin_required"); return a.grants[grantKey(id, deviceId)]!; });
  }
  async revocationChallenge(accountId: string, auth: Auth, subjectDeviceId: string, idempotencyKey: string): Promise<DeviceRevocation> {
    identifier(subjectDeviceId); identifier(idempotencyKey);
    return this.authenticated(accountId, auth, (a, now, hash) => {
      const authorizations = this.allAuthorities(a, auth.deviceId, now); device(a, subjectDeviceId);
      a.deviceRevocations ??= {}; const key = `${auth.deviceId}/${idempotencyKey}`, old = own(a.deviceRevocations, key);
      if (old) {
        if (old.revocation.subjectDeviceId !== subjectDeviceId || old.revocation.sessionHash !== hash) throw new Fault(409, "idempotency_conflict");
        if (!old.signature && BigInt(old.revocation.expiresAt) <= BigInt(now)) throw new Fault(403, "challenge_invalid");
        return structuredClone(old.revocation);
      }
      for (const [k, r] of Object.entries(a.deviceRevocations)) if (!r.signature && BigInt(r.revocation.expiresAt) <= BigInt(now)) delete a.deviceRevocations[k];
      if (Object.keys(a.deviceRevocations).length >= 256) throw new Fault(429, "challenge_capacity_reached");
      const subject = a.devices[subjectDeviceId]!;
      const revocation: DeviceRevocation = { accountId, accountGeneration: a.generation, deviceId: auth.deviceId, subjectDeviceId,
        subjectSigningPublicKey: subject.signingPublicKey, subjectReceivingPublicKey: subject.receivingPublicKey, idempotencyKey,
        challengeId: crypto.randomUUID(), sessionHash: hash, nonce: randomToken(), expiresAt: String(now + 120),
        authorities: authorizations.map(s => ({ environmentId: s.grant.environmentId, keyVersion: s.grant.keyVersion, grantGeneration: s.grant.grantGeneration })) };
      a.deviceRevocations[key] = { revocation, authorizations: structuredClone(authorizations) };
      return structuredClone(revocation);
    });
  }
  async revocationStatus(accountId: string, auth: Auth, idempotencyKey: string): Promise<{ state: "pending" | "complete" | "unknown"; sequence?: number; expiresAt?: string }> {
    identifier(idempotencyKey);
    return this.authenticated(accountId, auth, a => {
      const record = own(a.deviceRevocations, `${auth.deviceId}/${idempotencyKey}`);
      if (!record) return { state: "unknown" };
      return record.signature ? { state: "complete", sequence: record.sequence! } : { state: "pending", expiresAt: record.revocation.expiresAt };
    });
  }
  async revokeDevice(accountId: string, auth: Auth, signed: SignedDeviceRevocation): Promise<{ sequence: number; replayed: boolean }> {
    exact(signed, ["revocation", "signature"]); const encoded = deviceRevocationBytes(signed.revocation); bytes(signed.signature, 64);
    return this.authenticated(accountId, auth, (a, now, hash) => {
      const r = signed.revocation;
      if (r.accountId !== a.id || r.accountGeneration !== a.generation || r.deviceId !== auth.deviceId || r.sessionHash !== hash) throw new Fault(403, "binding_invalid");
      const authorities = this.allAuthorities(a, auth.deviceId, now);
      verify(a.devices[auth.deviceId]!.signingPublicKey, encoded, signed.signature);
      const record = own(a.deviceRevocations, `${auth.deviceId}/${r.idempotencyKey}`);
      if (!record || content(deviceRevocationBytes(record.revocation), "") !== content(encoded, "")) throw new Fault(403, "challenge_invalid");
      if (record.signature) {
        if (record.signature !== signed.signature) throw new Fault(409, "idempotency_conflict");
        return { sequence: record.sequence!, replayed: true };
      }
      if (BigInt(r.expiresAt) <= BigInt(now)) throw new Fault(403, "challenge_invalid");
      if (revocationAuthorityHash(authorities.map(s => ({ environmentId: s.grant.environmentId, keyVersion: s.grant.keyVersion, grantGeneration: s.grant.grantGeneration }))) !== revocationAuthorityHash(r.authorities)) throw new Fault(409, "authority_set_stale");
      device(a, r.subjectDeviceId); const subject = a.devices[r.subjectDeviceId]!;
      if (subject.signingPublicKey !== r.subjectSigningPublicKey || subject.receivingPublicKey !== r.subjectReceivingPublicKey) throw new Fault(403, "device_key_mismatch");
      const sequence = next(a); subject.revoked = true;
      a.sessions = a.sessions.filter(s => s.deviceId !== r.subjectDeviceId);
      a.deviceChallenges = a.deviceChallenges.filter(c => c.deviceId !== r.subjectDeviceId);
      a.bootChallenges = a.bootChallenges?.filter(c => c.deviceId !== r.subjectDeviceId) ?? [];
      for (const [key, grant] of Object.entries(a.grants)) if (grant.grant.subjectDeviceId === r.subjectDeviceId) delete a.grants[key];
      record.signature = signed.signature; record.sequence = sequence;
      return { sequence, replayed: false };
    });
  }
}
