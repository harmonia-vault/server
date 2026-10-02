import { Fault, type SignedGrant } from "./model.js";
import { bytes, generation, identifier } from "./protocol.js";
import { canonical, exact, hash } from "./enrollment-wire.js";
import { issuerAuthorityHash } from "./issuer-proof.js";

export interface EnvironmentRights {
  subjectDeviceId: string;
  subjectSigningPublicKey: string;
  subjectReceivingPublicKey: string;
  keyVersion: string;
  grantGeneration: string;
  role: "ro" | "rw" | "admin";
  expiresAt: string;
  grantHash: string;
}
export interface EnvironmentOrigin {
  accountId: string;
  accountGeneration: string;
  actorDeviceId: string;
  environmentId: string;
  operation: "create" | "rotate";
  authorityEnvironmentId: string;
  authorityKeyVersion: string;
  authorityGrantGeneration: string;
  previousKeyVersion: string;
  keyVersion: string;
  expectedSequence: string;
  idempotencyKey: string;
  changeHash: string;
  authorityHash: string;
  before: EnvironmentRights[];
  after: EnvironmentRights[];
}
export interface SignedEnvironmentOrigin { origin: EnvironmentOrigin; signature: string }
export function originDigest(value: string): void {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) throw new Fault(400, "environment_origin_invalid");
}
function decimal(value: string, zero = false): void {
  if (zero && value === "0") return;
  generation(value);
}
export function environmentRights(signed: SignedGrant): EnvironmentRights {
  const g = signed.grant;
  if (g.role === "none") throw new Fault(400, "environment_origin_invalid");
  return { subjectDeviceId: g.subjectDeviceId, subjectSigningPublicKey: g.subjectSigningPublicKey,
    subjectReceivingPublicKey: g.subjectReceivingPublicKey, keyVersion: g.keyVersion,
    grantGeneration: g.grantGeneration, role: g.role, expiresAt: g.expiresAt, grantHash: issuerAuthorityHash(signed) };
}
export function rightsFields(rows: EnvironmentRights[]): string[][] {
  if (!Array.isArray(rows) || rows.length > 256) throw new Fault(400, "environment_origin_invalid");
  let last = "";
  return rows.map(row => {
    exact(row, ["subjectDeviceId", "subjectSigningPublicKey", "subjectReceivingPublicKey", "keyVersion", "grantGeneration", "role", "expiresAt", "grantHash"]);
    identifier(row.subjectDeviceId);
    if (row.subjectDeviceId <= last) throw new Fault(400, "environment_origin_order_invalid");
    last = row.subjectDeviceId;
    bytes(row.subjectSigningPublicKey, 32); bytes(row.subjectReceivingPublicKey, 32);
    if (row.subjectSigningPublicKey === row.subjectReceivingPublicKey || !["ro", "rw", "admin"].includes(row.role)) throw new Fault(400, "environment_origin_invalid");
    generation(row.keyVersion); generation(row.grantGeneration); decimal(row.expiresAt, true);
    if (BigInt(row.expiresAt) > 253402300799n) throw new Fault(400, "expiry_invalid");
    originDigest(row.grantHash);
    return [row.subjectDeviceId, row.subjectSigningPublicKey, row.subjectReceivingPublicKey,
      row.keyVersion, row.grantGeneration, row.role, row.expiresAt, row.grantHash];
  });
}
export function environmentOriginFields(o: EnvironmentOrigin): unknown[] {
  exact(o, ["accountId", "accountGeneration", "actorDeviceId", "environmentId", "operation", "authorityEnvironmentId", "authorityKeyVersion", "authorityGrantGeneration", "previousKeyVersion", "keyVersion", "expectedSequence", "idempotencyKey", "changeHash", "authorityHash", "before", "after"]);
  for (const value of [o.accountId, o.actorDeviceId, o.environmentId, o.authorityEnvironmentId, o.idempotencyKey]) identifier(value);
  for (const value of [o.accountGeneration, o.authorityKeyVersion, o.authorityGrantGeneration, o.keyVersion]) generation(value);
  decimal(o.previousKeyVersion, true); decimal(o.expectedSequence, true);
  originDigest(o.changeHash); originDigest(o.authorityHash);
  if (o.operation !== "create" && o.operation !== "rotate") throw new Fault(400, "environment_origin_invalid");
  const before = rightsFields(o.before), after = rightsFields(o.after);
  if (!after.length || (o.operation === "create" ? o.previousKeyVersion !== "0" || o.keyVersion !== "1" || before.length !== 0 || after.length !== 1 : o.authorityEnvironmentId !== o.environmentId || BigInt(o.keyVersion) !== BigInt(o.previousKeyVersion) + 1n || before.length !== after.length)) throw new Fault(400, "environment_origin_invalid");
  if (o.operation === "create") {
    const row = o.after[0]!;
    if (row.subjectDeviceId !== o.actorDeviceId || row.role !== "admin" || row.keyVersion !== "1" || row.grantGeneration !== "1") throw new Fault(400, "environment_origin_invalid");
  } else {
    if (!o.before.length || o.authorityKeyVersion !== o.previousKeyVersion) throw new Fault(400, "environment_origin_invalid");
    let actorFound = false;
    for (let index = 0; index < o.before.length; index++) {
      const old = o.before[index]!, current = o.after[index]!;
      if (old.keyVersion !== o.previousKeyVersion || current.keyVersion !== o.keyVersion || BigInt(current.grantGeneration) !== BigInt(old.grantGeneration) + 1n || old.subjectDeviceId !== current.subjectDeviceId || old.subjectSigningPublicKey !== current.subjectSigningPublicKey || old.subjectReceivingPublicKey !== current.subjectReceivingPublicKey || old.role !== current.role || old.expiresAt !== current.expiresAt) throw new Fault(400, "environment_origin_invalid");
      if (old.subjectDeviceId === o.actorDeviceId) {
        if (old.role !== "admin" || old.grantHash !== o.authorityHash || old.grantGeneration !== o.authorityGrantGeneration) throw new Fault(400, "environment_origin_invalid");
        actorFound = true;
      }
    }
    if (!actorFound) throw new Fault(400, "environment_origin_invalid");
  }
  return ["harmonia/environment-origin/v1", o.accountId, o.accountGeneration, o.actorDeviceId, o.environmentId, o.operation,
    o.authorityEnvironmentId, o.authorityKeyVersion, o.authorityGrantGeneration, o.previousKeyVersion, o.keyVersion,
    o.expectedSequence, o.idempotencyKey, o.changeHash, o.authorityHash, before, after];
}
export const environmentOriginBytes = (o: EnvironmentOrigin): Uint8Array => canonical(environmentOriginFields(o));
export function environmentOriginHash(signed: SignedEnvironmentOrigin): string {
  exact(signed, ["origin", "signature"]); bytes(signed.signature, 64);
  return hash(["harmonia/environment-origin-ref/v1", Buffer.from(environmentOriginBytes(signed.origin)).toString("base64url"), signed.signature]);
}
export function environmentChangeHash(encoded: Uint8Array, signature: string): string {
  bytes(signature, 64);
  return hash(["harmonia/environment-change-ref/v1", Buffer.from(encoded).toString("base64url"), signature]);
}
