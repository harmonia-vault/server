import { ed25519 } from "@noble/curves/ed25519.js";
import type { Grant, Mutation } from "./model.js";
import { Fault } from "./model.js";
const id = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const uint = /^[1-9][0-9]{0,19}$/;
const max = 18446744073709551615n;
export function bytes(value: string, length?: number): Uint8Array {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/.test(value)) throw new Fault(400, "encoding_invalid");
  const result = Buffer.from(value, "base64url");
  if (result.toString("base64url") !== value || (length !== undefined && result.length !== length))
    throw new Fault(400, "encoding_invalid");
  return result;
}
export function identifier(value: string): void { if (typeof value !== "string" || !id.test(value)) throw new Fault(400, "identifier_invalid"); }
export function generation(value: string): void {
  if (typeof value !== "string" || !uint.test(value) || BigInt(value) > max) throw new Fault(400, "generation_invalid");
}
function base(accountId: string, accountGeneration: string, environmentId: string, keyVersion: string, grantGeneration: string): void {
  identifier(accountId); identifier(environmentId); generation(accountGeneration); generation(keyVersion); generation(grantGeneration);
}
function exact(value: object, fields: string[]): void {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join("|") !== fields.sort().join("|")) throw new Fault(400, "fields_invalid");
}
export function mutationBytes(m: Mutation): Uint8Array {
  exact(m, ["accountId", "accountGeneration", "deviceId", "environmentId", "keyVersion", "grantGeneration", "operation", "idempotencyKey", "name", "payload"]);
  base(m.accountId, m.accountGeneration, m.environmentId, m.keyVersion, m.grantGeneration);
  identifier(m.deviceId); identifier(m.idempotencyKey);
  if (typeof m.name !== "string" || !/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(m.name) || /^__HARMONIA_/i.test(m.name)) throw new Fault(400, "name_invalid");
  if (m.operation !== "put" && m.operation !== "delete") throw new Fault(400, "operation_invalid");
  const payload = bytes(m.payload);
  if ((m.operation === "delete" && m.payload !== "") || (m.operation === "put" && (payload.length < 40 || payload.length > 65576))) throw new Fault(400, "payload_invalid");
  return new TextEncoder().encode(JSON.stringify(["harmonia/mutation/v1", m.accountId, m.accountGeneration,
    m.deviceId, m.environmentId, m.keyVersion, m.grantGeneration, m.operation, m.idempotencyKey, m.name, m.payload]));
}
export function grantBytes(g: Grant): Uint8Array {
  exact(g, ["accountId", "accountGeneration", "issuerDeviceId", "subjectDeviceId", "subjectSigningPublicKey", "subjectReceivingPublicKey", "environmentId", "keyVersion", "grantGeneration", "role", "expiresAt", "idempotencyKey", "envelope"]);
  base(g.accountId, g.accountGeneration, g.environmentId, g.keyVersion, g.grantGeneration);
  identifier(g.issuerDeviceId); identifier(g.subjectDeviceId); identifier(g.idempotencyKey);
  bytes(g.subjectSigningPublicKey, 32); bytes(g.subjectReceivingPublicKey, 32);
  if (!["ro", "rw", "admin", "none"].includes(g.role)) throw new Fault(400, "role_invalid");
  if (g.expiresAt !== "0") generation(g.expiresAt);
  if (g.role === "none") { if (g.envelope !== "") throw new Fault(400, "envelope_invalid"); }
  else bytes(g.envelope, 80);
  return new TextEncoder().encode(JSON.stringify(["harmonia/grant/v1", g.accountId, g.accountGeneration,
    g.issuerDeviceId, g.subjectDeviceId, g.subjectSigningPublicKey, g.subjectReceivingPublicKey,
    g.environmentId, g.keyVersion, g.grantGeneration, g.role, g.expiresAt, g.idempotencyKey, g.envelope]));
}
export function verify(publicKey: string, message: Uint8Array, signature: string): void {
  let valid = false;
  try { valid = ed25519.verify(bytes(signature, 64), message, bytes(publicKey, 32), { zip215: false }); } catch { /* uniform invalid signature */ }
  if (!valid) throw new Fault(403, "signature_invalid");
}
