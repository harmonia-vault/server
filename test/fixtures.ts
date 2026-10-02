import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { hashCredential, credential } from "../src/password.js";
import { grantBytes, mutationBytes } from "../src/protocol.js";
import { VaultService, tokenHash } from "../src/service.js";
import type { Account, Auth, Grant, Mutation, SignedGrant, SignedMutation } from "../src/model.js";
import { grantKey } from "../src/model.js";
import type { Store } from "../src/store.js";
export const now = 1800000000;
export const email = "synthetic@example.invalid";
export const clientCredential = "ab".repeat(32);
export const tokenFor = (deviceId: string): string => Buffer.alloc(32, { admin: 41, writer: 42, reader: 43, stranger: 44 }[deviceId] ?? 45).toString("base64url");
export const token = tokenFor("writer");
export const seeds: Record<string, Uint8Array> = {
  admin: new Uint8Array(32).fill(1), writer: new Uint8Array(32).fill(2), reader: new Uint8Array(32).fill(3), stranger: new Uint8Array(32).fill(4),
};
export const publicKey = (id: string): string => Buffer.from(ed25519.getPublicKey(seeds[id]!)).toString("base64url");
export function signGrant(grant: Grant): SignedGrant {
  return { grant, signature: Buffer.from(ed25519.sign(grantBytes(grant), seeds[grant.issuerDeviceId]!)).toString("base64url") };
}
export function grant(subjectDeviceId: string, overrides: Partial<Grant> = {}): Grant {
  return { accountId: "synthetic-account", accountGeneration: "1", issuerDeviceId: "admin", subjectDeviceId,
    subjectSigningPublicKey: publicKey(subjectDeviceId), subjectReceivingPublicKey: Buffer.from(x25519.getPublicKey(Buffer.alloc(32, 8))).toString("base64url"),
    environmentId: "dev", keyVersion: "1", grantGeneration: "1", role: subjectDeviceId === "admin" ? "admin" : subjectDeviceId === "reader" ? "ro" : "rw",
    expiresAt: "0", idempotencyKey: `initial-${subjectDeviceId}`, envelope: Buffer.alloc(80, 9).toString("base64url"), ...overrides };
}
export function mutation(deviceId = "writer", overrides: Partial<Mutation> = {}): SignedMutation {
  const m: Mutation = { accountId: "synthetic-account", accountGeneration: "1", deviceId, environmentId: "dev", keyVersion: "1",
    grantGeneration: "1", operation: "put", idempotencyKey: "write-1", name: "SYNTHETIC_KEY", payload: Buffer.alloc(40, 6).toString("base64url"), ...overrides };
  return { mutation: m, signature: Buffer.from(ed25519.sign(mutationBytes(m), seeds[deviceId]!)).toString("base64url") };
}
export const auth = (deviceId = "writer"): Auth => ({ token: tokenFor(deviceId), deviceId, accountGeneration: "1" });
export async function fixtureAccount(id = "synthetic-account", mail = email): Promise<Account> {
  const passwordVerifier = await hashCredential(clientCredential);
  const a: Account = { schema: 1, id, email: mail, generation: "1", verified: true, passwordVerifier, sequence: 0,
    devices: {}, environments: { dev: { id: "dev", keyVersion: "1", recoveryEnvelope: Buffer.alloc(80, 9).toString("base64url") } }, grants: {},
    sessions: [], deviceChallenges: [], events: [], idempotency: {},
    recoveryGeneration: "1", recoverySigningPublicKey: null };
  for (const deviceId of Object.keys(seeds)) {
    a.sessions.push({ tokenHash: await tokenHash(tokenFor(deviceId)), generation: "1", expiresAt: now + 7200, kind: "login", deviceId });
    a.devices[deviceId] = { id: deviceId, signingPublicKey: publicKey(deviceId), receivingPublicKey: Buffer.from(x25519.getPublicKey(Buffer.alloc(32, 8))).toString("base64url"), revoked: false };
    if (deviceId !== "stranger") {
      const g = grant(deviceId, { accountId: id }); a.grants[grantKey("dev", deviceId)] = signGrant(g);
    }
  }
  return a;
}
export async function seed(store: Store): Promise<VaultService> {
  store.create(await fixtureAccount());
  return new VaultService(store, { allowRegistration: false, requireEmailVerification: true }, () => now);
}
