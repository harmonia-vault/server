import {environmentChangeBytes} from "../src/environments.js";
import {environmentChangeHash,environmentRights,environmentOriginBytes} from "../src/environment-origin.js";
import {issuerAuthorityHash} from "../src/issuer-proof.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { hashCredential, credential } from "../src/password.js";
import { grantBytes, mutationBytes } from "../src/protocol.js";
import { VaultService, tokenHash } from "../src/service.js";
import type { Account, Auth, Grant, Mutation, SignedGrant, SignedMutation } from "../src/model.js";
import { grantKey } from "../src/model.js";
import type { Store } from "../src/store.js";
import { canonical, initializationHash, initializationFields, proposalRoot, pairingProfile, type InitializationProposal, type InitializationRecord } from "../src/enrollment-wire.js";
import { buildIssuerRecoveryDAGEvidence, type RecoveryDAGAccount } from "../src/recovery-dag-account.js";
import { enrollmentV5Fields, type EnrollmentApprovalV5 } from "../src/issuer-dag.js";
import { recoveryDAGCapability } from "../src/recovery-dag-wire.js";
import { trustRootPayload } from "../src/trust-root.js";
export const receivingKey = (id: string): string => Buffer.from(x25519.getPublicKey(Buffer.alloc(32, { admin: 8, writer: 9, reader: 10, stranger: 11 }[id] ?? 12))).toString("base64url");
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
    subjectSigningPublicKey: publicKey(subjectDeviceId), subjectReceivingPublicKey: receivingKey(subjectDeviceId),
    environmentId: "dev", keyVersion: "1", grantGeneration: "1", role: subjectDeviceId === "admin" ? "admin" : subjectDeviceId === "reader" ? "ro" : "rw",
    expiresAt: "0", idempotencyKey: `initial-${subjectDeviceId}`, envelope: Buffer.alloc(80, 9).toString("base64url"), ...overrides };
}
export function mutation(deviceId = "writer", overrides: Partial<Mutation> = {}): SignedMutation {
  const m: Mutation = { accountId: "synthetic-account", accountGeneration: "1", deviceId, environmentId: "dev", keyVersion: "1",
    grantGeneration: "1", operation: "put", idempotencyKey: "write-1", name: "SYNTHETIC_KEY", payload: Buffer.alloc(40, 6).toString("base64url"), ...overrides };
  return { mutation: m, signature: Buffer.from(ed25519.sign(mutationBytes(m), seeds[deviceId]!)).toString("base64url") };
}
export const auth = (deviceId = "writer"): Auth => ({ token: tokenFor(deviceId), deviceId, accountGeneration: "1" });
export async function fixtureAccount(id = "synthetic-account", mail = email): Promise<RecoveryDAGAccount> {
  const passwordVerifier = await hashCredential(clientCredential);
  const a: RecoveryDAGAccount = { schema: 2, id, email: mail, generation: "1", verified: true, passwordVerifier, sequence: 0,
    verificationRequiredAtRegistration: false, registrationAdmission: { id: `registration-${id}`, mode: "open", state: "complete", expiresAt: now + 900, readyAt: now },
    devices: {}, environments: { dev: { id: "dev", keyVersion: "1", recoveryEnvelope: Buffer.alloc(80, 9).toString("base64url"), recoveryGeneration: "1", recoveryKeyVersion: "1" } }, grants: {},
    sessions: [], deviceChallenges: [], events: [], idempotency: {}, grantHistory: [],
    recoveryGeneration: "1", recoverySigningPublicKey: recoveryKeys(recoverySeed, id).signingPublicKey, recoveryReceivingPublicKey: recoveryKeys(recoverySeed, id).receivingPublicKey };
  for (const deviceId of Object.keys(seeds)) {
    a.sessions.push({ tokenHash: await tokenHash(tokenFor(deviceId)), generation: "1", expiresAt: now + 7200, kind: "login", deviceId });
    a.devices[deviceId] = { id: deviceId, signingPublicKey: publicKey(deviceId), receivingPublicKey: receivingKey(deviceId), revoked: false };
    if (deviceId !== "stranger") {
      const g = grant(deviceId, { accountId: id }); a.grants[grantKey("dev", deviceId)] = signGrant(g);
      a.grantHistory!.push({ sequence: 0, grant: signGrant(g), authorization: deviceId === "admin" ? null : signGrant(grant("admin", { accountId: id })) });
    }
  }
  const rootGrant = a.grants[grantKey("dev", "admin")]!, keys = recoveryKeys(recoverySeed, id);
  const root = { rootDeviceId: "admin", rootSigningPublicKey: publicKey("admin"), rootReceivingPublicKey: receivingKey("admin"), recoveryGeneration: "1", recoverySigningPublicKey: keys.signingPublicKey, recoveryReceivingPublicKey: keys.receivingPublicKey, signature: "" };
  root.signature = Buffer.from(ed25519.sign(canonical(trustRootPayload(id, "1", root)), keys.signingSeed)).toString("base64url");
  const proposal: InitializationProposal = { idempotencyKey: "fixture-init", device: { id: "admin", signingPublicKey: publicKey("admin"), receivingPublicKey: receivingKey("admin") }, recoveryGeneration: "1", recoverySigningPublicKey: keys.signingPublicKey, recoveryReceivingPublicKey: keys.receivingPublicKey, trustRootSignature: root.signature, environments: [{ environmentId: "dev", keyVersion: "1", recoveryEnvelope: a.environments.dev!.recoveryEnvelope!, grant: rootGrant }] };
  const record: InitializationRecord = { id: "fixture-challenge", sessionHash: await tokenHash(tokenFor("admin")), accountGeneration: "1", nonce: Buffer.alloc(32, 20).toString("base64url"), expiresAt: now + 120, proposal, proposalHash: initializationHash(id, "1", proposal) };
  const fields = canonical(initializationFields(id, record));
  record.complete = { sequence: 1, deviceSignature: Buffer.from(ed25519.sign(fields, seeds.admin!)).toString("base64url"), recoverySignature: Buffer.from(ed25519.sign(fields, keys.signingSeed)).toString("base64url") };
  a.vaultInitializations = { [proposal.idempotencyKey]: record }; a.trustRoot = proposalRoot(proposal); a.sequence = 1;
  a.grantHistory = [{ sequence: 1, grant: rootGrant, authorization: null }];
  a.dagDeviceEnrollments = {};
  for (const child of ["writer", "reader"]) {
    const proof = buildIssuerRecoveryDAGEvidence(a, "admin", [rootGrant])!;
    const c: EnrollmentApprovalV5 = { certificateVersion: "5", capabilities: [recoveryDAGCapability], pairingProfile, transcriptHash: "01".repeat(32), context: { accountId: id, accountGeneration: "1", purpose: "enroll-device", sessionId: `fixture-${child}`, challengeNonce: Buffer.alloc(32, 21).toString("base64url"), expiresAt: String(now + 120), initiatorDeviceId: child, initiatorSigningPublicKey: publicKey(child), initiatorReceivingPublicKey: receivingKey(child), approverDeviceId: "admin", approverSigningPublicKey: publicKey("admin"), approverReceivingPublicKey: receivingKey("admin") }, grants: [a.grants[grantKey("dev", child)]!], issuerProof: proof, approverSignature: "" };
    const bytes = canonical(enrollmentV5Fields(c));
    c.approverSignature = Buffer.from(ed25519.sign(bytes, seeds.admin!)).toString("base64url"); c.initiatorSignature = Buffer.from(ed25519.sign(bytes, seeds[child]!)).toString("base64url");
    a.dagDeviceEnrollments[child] = c; a.grantHistory.push({ sequence: ++a.sequence, grant: c.grants[0]!, authorization: rootGrant });
  }
  return a;
}
export async function seed(store: Store): Promise<VaultService> {
  const account = await fixtureAccount();
  store.create(account);
  await store.registrationAuthority.complete(account.id,account.registrationAdmission!.id,"open");
  return new VaultService(store, { allowRegistration: false, requireEmailVerification: true }, () => now);
}

export const recoverySeed = new Uint8Array(32).fill(5);
export function recoveryKeys(seed: Uint8Array, id = "synthetic-account", recGen = "1") {
  const derive = (purpose: string) => hkdf(sha256, seed, undefined, new TextEncoder().encode(JSON.stringify(["harmonia/recovery-kdf/v1", purpose, id, "1", recGen])), 32);
  const signingSeed = derive("ed25519-signing"), receivingPrivate = derive("x25519-receiving");
  return { signingSeed, signingPublicKey: Buffer.from(ed25519.getPublicKey(signingSeed)).toString("base64url"), receivingPrivate, receivingPublicKey: Buffer.from(x25519.getPublicKey(receivingPrivate)).toString("base64url") };
}

export function clearVault(a: Account): void {
  const d = a as RecoveryDAGAccount;
  d.devices = {}; d.environments = {}; d.grants = {}; d.events = []; d.grantHistory = []; d.sequence = 0;
  delete d.trustRoot; delete d.vaultInitializations; delete d.dagDeviceEnrollments; delete d.dagPairingSessions;
  d.recoveryGeneration = "1"; d.recoverySigningPublicKey = null; d.recoveryReceivingPublicKey = null;
}

export function withEnvironmentOrigin(a: Account, packet: import("../src/environments.js").SignedEnvironmentChange) {
  const c = packet.change;
  if (c.operation !== "create" && c.operation !== "rotate") return packet;
  const historical=a.environmentHistory?.find(e=>e.change.change.idempotencyKey===c.idempotencyKey&&e.change.change.deviceId===c.deviceId);
  const authority = historical?.authorization ?? a.grants[grantKey(c.authorityEnvironmentId, c.deviceId)]!;
  const before = c.operation === "create" ? [] : historical?.origin ? historical.origin.origin.before.map(r=>a.grantHistory!.find(g=>issuerAuthorityHash(g.grant)===r.grantHash)!.grant) : Object.values(a.grants).filter(g => g.grant.environmentId === c.environmentId && g.grant.role !== "none" && (g.grant.expiresAt === "0" || Number(g.grant.expiresAt) > now) && !a.devices[g.grant.subjectDeviceId]?.revoked);
  const origin = {accountId:c.accountId,accountGeneration:c.accountGeneration,actorDeviceId:c.deviceId,environmentId:c.environmentId,operation:c.operation,authorityEnvironmentId:c.authorityEnvironmentId,authorityKeyVersion:c.authorityKeyVersion,authorityGrantGeneration:c.authorityGrantGeneration,previousKeyVersion:c.previousKeyVersion,keyVersion:c.keyVersion,expectedSequence:c.expectedSequence,idempotencyKey:c.idempotencyKey,changeHash:environmentChangeHash(environmentChangeBytes(c),packet.signature),authorityHash:issuerAuthorityHash(authority),before:before.map(environmentRights).sort((a,b)=>a.subjectDeviceId.localeCompare(b.subjectDeviceId)),after:c.grants.map(environmentRights).sort((a,b)=>a.subjectDeviceId.localeCompare(b.subjectDeviceId))};
  return {...packet, origin:{origin,signature:Buffer.from(ed25519.sign(environmentOriginBytes(origin),seeds[c.deviceId]!)).toString("base64url")}};
}

export async function submitEnvironmentChange(service: import("../src/environments.js").EnvironmentService, accountId: string, auth: Auth, packet: import("../src/environments.js").SignedEnvironmentChange) {
  return service.changeV4(accountId,auth,withEnvironmentOrigin(service.store.read(accountId)!,packet));
}
