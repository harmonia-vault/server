import test from "node:test";
import assert from "node:assert/strict";
import { ed25519 } from "@noble/curves/ed25519.js";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { nodeStore, NodeSql } from "../src/node-store.js";
import { SqlStore, type Sql } from "../src/store.js";
import { LifecycleService } from "../src/lifecycle.js";
import { canonical, bootPayload, envelopeHash, recoveryPayload, rotationPayload, trustRootPayload, trustRootHash, type TrustRoot, type RecoveryAuth, type RotationProposal } from "../src/lifecycle-wire.js";
import { Fault, grantKey } from "../src/model.js";
import { VaultService } from "../src/service.js";
import { route } from "../src/http.js";
import { auth, fixtureAccount, grant, mutation, now, recoveryKeys, recoverySeed, seed, seeds, signGrant } from "./fixtures.js";
const id = "synthetic-account";
const sign = (fields: unknown, key: Uint8Array): string => Buffer.from(ed25519.sign(canonical(fields as string[]), key)).toString("base64url");
const deny = (code: string) => (e: unknown): boolean => e instanceof Fault && e.code === code;
async function context(run: (c: ReturnType<typeof nodeStore>, lifecycle: LifecycleService, vault: VaultService, path: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "harmonia-lifecycle-test-")), path = join(dir, "account.sqlite");
  const c = nodeStore(path);
  try { const vault = await seed(c.store); await run(c, new LifecycleService(c.store, () => now), vault, path); }
  finally { try { c.sql.close(); } catch {} rmSync(dir, { recursive: true, force: true }); }
}
async function recover(service: LifecycleService, recSeed = recoverySeed, recGen = "1"): Promise<RecoveryAuth> {
  const c = service.recoveryChallenge(id, "1");
  const result = await service.recoverySession(id, "1", c.challengeId, sign(c.signingPayload, recoveryKeys(recSeed, id, recGen).signingSeed));
  assert.equal(result.rotationRequired, true);
  return { token: result.token, accountGeneration: "1" };
}
function proposal(op = "rotate-1", gen = "2", recSeed = new Uint8Array(32).fill(6)): RotationProposal {
  const keys = recoveryKeys(recSeed, id, gen);
  return { idempotencyKey: op, newRecoveryGeneration: gen, newRecoverySigningPublicKey: keys.signingPublicKey, newRecoveryReceivingPublicKey: keys.receivingPublicKey,
    envelopes: [{ environmentId: "dev", keyVersion: "1", envelope: Buffer.alloc(80, 12).toString("base64url") }] };
}
test("boot possession issues a device-bound session without a password; persisted nonce is single-use", async () => context(async ({ store }, service, vault) => {
  store.transaction(id, a => { a.sessions = []; });
  const c = service.bootChallenge(id, "reader", "1"), sig = sign(c.signingPayload, seeds.reader!);
  const result = await service.bootSession(id, "reader", "1", c.challengeId, sig);
  assert.equal(result.expiresAt, now + 3600);
  assert.equal((await vault.pull(id, { ...auth("reader"), token: result.token }, 0)).grants.length, 1);
  await assert.rejects(vault.pull(id, { ...auth("admin"), token: result.token }, 0), deny("device_proof_required"));
  await assert.rejects(service.bootSession(id, "reader", "1", c.challengeId, sig), deny("challenge_invalid"));
}));
test("boot rechecks both registered keys, device revocation, expiry and generation at completion", async () => context(async ({ store }, service) => {
  const c = service.bootChallenge(id, "reader", "1"), sig = sign(c.signingPayload, seeds.reader!);
  await assert.rejects(service.bootSession(id, "writer", "1", c.challengeId, sig), deny("challenge_invalid"));
  await assert.rejects(service.bootSession(id, "reader", "1", c.challengeId, sign(c.signingPayload, seeds.writer!)), deny("signature_invalid"));
  const original = store.read(id)!.devices.reader!.receivingPublicKey;
  store.transaction(id, a => { a.devices.reader!.receivingPublicKey = Buffer.alloc(32, 7).toString("base64url"); });
  await assert.rejects(service.bootSession(id, "reader", "1", c.challengeId, sig), deny("challenge_invalid"));
  store.transaction(id, a => { a.devices.reader!.receivingPublicKey = original; a.devices.reader!.revoked = true; });
  await assert.rejects(service.bootSession(id, "reader", "1", c.challengeId, sig), deny("device_untrusted"));
  store.transaction(id, a => { a.devices.reader!.revoked = false; a.grants[grantKey("dev", "reader")] = signGrant(grant("reader", { expiresAt: String(now) })); });
  await assert.rejects(service.bootSession(id, "reader", "1", c.challengeId, sig), deny("no_current_grant"));
  store.transaction(id, a => { a.grants[grantKey("dev", "reader")] = signGrant(grant("reader")); a.bootChallenges![0]!.expiresAt = now; });
  await assert.rejects(service.bootSession(id, "reader", "1", c.challengeId, sig), deny("challenge_invalid"));
  store.transaction(id, a => { a.generation = "2"; });
  await assert.rejects(service.bootSession(id, "reader", "1", c.challengeId, sig), deny("generation_stale"));
  assert.throws(() => service.bootChallenge(id, "stranger", "2"), deny("no_current_grant"));
}));
test("Go boot static vector agrees byte-for-byte with TypeScript strict Ed25519", () => {
  const v = JSON.parse(readFileSync(new URL("./vectors/device-boot-v1.json", import.meta.url), "utf8"));
  const p = v.proof;
  const fields = bootPayload(p.accountId, { id: p.challengeId, deviceId: p.deviceId, generation: p.accountGeneration, signingPublicKey: p.signingPublicKey, receivingPublicKey: p.receivingPublicKey, nonce: p.nonce, expiresAt: Number(p.expiresAt) });
  assert.equal(Buffer.from(canonical(fields)).toString("hex"), v.signingHex);
  assert.equal(ed25519.verify(Buffer.from(v.signature, "base64url"), canonical(fields), Buffer.from(p.signingPublicKey, "base64url"), { zip215: false }), true);
  fields[5] = Buffer.alloc(32, 99).toString("base64url");
  assert.equal(ed25519.verify(Buffer.from(v.signature, "base64url"), canonical(fields), Buffer.from(p.signingPublicKey, "base64url"), { zip215: false }), false);
});
test("recovery proof is one-use, bound to account/generation and restricted to recovery actions", async () => context(async ({ store }, service, vault) => {
  const c = service.recoveryChallenge(id, "1"), old = recoveryKeys(recoverySeed);
  await assert.rejects(service.recoverySession(id, "1", c.challengeId, sign(c.signingPayload, seeds.admin!)), deny("signature_invalid"));
  const changed = [...c.signingPayload]; changed[1] = "other-account";
  await assert.rejects(service.recoverySession(id, "1", c.challengeId, sign(changed, old.signingSeed)), deny("signature_invalid"));
  const result = await service.recoverySession(id, "1", c.challengeId, sign(c.signingPayload, old.signingSeed));
  const credentials = { token: result.token, accountGeneration: "1" };
  await assert.rejects(service.recoverySession(id, "1", c.challengeId, sign(c.signingPayload, old.signingSeed)), deny("challenge_invalid"));
  await assert.rejects(vault.pull(id, { ...credentials, deviceId: "admin" }, 0), deny("unauthorized"));
  await assert.rejects(vault.mutate(id, { ...credentials, deviceId: "writer" }, mutation()), deny("unauthorized"));
  await assert.rejects(vault.changeGrant(id, { ...credentials, deviceId: "admin" }, signGrant(grant("reader", { grantGeneration: "2" }))), deny("unauthorized"));
  await assert.rejects(service.requireRecoveryManagement(id, credentials), deny("recovery_rotation_required"));
  await vault.mutate(id, auth(), mutation());
  const material = await service.recoveryVault(id, credentials);
  assert.equal((material.events as unknown[]).length, 1); assert.equal((material.publicDevices as unknown[]).length, 4); assert.equal((material.grantHistory as unknown[]).length, 3);
  assert.equal(store.read(id)!.sessions.find(s => s.kind === "recovery")!.deviceId, undefined);
}));
test("only an all-environment trusted Admin or a current restricted recovery session may initiate rotation", async () => context(async ({ store }, service) => {
  for (const deviceId of ["reader", "writer"]) await assert.rejects(service.beginRotation(id, auth(deviceId), proposal()), deny("all_environment_admin_required"));
  const credentials = await recover(service);
  assert.equal((await service.beginRotation(id, credentials, proposal())).state, "pending");
  store.transaction(id, a => { a.environments.second = { ...a.environments.dev!, id: "second" }; });
  await assert.rejects(service.beginRotation(id, auth("admin"), proposal("admin-second")), deny("environment_forbidden"));
}));
test("rotation binds all envelopes, exact new generations and both new public keys", async () => context(async (_, service) => {
  const credentials = await recover(service), p = proposal();
  await assert.rejects(service.beginRotation(id, credentials, { ...p, envelopes: [] }), deny("envelope_set_stale_or_incomplete"));
  await assert.rejects(service.beginRotation(id, credentials, { ...p, envelopes: [p.envelopes[0]!, p.envelopes[0]!] }), deny("envelope_duplicate"));
  await assert.rejects(service.beginRotation(id, credentials, { ...p, envelopes: [{ ...p.envelopes[0]!, keyVersion: "2" }] }), deny("envelope_set_stale_or_incomplete"));
  await assert.rejects(service.beginRotation(id, credentials, { ...p, newRecoveryGeneration: "3" }), deny("recovery_generation_conflict"));
  await assert.rejects(service.beginRotation(id, credentials, { ...p, newRecoverySigningPublicKey: recoveryKeys(recoverySeed).signingPublicKey }), deny("recovery_key_unchanged"));
  const c = await service.beginRotation(id, credentials, p);
  await assert.rejects(service.beginRotation(id, credentials, { ...p, newRecoveryReceivingPublicKey: Buffer.alloc(32, 13).toString("base64url") }), deny("idempotency_conflict"));
  await assert.rejects(service.completeRotation(id, credentials, p.idempotencyKey, String(c.challengeId), sign(c.signingPayload, recoveryKeys(recoverySeed).signingSeed)), deny("signature_invalid"));
  const substituted = [...c.signingPayload as string[]]; substituted[10] = Buffer.alloc(32, 13).toString("base64url");
  await assert.rejects(service.completeRotation(id, credentials, p.idempotencyKey, String(c.challengeId), sign(substituted, recoveryKeys(new Uint8Array(32).fill(6), id, "2").signingSeed)), deny("signature_invalid"));
  assert.equal(envelopeHash(p.envelopes), c.envelopesHash);
}));
test("atomic rotation switches keys and every envelope once, invalidates old recovery sessions/code, keeps recovery separate from enrollment", async () => context(async ({ store }, service, vault) => {
  const credentials = await recover(service), second = await recover(service), p = proposal(), c = await service.beginRotation(id, credentials, p);
  const newSeed = new Uint8Array(32).fill(6), signature = sign(c.signingPayload, recoveryKeys(newSeed, id, "2").signingSeed);
  const result = await service.completeRotation(id, credentials, p.idempotencyKey, String(c.challengeId), signature);
  assert.equal(result.sequence, 1); assert.equal(result.replayed, false);
  const persisted = store.read(id)!;
  assert.equal(persisted.recoveryGeneration, "2"); assert.equal(persisted.recoverySigningPublicKey, p.newRecoverySigningPublicKey); assert.equal(persisted.recoveryReceivingPublicKey, p.newRecoveryReceivingPublicKey);
  assert.equal(persisted.environments.dev!.recoveryEnvelope, p.envelopes[0]!.envelope); assert.equal(persisted.environments.dev!.recoveryGeneration, "2");
  assert.equal((await service.rotationStatus(id, credentials, p.idempotencyKey)).state, "complete");
  assert.equal((await service.completeRotation(id, credentials, p.idempotencyKey, String(c.challengeId), signature)).sequence, 1);
  assert.equal((await service.beginRotation(id, credentials, { ...p, envelopes: [{ envelope: p.envelopes[0]!.envelope, keyVersion: "1", environmentId: "dev" }] })).sequence, 1);
  await assert.rejects(service.completeRotation(id, credentials, p.idempotencyKey, String(c.challengeId), Buffer.alloc(64, 1).toString("base64url")), deny("idempotency_conflict"));
  await assert.rejects(service.recoveryVault(id, second), deny("unauthorized"));
  await service.requireRecoveryManagement(id, credentials);
  assert.equal((await service.recoveryVault(id, credentials)).rotationRequired, false);
  await assert.rejects(vault.pull(id, { ...credentials, deviceId: "admin" }, 0), deny("unauthorized"));
  const fresh = service.recoveryChallenge(id, "1");
  await assert.rejects(service.recoverySession(id, "1", fresh.challengeId, sign(fresh.signingPayload, recoveryKeys(recoverySeed).signingSeed)), deny("signature_invalid"));
  assert.equal((await service.recoverySession(id, "1", fresh.challengeId, sign(fresh.signingPayload, recoveryKeys(newSeed, id, "2").signingSeed))).rotationRequired, true);
  assert.equal(store.read(id)!.sequence, 1);
}));
test("rotation query resolves unknown results; changed environment keys, sessions, expiry and resets reject pending proof", async () => context(async ({ store }, service) => {
  const credentials = await recover(service), other = await recover(service), p = proposal(), c = await service.beginRotation(id, credentials, p), signature = sign(c.signingPayload, recoveryKeys(new Uint8Array(32).fill(6), id, "2").signingSeed);
  assert.equal((await service.rotationStatus(id, credentials, "not-started")).state, "absent");
  assert.equal((await service.rotationStatus(id, credentials, p.idempotencyKey)).state, "pending");
  await assert.rejects(service.rotationStatus(id, other, p.idempotencyKey), deny("rotation_forbidden"));
  await assert.rejects(service.completeRotation(id, other, p.idempotencyKey, String(c.challengeId), signature), deny("challenge_invalid"));
  store.transaction(id, a => { a.environments.dev!.keyVersion = "2"; a.environments.dev!.recoveryKeyVersion = "2"; });
  await assert.rejects(service.completeRotation(id, credentials, p.idempotencyKey, String(c.challengeId), signature), deny("envelope_set_stale_or_incomplete"));
  store.transaction(id, a => { a.environments.dev!.keyVersion = "1"; a.environments.dev!.recoveryKeyVersion = "1"; a.recoveryRotations![p.idempotencyKey]!.expiresAt = now; });
  assert.equal((await service.rotationStatus(id, credentials, p.idempotencyKey)).state, "expired");
  await assert.rejects(service.completeRotation(id, credentials, p.idempotencyKey, String(c.challengeId), signature), deny("challenge_invalid"));
  store.transaction(id, a => { a.generation = "2"; a.sessions = []; a.environments = {}; a.devices = {}; a.grants = {}; a.recoverySigningPublicKey = null; a.recoveryReceivingPublicKey = null; });
  await assert.rejects(service.rotationStatus(id, credentials, p.idempotencyKey), deny("generation_stale"));
}));
test("SQLite enforces mandatory recovery envelopes and rolls back entire rotation on a real SQL update failure", async () => context(async ({ store, sql }, service) => {
  assert.throws(() => store.transaction(id, a => { a.environments.dev!.keyVersion = "2"; }), deny("recovery_envelope_stale"));
  assert.equal(store.read(id)!.environments.dev!.keyVersion, "1");
  assert.throws(() => store.transaction(id, a => { a.environments.dev!.recoveryEnvelope = ""; }), deny("encoding_invalid"));
  const credentials = await recover(service), p = proposal(), c = await service.beginRotation(id, credentials, p), signature = sign(c.signingPayload, recoveryKeys(new Uint8Array(32).fill(6), id, "2").signingSeed);
  let fail = true;
  const injected: Sql = { execute: (query, params) => { if (fail && query.startsWith("UPDATE accounts")) { fail = false; throw new Error("synthetic SQL write failure"); } sql.execute(query, params); }, rows: (query, params) => sql.rows(query, params), transaction: operation => sql.transaction(operation) };
  const failing = new LifecycleService(new SqlStore(injected), () => now);
  await assert.rejects(failing.completeRotation(id, credentials, p.idempotencyKey, String(c.challengeId), signature), /synthetic SQL write failure/);
  const persisted = store.read(id)!;
  assert.equal(persisted.sequence, 0); assert.equal(persisted.recoveryGeneration, "1"); assert.equal(persisted.recoveryRotations![p.idempotencyKey]!.state, "pending");
  assert.equal(persisted.environments.dev!.recoveryEnvelope, Buffer.alloc(80, 9).toString("base64url"));
  assert.equal((await service.completeRotation(id, credentials, p.idempotencyKey, String(c.challengeId), signature)).sequence, 1);
}));
test("SQLite reopen keeps pending/completed operation state and consumed boot/recovery nonces", async () => context(async ({ sql }, service, _, path) => {
  const credentials = await recover(service), p = proposal(), c = await service.beginRotation(id, credentials, p), signature = sign(c.signingPayload, recoveryKeys(new Uint8Array(32).fill(6), id, "2").signingSeed);
  const boot = service.bootChallenge(id, "reader", "1"), bootSig = sign(boot.signingPayload, seeds.reader!);
  await service.bootSession(id, "reader", "1", boot.challengeId, bootSig);
  sql.close(); const reopened = nodeStore(path);
  try { const next = new LifecycleService(reopened.store, () => now);
    assert.equal((await next.rotationStatus(id, credentials, p.idempotencyKey)).state, "pending");
    await assert.rejects(next.bootSession(id, "reader", "1", boot.challengeId, bootSig), deny("challenge_invalid"));
    assert.equal((await next.completeRotation(id, credentials, p.idempotencyKey, String(c.challengeId), signature)).sequence, 1);
    reopened.sql.close(); const final = nodeStore(path);
    try { const last = new LifecycleService(final.store, () => now); assert.equal((await last.rotationStatus(id, credentials, p.idempotencyKey)).state, "complete"); assert.equal((await last.completeRotation(id, credentials, p.idempotencyKey, String(c.challengeId), signature)).replayed, true); }
    finally { final.sql.close(); }
  } finally { try { reopened.sql.close(); } catch {} }
}));
test("HTTP lifecycle routes never create trust, reject password-only scope, and enforce exact body shape", async () => context(async (_, service, vault) => {
  const request = (path: string, value: unknown, token?: string) => new Request(`https://selfhost.example.invalid/v1/accounts/${id}/${path}`, { method: "POST", headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}`, "x-harmonia-account-generation": "1" } : {}) }, body: JSON.stringify(value) });
  const challenge = await route(request("boot-challenges", { deviceId: "reader", accountGeneration: "1" }), vault);
  assert.equal(challenge.status, 200); const data = await challenge.json() as { challengeId: string; signingPayload: string[] };
  const result = await route(request("boot-sessions", { deviceId: "reader", accountGeneration: "1", challengeId: data.challengeId, signature: sign(data.signingPayload, seeds.reader!) }), vault); assert.equal(result.status, 200);
  assert.equal((await route(request("boot-challenges", { deviceId: "reader", accountGeneration: "1", bootstrap: true }), vault)).status, 400);
  assert.equal((await route(request("boot-challenges", { deviceId: "stranger", accountGeneration: "1" }), vault)).status, 403);
  const credentials = await recover(service);
  const recChallenge = await route(request("recovery-challenges", { accountGeneration: "1" }), vault); assert.equal(recChallenge.status, 200);
  assert.equal((await route(request("recovery-rotations", proposal(), credentials.token), vault)).status, 200);
}));

function manifest(recSeed: Uint8Array, gen: string): TrustRoot {
  const rec = recoveryKeys(recSeed, id, gen), root: TrustRoot = { rootDeviceId: "admin", rootSigningPublicKey: Buffer.from(ed25519.getPublicKey(seeds.admin!)).toString("base64url"), rootReceivingPublicKey: grant("admin").subjectReceivingPublicKey, recoveryGeneration: gen, recoverySigningPublicKey: rec.signingPublicKey, recoveryReceivingPublicKey: rec.receivingPublicKey, signature: "" };
  root.signature = sign(trustRootPayload(id, "1", root), rec.signingSeed); return root;
}
test("recovery rotation atomically re-signs a fixed trust root, rejects missing/substituted manifests and binds its signature", async () => context(async ({ store }, service) => {
  const original = manifest(recoverySeed, "1"); store.transaction(id, a => { a.trustRoot = original; });
  const credentials = await recover(service), p = proposal(), recSeed = new Uint8Array(32).fill(6);
  assert.deepEqual((await service.recoveryVault(id, credentials)).trustRoot, original);
  await assert.rejects(service.beginRotation(id, credentials, p), deny("trust_root_required"));
  const replacement = manifest(recSeed, "2");
  const substituted = { ...replacement, rootDeviceId: "writer", rootSigningPublicKey: Buffer.from(ed25519.getPublicKey(seeds.writer!)).toString("base64url") };
  substituted.signature = sign(trustRootPayload(id, "1", substituted), recoveryKeys(recSeed, id, "2").signingSeed);
  await assert.rejects(service.beginRotation(id, credentials, { ...p, newTrustRoot: substituted }), deny("trust_root_substitution"));
  await assert.rejects(service.beginRotation(id, credentials, { ...p, newTrustRoot: { ...replacement, signature: original.signature } }), deny("signature_invalid"));
  const complete = { ...p, newTrustRoot: replacement }, c = await service.beginRotation(id, credentials, complete);
  assert.equal(c.trustRootHash, trustRootHash(id, "1", replacement)); assert.equal((c.signingPayload as string[]).length, 13);
  const dropped = (c.signingPayload as string[]).slice(0, 12);
  await assert.rejects(service.completeRotation(id, credentials, p.idempotencyKey, String(c.challengeId), sign(dropped, recoveryKeys(recSeed, id, "2").signingSeed)), deny("signature_invalid"));
  await service.completeRotation(id, credentials, p.idempotencyKey, String(c.challengeId), sign(c.signingPayload, recoveryKeys(recSeed, id, "2").signingSeed));
  assert.deepEqual(store.read(id)!.trustRoot, replacement); assert.equal(store.read(id)!.recoveryGeneration, "2");
  assert.equal((await service.beginRotation(id, credentials, complete)).state, "complete");
  const resigned = { ...replacement, rootReceivingPublicKey: Buffer.alloc(32, 8).toString("base64url") }; resigned.signature = sign(trustRootPayload(id, "1", resigned), recoveryKeys(recSeed, id, "2").signingSeed);
  assert.throws(() => store.transaction(id, a => { a.trustRoot = resigned; }), deny("trust_root_stale"));
}));

test("concurrent nonce completion admits exactly one device/recovery session, and expired recovery challenges are rejected", async () => context(async ({ store }, service) => {
  const boot = service.bootChallenge(id, "reader", "1"), signature = sign(boot.signingPayload, seeds.reader!);
  const attempts = await Promise.allSettled([service.bootSession(id, "reader", "1", boot.challengeId, signature), service.bootSession(id, "reader", "1", boot.challengeId, signature)]);
  assert.equal(attempts.filter(a => a.status === "fulfilled").length, 1);
  const c = service.recoveryChallenge(id, "1"), proof = sign(c.signingPayload, recoveryKeys(recoverySeed).signingSeed);
  const recovering = await Promise.allSettled([service.recoverySession(id, "1", c.challengeId, proof), service.recoverySession(id, "1", c.challengeId, proof)]);
  assert.equal(recovering.filter(a => a.status === "fulfilled").length, 1);
  const expired = service.recoveryChallenge(id, "1"); store.transaction(id, a => { a.recoveryChallenges!.find(c => c.id === expired.challengeId)!.expiresAt = now; });
  await assert.rejects(service.recoverySession(id, "1", expired.challengeId, sign(expired.signingPayload, recoveryKeys(recoverySeed).signingSeed)), deny("challenge_invalid"));
  assert.equal(store.read(id)!.sessions.filter(s => s.kind === "recovery").length, 1);
}));
test("competing Admin rotations become superseded; expired sessions and devices cannot finish a proof", async () => context(async ({ store }, service) => {
  const credentials = auth("admin"), p = proposal(), pending = await service.beginRotation(id, credentials, p), other = await service.beginRotation(id, credentials, proposal("rotate-other", "2", new Uint8Array(32).fill(7)));
  await service.completeRotation(id, credentials, p.idempotencyKey, String(pending.challengeId), sign(pending.signingPayload, recoveryKeys(new Uint8Array(32).fill(6), id, "2").signingSeed));
  assert.equal((await service.rotationStatus(id, credentials, "rotate-other")).state, "superseded");
  await assert.rejects(service.completeRotation(id, credentials, "rotate-other", String(other.challengeId), sign(other.signingPayload, recoveryKeys(new Uint8Array(32).fill(7), id, "2").signingSeed)), deny("challenge_invalid"));
  store.transaction(id, a => { a.devices.admin!.revoked = true; });
  await assert.rejects(service.rotationStatus(id, credentials, p.idempotencyKey), deny("device_untrusted"));
  store.transaction(id, a => { a.devices.admin!.revoked = false; a.sessions = a.sessions.map(s => ({ ...s, expiresAt: now })); });
  await assert.rejects(service.rotationStatus(id, credentials, p.idempotencyKey), deny("unauthorized"));
}));

test("Go recovery/rotation static vector agrees with TypeScript envelope hash, signed trust root and all 13 fields", () => {
  const v = JSON.parse(readFileSync(new URL("./vectors/recovery-lifecycle-v1.json", import.meta.url), "utf8")), p = v.recoveryProof, rotation = v.rotationProof;
  const proof = recoveryPayload(p.accountId, { id: p.challengeId, generation: p.accountGeneration, recoveryGeneration: p.recoveryGeneration, nonce: p.nonce, expiresAt: Number(p.expiresAt), signingPublicKey: v.priorTrustRoot.recoverySigningPublicKey });
  assert.equal(Buffer.from(canonical(proof)).toString("hex"), v.recoverySigningHex);
  assert.equal(ed25519.verify(Buffer.from(v.recoverySignature, "base64url"), canonical(proof), Buffer.from(v.priorTrustRoot.recoverySigningPublicKey, "base64url"), { zip215: false }), true);
  assert.equal(envelopeHash(v.proposal.envelopes), rotation.envelopesHash); assert.equal(trustRootHash(rotation.accountId, rotation.accountGeneration, v.proposal.newTrustRoot), rotation.trustRootHash);
  const fields = rotationPayload(rotation.accountId, { state: "pending", id: rotation.challengeId, generation: rotation.accountGeneration, recoveryGeneration: rotation.recoveryGeneration, sessionHash: rotation.sessionHash, deviceId: null, nonce: rotation.nonce, expiresAt: Number(rotation.expiresAt), proposal: v.proposal, envelopesHash: rotation.envelopesHash, trustRootHash: rotation.trustRootHash });
  assert.equal(Buffer.from(canonical(fields)).toString("hex"), v.rotationSigningHex);
  assert.equal(ed25519.verify(Buffer.from(v.rotationSignature, "base64url"), canonical(fields), Buffer.from(rotation.newRecoverySigningPublicKey, "base64url"), { zip215: false }), true);
  for (let i = 0; i < fields.length; i++) { const changed = [...fields]; changed[i] += "x"; assert.equal(ed25519.verify(Buffer.from(v.rotationSignature, "base64url"), canonical(changed), Buffer.from(rotation.newRecoverySigningPublicKey, "base64url"), { zip215: false }), false); }
});
