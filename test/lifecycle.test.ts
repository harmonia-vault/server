import {RecoveryDAGService} from "../src/recovery-dag-service.js";
import test from "node:test";
import assert from "node:assert/strict";
import { ed25519 } from "@noble/curves/ed25519.js";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { nodeStore, NodeSql } from "../src/node-store.js";
import { SqlStore, type Sql } from "../src/store.js";
import { LifecycleService } from "../src/lifecycle.js";
import { canonical, bootPayload, envelopeHash, recoveryPayload, trustRootPayload, trustRootHash, type TrustRoot, type RecoveryAuth } from "../src/lifecycle-wire.js";
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
  store.transaction(id, a => { a.generation = "2"; delete a.trustRoot; });
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
  await vault.mutate(id, auth(), mutation());
  const material = await new RecoveryDAGService(store, () => now).vault(id, credentials);
  assert.equal((material.events as unknown[]).length, 1); assert.equal((material.publicDevices as unknown[]).length, 4); assert.equal((material.grantHistory as unknown[]).length, 3);
  assert.equal(store.read(id)!.sessions.find(s => s.kind === "recovery")!.deviceId, undefined);
}));
test("HTTP lifecycle routes never create trust, reject password-only scope, and enforce exact body shape", async () => context(async (_, service, vault) => {
  const request = (path: string, value: unknown, token?: string) => new Request(`https://selfhost.example.invalid/v1/accounts/${id}/${path}`, { method: "POST", headers: {"Harmonia-Protocol-Major":"2", "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}`, "x-harmonia-account-generation": "1" } : {}) }, body: JSON.stringify(value) });
  const challenge = await route(request("boot-challenges", { deviceId: "reader", accountGeneration: "1" }), vault);
  assert.equal(challenge.status, 200); const data = await challenge.json() as { challengeId: string; signingPayload: string[] };
  const result = await route(request("boot-sessions", { deviceId: "reader", accountGeneration: "1", challengeId: data.challengeId, signature: sign(data.signingPayload, seeds.reader!) }), vault); assert.equal(result.status, 200);
  assert.equal((await route(request("boot-challenges", { deviceId: "reader", accountGeneration: "1", bootstrap: true }), vault)).status, 400);
  assert.equal((await route(request("boot-challenges", { deviceId: "stranger", accountGeneration: "1" }), vault)).status, 403);
  const credentials = await recover(service);
  const recChallenge = await route(request("recovery-challenges", { accountGeneration: "1" }), vault); assert.equal(recChallenge.status, 200);
  assert.equal((await route(request("recovery-rotations", {}, credentials.token), vault)).status, 404);
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
