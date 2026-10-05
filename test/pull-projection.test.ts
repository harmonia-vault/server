import {VaultService} from "../src/service.js";
import test from "node:test";
import assert from "node:assert/strict";
import { ed25519 } from "@noble/curves/ed25519.js";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { nodeStore } from "../src/node-store.js";
import { EnvironmentService, environmentChangeBytes, type EnvironmentChange, type SignedEnvironmentChange } from "../src/environments.js";
import { route } from "../src/http.js";
import { Fault, grantKey } from "../src/model.js";
import { submitEnvironmentChange, auth, grant, mutation, now, seeds, seed, signGrant } from "./fixtures.js";
const id = "synthetic-account";
const sign = (c: EnvironmentChange): SignedEnvironmentChange => ({ change: c, signature: Buffer.from(ed25519.sign(environmentChangeBytes(c), seeds.admin!)).toString("base64url") });
async function context(run: (c: ReturnType<typeof nodeStore>, vault: Awaited<ReturnType<typeof seed>>, env: EnvironmentService) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "harmonia-pull-projection-")), c = nodeStore(join(dir, "account.sqlite"));
  try { await run(c, await seed(c.store), new EnvironmentService(c.store, () => now)); } finally { c.sql.close(); rmSync(dir, { recursive: true, force: true }); }
}
test("authorization projection preserves current signed grants and sequence while omitting ordinary mutations", async () => context(async ({ store }, vault) => {
  await vault.mutate(id, auth(), mutation());
  const ordinary = await vault.pull(id, auth("reader"), 0), projection = await vault.pull(id, auth("reader"), 0, "authorizations");
  assert.equal(projection.scope, "authorizations"); assert.equal(projection.sequence, ordinary.sequence); assert.deepEqual(projection.grants, ordinary.grants); assert.deepEqual(projection.events, []); assert.equal(ordinary.events.length, 1); assert.equal(ordinary.scope, undefined);
  await vault.changeGrant(id,auth("admin"),signGrant(grant("reader",{grantGeneration:"2",idempotencyKey:"expire-reader",expiresAt:String(now+1)})));
  assert.equal((await new VaultService(store,vault.policy,()=>now+1).pull(id, auth("reader"), 0, "authorizations")).grants[0]!.grant.expiresAt, String(now+1));
  store.transaction(id, a => { a.devices.reader!.revoked = true; });
  await assert.rejects(vault.pull(id, auth("reader"), 0, "authorizations"), e => e instanceof Fault && e.code === "device_untrusted");
}));
test("authorized deletion tombstones survive grant removal, filter subjects and checkpoints, and never expose another environment", async () => context(async (_, vault, env) => {
  await vault.mutate(id, auth(), mutation());
  const privateChange: EnvironmentChange = { accountId: id, accountGeneration: "1", deviceId: "admin", environmentId: "private", operation: "create", authorityEnvironmentId: "dev", authorityKeyVersion: "1", authorityGrantGeneration: "1", previousKeyVersion: "0", keyVersion: "1", expectedSequence: "4", idempotencyKey: "private-create", labelPayload: Buffer.alloc(40, 8).toString("base64url"), recoveryGeneration: "1", recoveryEnvelope: Buffer.alloc(80, 8).toString("base64url"), grants: [signGrant(grant("admin", { environmentId: "private", idempotencyKey: "private-admin" }))], mutations: [] };
  await submitEnvironmentChange(env, id, auth("admin"), sign(privateChange));
  const deleted = sign({ ...privateChange, environmentId: "dev", operation: "delete", previousKeyVersion: "1", expectedSequence: "5", idempotencyKey: "delete-dev", labelPayload: "", recoveryEnvelope: "", grants: [] });
  await submitEnvironmentChange(env, id, auth("admin"), deleted);
  for (const scope of [undefined, "authorizations"] as const) {
    const result = await vault.pull(id, auth("reader"), 1, scope); assert.deepEqual(result.grants, []); assert.deepEqual(result.events, []); assert.equal(result.environmentEvents!.length, 1);
    const tombstone = result.environmentEvents![0]!; assert.equal(tombstone.sequence, 6); assert.deepEqual(tombstone.change, deleted);
    assert.equal(ed25519.verify(Buffer.from(tombstone.change.signature, "base64url"), environmentChangeBytes(tombstone.change.change), Buffer.from(tombstone.authorization.grant.subjectSigningPublicKey, "base64url"), { zip215: false }), true);
    assert.deepEqual((await vault.pull(id, auth("reader"), 6, scope)).environmentEvents, []);
  }
  assert.equal((await vault.pull(id, auth("admin"), 1, "authorizations")).environmentEvents!.length, 2);
}));
test("HTTP authorization scope is explicit, refuses unknown/duplicate values and keeps device session checks", async () => context(async (_, vault) => {
  await vault.mutate(id, auth(), mutation());
  const request = (query: string) => new Request(`https://selfhost.example.invalid/v1/accounts/${id}/pull?after=0&capability=issuer-recovery-dag-v1${query}`, { headers: {"Harmonia-Protocol-Major":"2", authorization: `Bearer ${auth("reader").token}`, "x-harmonia-device-id": "reader", "x-harmonia-account-generation": "1" } });
  const response = await route(request("&scope=authorizations"), vault); assert.equal(response.status, 200);
  const result = await response.json() as { scope: string; events: unknown[] }; assert.equal(result.scope, "authorizations"); assert.deepEqual(result.events, []); assert.equal(response.headers.get("cache-control"), "no-store");
  for (const query of ["&scope=anything", "&scope=", "&scope=authorizations&scope=authorizations"]) assert.equal((await route(request(query), vault)).status, 400);
  const login = await vault.login("synthetic@example.invalid", "ab".repeat(32));
  const unbound = request("&scope=authorizations"); unbound.headers.set("authorization", `Bearer ${login.token}`); assert.equal((await route(unbound, vault)).status, 403);
}));

test("revoked/expired readers receive no historical labels or rotation ciphertext while empty deletion tombstones still arrive", async () => context(async ({ store }, vault, env) => {
  await vault.mutate(id, auth(), mutation());
  const change: EnvironmentChange = { accountId: id, accountGeneration: "1", deviceId: "admin", environmentId: "dev", operation: "rename", authorityEnvironmentId: "dev", authorityKeyVersion: "1", authorityGrantGeneration: "1", previousKeyVersion: "1", keyVersion: "1", expectedSequence: "4", idempotencyKey: "rename-dev", labelPayload: Buffer.alloc(40, 15).toString("base64url"), recoveryGeneration: "1", recoveryEnvelope: "", grants: [], mutations: [] };
  await submitEnvironmentChange(env, id, auth("admin"), sign(change)); assert.equal((await vault.pull(id, auth("reader"), 0, "authorizations")).environmentEvents!.length, 1);
  await vault.changeGrant(id, auth("admin"), signGrant(grant("reader", { grantGeneration: "2", role: "none", envelope: "", idempotencyKey: "reader-revoke" })));
  const rotated = sign({ ...change, operation: "rotate", keyVersion: "2", expectedSequence: "6", idempotencyKey: "rotate-dev", labelPayload: Buffer.alloc(40, 16).toString("base64url"), recoveryEnvelope: Buffer.alloc(80, 10).toString("base64url"), grants: ["admin", "writer"].map(deviceId => signGrant(grant(deviceId, { keyVersion: "2", grantGeneration: "2", idempotencyKey: `rotate-${deviceId}` }))), mutations: [mutation("admin", { keyVersion: "2", grantGeneration: "2", idempotencyKey: "rotation-value" })] });
  await submitEnvironmentChange(env, id, auth("admin"), rotated);
  for (const scope of [undefined, "authorizations"] as const) {
    assert.deepEqual((await vault.pull(id, auth("reader"), 0, scope)).environmentEvents, []);
    assert.equal((await vault.pull(id, auth("writer"), 0, scope)).environmentEvents!.length, 2);
  }
  await vault.changeGrant(id,auth("admin"),signGrant(grant("writer",{keyVersion:"2",grantGeneration:"3",expiresAt:String(now+1),idempotencyKey:"expire-rotated-writer"})));
  assert.deepEqual((await new VaultService(store,vault.policy,()=>now+1).pull(id, auth("writer"), 0, "authorizations")).environmentEvents, []);
  const privateChange = sign({ ...change, operation: "create", environmentId: "private", authorityKeyVersion: "2", authorityGrantGeneration: "2", previousKeyVersion: "0", keyVersion: "1", expectedSequence: "9", idempotencyKey: "private-create", recoveryEnvelope: Buffer.alloc(80, 11).toString("base64url"), grants: [signGrant(grant("admin", { environmentId: "private", idempotencyKey: "private-admin" }))] });
  await submitEnvironmentChange(env, id, auth("admin"), privateChange);
  await submitEnvironmentChange(env, id, auth("admin"), sign({ ...change, operation: "delete", authorityKeyVersion: "2", authorityGrantGeneration: "2", previousKeyVersion: "2", keyVersion: "2", expectedSequence: "10", idempotencyKey: "delete-dev", labelPayload: "" }));
  for (const deviceId of ["reader", "writer"]) { const view = await vault.pull(id, auth(deviceId), 0, "authorizations"); assert.equal(view.environmentEvents!.length, 1); assert.equal(view.environmentEvents![0]!.change.change.operation, "delete"); assert.equal(view.environmentEvents![0]!.change.change.labelPayload, ""); assert.deepEqual(view.environmentEvents![0]!.change.change.mutations, []); }
}));
