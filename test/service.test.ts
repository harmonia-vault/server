import test from "node:test";
import assert from "node:assert/strict";
import { ed25519 } from "@noble/curves/ed25519.js";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { nodeStore } from "../src/node-store.js";
import { VaultService } from "../src/service.js";
import { Fault, grantKey } from "../src/model.js";
import { hashCredential, verifyCredential } from "../src/password.js";
import { route } from "../src/http.js";
import { smtpOptions } from "../src/smtp.js";
import { auth, clientCredential, email, fixtureAccount, grant, mutation, now, seed, signGrant, token, tokenFor, seeds } from "./fixtures.js";
async function withStore(run: (context: ReturnType<typeof nodeStore>, service: VaultService, path: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "harmonia-server-test-")); const path = join(dir, "test.sqlite");
  const context = nodeStore(path);
  try { await run(context, await seed(context.store), path); } finally { try { context.sql.close(); } catch {} rmSync(dir, { recursive: true, force: true }); }
}
function denies(code: string): (e: unknown) => boolean { return e => e instanceof Fault && e.code === code; }
test("accepted writes are ordered, identical retry keeps sequence and pull catches up", async () => withStore(async (_, service) => {
  assert.deepEqual(await service.mutate("synthetic-account", auth(), mutation()), { sequence: 1, replayed: false });
  assert.deepEqual(await service.mutate("synthetic-account", auth(), mutation()), { sequence: 1, replayed: true });
  assert.equal((await service.mutate("synthetic-account", auth(), mutation("writer", { idempotencyKey: "write-2" }))).sequence, 2);
  const pull = await service.pull("synthetic-account", auth("reader"), 1);
  assert.equal(pull.sequence, 2); assert.deepEqual(pull.events.map(e => e.sequence), [2]);
}));
test("same id with changed signed content is rejected", async () => withStore(async (_, service) => {
  await service.mutate("synthetic-account", auth(), mutation());
  await assert.rejects(service.mutate("synthetic-account", auth(), mutation("writer", { name: "OTHER_KEY" })), denies("idempotency_conflict"));
}));
test("RO, ungranted, wrong device and tampered signatures cannot write", async () => withStore(async (_, service) => {
  await assert.rejects(service.mutate("synthetic-account", auth("reader"), mutation("reader")), denies("write_forbidden"));
  await assert.rejects(service.mutate("synthetic-account", auth("stranger"), mutation("stranger")), denies("environment_forbidden"));
  await assert.rejects(service.mutate("synthetic-account", auth("reader"), mutation()), denies("binding_invalid"));
  const tampered = mutation(); tampered.mutation.payload = Buffer.alloc(40, 11).toString("base64url");
  await assert.rejects(service.mutate("synthetic-account", auth(), tampered), denies("signature_invalid"));
}));
test("signed downgrade and revocation take effect before retry; revoked pull returns no ciphertext", async () => withStore(async (_, service) => {
  await service.mutate("synthetic-account", auth(), mutation());
  const downgrade = signGrant(grant("writer", { grantGeneration: "2", role: "ro", idempotencyKey: "downgrade" }));
  assert.equal((await service.changeGrant("synthetic-account", auth("admin"), downgrade)).sequence, 2);
  await assert.rejects(service.mutate("synthetic-account", auth(), mutation()), denies("write_forbidden"));
  assert.equal((await service.changeGrant("synthetic-account", auth("admin"), downgrade)).replayed, true);
  const revoke = signGrant(grant("writer", { grantGeneration: "3", role: "none", envelope: "", idempotencyKey: "revoke" }));
  await service.changeGrant("synthetic-account", auth("admin"), revoke);
  const pull = await service.pull("synthetic-account", auth(), 0);
  assert.equal(pull.grants[0]?.grant.role, "none"); assert.equal(pull.events.length, 0);
}));
test("expired grants deny reads and writes at exact boundary", async () => withStore(async ({ store }, service) => {
  store.transaction("synthetic-account", a => { a.grants[grantKey("dev", "writer")] = signGrant(grant("writer", { expiresAt: String(now) })); });
  await assert.rejects(service.mutate("synthetic-account", auth(), mutation()), denies("environment_forbidden"));
  assert.equal((await service.pull("synthetic-account", auth(), 0)).events.length, 0);
}));
test("non-admin grants, key substitution, stale generations and grant replay fail", async () => withStore(async (_, service) => {
  const g = signGrant(grant("reader", { grantGeneration: "2", role: "rw", idempotencyKey: "promote" }));
  await assert.rejects(service.changeGrant("synthetic-account", auth(), g), denies("binding_invalid"));
  await assert.rejects(service.changeGrant("synthetic-account", auth("admin"), signGrant(grant("reader", { grantGeneration: "3" }))), denies("grant_generation_conflict"));
  await assert.rejects(service.changeGrant("synthetic-account", auth("admin"), signGrant(grant("reader", { subjectSigningPublicKey: Buffer.alloc(32, 99).toString("base64url"), grantGeneration: "2" }))), denies("device_key_mismatch"));
  await assert.rejects(service.mutate("synthetic-account", auth(), mutation("writer", { grantGeneration: "2" })), denies("grant_stale"));
}));
test("account isolation and generation invalidation are checked against current persisted state", async () => withStore(async ({ store }, service) => {
  store.create(await fixtureAccount("other-account", "other@example.invalid"));
  await assert.rejects(service.mutate("other-account", auth(), mutation()), denies("binding_invalid"));
  store.transaction("synthetic-account", a => { a.generation = "2"; a.sessions = []; a.devices = {}; a.grants = {}; a.events = []; a.idempotency = {}; });
  await assert.rejects(service.pull("synthetic-account", auth(), 0), denies("generation_stale"));
  await assert.rejects(service.mutate("synthetic-account", auth(), mutation()), denies("generation_stale"));
}));
test("SQLite reopen preserves accepted event, authorization, token and idempotency", async () => withStore(async ({ sql }, service, path) => {
  await service.mutate("synthetic-account", auth(), mutation()); sql.close();
  const restarted = nodeStore(path);
  try { const next = new VaultService(restarted.store, service.policy, () => now);
    assert.equal((await next.pull("synthetic-account", auth(), 0)).events.length, 1);
    assert.deepEqual(await next.mutate("synthetic-account", auth(), mutation()), { sequence: 1, replayed: true });
  } finally { restarted.sql.close(); }
}));
test("transaction rollback does not consume sequence", async () => withStore(async ({ store }, service) => {
  assert.throws(() => store.transaction("synthetic-account", a => { a.sequence = 100; throw new Error("synthetic rollback"); }));
  assert.equal((await service.mutate("synthetic-account", auth(), mutation())).sequence, 1);
}));
test("password-equivalent SHA256 is randomly salted Argon2id at 64 MiB / 3 passes; login does not establish device trust", async () => withStore(async (_, service) => {
  const h1 = await hashCredential(clientCredential); const h2 = await hashCredential(clientCredential);
  assert.notEqual(h1, h2); assert.match(h1, /^\$argon2id\$v=19\$m=65536,t=3,p=1\$/);
  assert.equal(await verifyCredential(clientCredential, h1), true); assert.equal(await verifyCredential("ff".repeat(32), h1), false);
  const login = await service.login(email, clientCredential);
  await assert.rejects(service.pull(login.accountId, { token: login.token, accountGeneration: login.accountGeneration, deviceId: "not-enrolled" }, 0), denies("device_untrusted"));
}));
test("registration switches are independent; verification and pairing remain fail closed", async () => withStore(async ({ store }) => {
  await assert.rejects(new VaultService(store, { allowRegistration: false, requireEmailVerification: false }).register(email, clientCredential), denies("registration_disabled"));
  await assert.rejects(new VaultService(store, { allowRegistration: true, requireEmailVerification: true }).register(email, clientCredential), denies("email_verification_unavailable"));
  const service = new VaultService(store, { allowRegistration: true, requireEmailVerification: false });
  const account = await service.register("new@example.invalid", clientCredential); const login = await service.login("new@example.invalid", clientCredential);
  await assert.rejects(service.pull(account.accountId, { deviceId: "admin", token: login.token, accountGeneration: "1" }, 0), denies("device_untrusted"));
}));
test("HTTP rejects remote plain HTTP, malformed body, and enrollment/reset bypass routes", async () => withStore(async (_, service) => {
  const request = (path: string, data: unknown) => new Request(`https://selfhost.example.invalid${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(data) });
  assert.equal((await route(new Request("http://remote.example.invalid/health"), service)).status, 400);
  for (const path of ["/v1/bootstrap", "/v1/reset", "/v1/pairing"]) assert.equal((await route(request(path, {}), service)).status, 404);
  assert.equal((await route(request("/v1/login", { email }), service)).status, 400);
  assert.equal((await route(new Request("https://selfhost.example.invalid/v1/accounts/synthetic-account/pull?after=0", { headers: { authorization: `Bearer ${tokenFor("reader")}`, "x-harmonia-device-id": "reader", "x-harmonia-account-generation": "1" } }), service)).status, 200);
}));
test("SMTP permits only authenticated TLS modes and disables secret debug output", () => {
  for (const port of [465, 587] as const) {
    const options = smtpOptions({ host: "smtp.example.invalid", port, user: "synthetic", password: "test-only" });
    assert.equal(options.requireTLS, true); assert.equal(options.secure, port === 465); assert.equal(options.debug, false); assert.equal(options.logger, false);
  }
  assert.throws(() => smtpOptions({ host: "smtp.example.invalid", port: 25 as 465, user: "synthetic", password: "test-only" }), denies("smtp_tls_required"));
});

test("password-only login cannot impersonate existing reader; bound one-use proof issues device-scoped token", async () => withStore(async (_, service) => {
  const login = await service.login(email, clientCredential);
  const credentials = { token: login.token, accountGeneration: login.accountGeneration, deviceId: "reader" };
  await assert.rejects(service.pull(login.accountId, credentials, 0), denies("device_proof_required"));
  const c = await service.deviceChallenge(login.accountId, credentials);
  const signature = Buffer.from(ed25519.sign(new TextEncoder().encode(JSON.stringify(c.signingPayload)), seeds.reader!)).toString("base64url");
  const trusted = await service.deviceSession(login.accountId, credentials, c.challengeId, signature);
  assert.notEqual(trusted.token, login.token);
  assert.equal((await service.pull(login.accountId, { ...credentials, token: trusted.token }, 0)).grants.length, 1);
  await assert.rejects(service.pull(login.accountId, { ...credentials, token: trusted.token, deviceId: "admin" }, 0), denies("device_proof_required"));
  await assert.rejects(service.deviceSession(login.accountId, credentials, c.challengeId, signature), denies("challenge_invalid"));
  await assert.rejects(service.pull(login.accountId, credentials, 0), denies("device_proof_required"));
}));
test("device proof binds login session and device; wrong key and expired challenge fail", async () => withStore(async ({ store }, service) => {
  const login = await service.login(email, clientCredential);
  const credentials = { token: login.token, accountGeneration: "1", deviceId: "reader" };
  const c = await service.deviceChallenge(login.accountId, credentials);
  const sig = (seed: Uint8Array): string => Buffer.from(ed25519.sign(new TextEncoder().encode(JSON.stringify(c.signingPayload)), seed)).toString("base64url");
  await assert.rejects(service.deviceSession(login.accountId, credentials, c.challengeId, sig(seeds.writer!)), denies("signature_invalid"));
  await assert.rejects(service.deviceSession(login.accountId, { ...credentials, deviceId: "writer" }, c.challengeId, sig(seeds.reader!)), denies("challenge_invalid"));
  const other = await service.login(email, clientCredential);
  await assert.rejects(service.deviceSession(login.accountId, { ...credentials, token: other.token }, c.challengeId, sig(seeds.reader!)), denies("challenge_invalid"));
  store.transaction(login.accountId, a => { a.deviceChallenges[0]!.expiresAt = now; });
  await assert.rejects(service.deviceSession(login.accountId, credentials, c.challengeId, sig(seeds.reader!)), denies("challenge_invalid"));
}));
