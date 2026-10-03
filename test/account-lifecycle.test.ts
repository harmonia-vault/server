import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { nodeStore } from "../src/node-store.js";
import { SqlStore, type Sql } from "../src/store.js";
import { AccountLifecycle, type ProofInput, type ResetInput } from "../src/account-lifecycle.js";
import { cloudflareEmail, type Email } from "../src/email-transport.js";
import { wasmPassword } from "../src/password.js";
import { VaultService } from "../src/service.js";
import { LifecycleService } from "../src/lifecycle.js";
import { Fault } from "../src/model.js";
import { route } from "../src/http.js";
import { auth, clientCredential, fixtureAccount, now, mutation, seeds, email } from "./fixtures.js";
const id = "synthetic-account", replacement = "cd".repeat(32);
const denies = (code: string) => (e: unknown): boolean => e instanceof Fault && e.code === code;
function proof(message: Email): ProofInput & { accountId: string } { return JSON.parse(message.text.split("\n").find(line => line.startsWith("{"))!); }
async function context(run: (c: ReturnType<typeof nodeStore>, account: AccountLifecycle, vault: VaultService, mails: Email[], path: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "harmonia-account-test-")), path = join(dir, "account.sqlite"), c = nodeStore(path), mails: Email[] = [];
  const mail = { send: async (message: Email): Promise<void> => { mails.push(message); } };
  const account = new AccountLifecycle(c.store, wasmPassword, () => now, mail);
  const vault = new VaultService(c.store, { allowRegistration: true, requireEmailVerification: true }, () => now, wasmPassword, mail);
  try { await run(c, account, vault, mails, path); } finally { try { c.sql.close(); } catch {} rmSync(dir, { recursive: true, force: true }); }
}
test("registration switches stay independent; email proof enables login without granting device trust", async () => context(async ({ store }, account, vault, mails) => {
  const registration = await account.register(email, clientCredential, vault.policy); assert.equal(registration.verificationRequired, true); assert.equal(mails.length, 1);
  const p = proof(mails[0]!); assert.equal(p.accountId, registration.accountId); assert.equal(store.read(p.accountId)!.verified, false);
  await assert.rejects(vault.login(email, clientCredential), denies("unauthorized"));
  await account.verifyEmail(p.accountId, p); assert.equal(store.read(p.accountId)!.verified, true);
  await assert.rejects(account.register("closed@example.invalid", clientCredential, { allowRegistration: false, requireEmailVerification: false }), denies("registration_disabled"));
  const login = await vault.login(email, clientCredential);
  await assert.rejects(vault.pull(p.accountId, { token: login.token, deviceId: "admin", accountGeneration: "1" }, 0), denies("device_untrusted"));
  await assert.rejects(account.verifyEmail(p.accountId, p), denies("email_proof_invalid"));
  const second = await account.register("optional@example.invalid", clientCredential, { allowRegistration: true, requireEmailVerification: false });
  assert.equal(second.verificationRequired, false); assert.equal(store.read(second.accountId)!.verified, false); assert.equal(mails.length, 1);
  const optional = new VaultService(store, { allowRegistration: false, requireEmailVerification: false }, () => now);
  assert.equal((await optional.login("optional@example.invalid", clientCredential)).accountId, second.accountId);
  assert.equal((await vault.login("optional@example.invalid", clientCredential)).accountId, second.accountId);
}));
test("verification tokens are purpose/account/generation bound, expiring, and only hashes are persisted", async () => context(async ({ store }, account, vault, mails) => {
  const registered = await account.register(email, clientCredential, vault.policy), p = proof(mails[0]!);
  const serialized = JSON.stringify(store.read(registered.accountId)); assert.equal(serialized.includes(p.token), false); assert.equal(serialized.includes(clientCredential), false);
  await assert.rejects(account.verifyEmail(p.accountId, { ...p, token: Buffer.alloc(32, 9).toString("base64url") }), denies("email_proof_invalid"));
  await assert.rejects(account.verifyEmail(p.accountId, { ...p, accountGeneration: "2" }), denies("generation_stale"));
  await assert.rejects(account.reset(p.accountId, { ...p, newCredential: replacement, confirmation: "DELETE_OLD_VAULT" }), denies("registration_pending"));
  store.transaction(p.accountId, a => { a.emailProofs![0]!.expiresAt = now; });
  await assert.rejects(account.verifyEmail(p.accountId, p), denies("email_proof_invalid"));
}));
test("mail failures remove the unusable proof and configuration absence stays fail closed", async () => context(async ({ store }, account, vault, mails) => {
  await assert.rejects(new AccountLifecycle(store, wasmPassword, () => now).register(email, clientCredential, vault.policy), denies("email_verification_unavailable"));
  assert.equal(store.byEmail(email), undefined);
  const unavailable = new AccountLifecycle(store, wasmPassword, () => now, { send: async () => { throw new Error("synthetic secret SMTP failure"); } });
  await assert.rejects(unavailable.register(email, clientCredential, vault.policy), denies("email_delivery_failed"));
  const accountId = store.byEmail(email)!; assert.equal(store.read(accountId)!.verified, false); assert.deepEqual(store.read(accountId)!.emailProofs, []);
  await account.requestProof(email, "verification"); assert.equal(mails.length, 1);
  assert.deepEqual(await account.requestProof("absent@example.invalid", "reset"), { accepted: true }); assert.equal(mails.length, 1);
  await assert.rejects(account.requestProof(email, "verification"), denies("email_request_limited"));
}));
test("email-owned destructive reset atomically clears every old authority and supports status and identical retry", async () => context(async ({ store }, account, vault, mails) => {
  const initialized = await fixtureAccount(); (initialized as unknown as Record<string, unknown>).futurePairingNonce = "synthetic-old-nonce"; store.create(initialized);
  await vault.mutate(id, auth(), mutation()); const boot = new LifecycleService(store, () => now); const challenge = boot.bootChallenge(id, "reader", "1");
  await account.requestProof(email, "reset"); const p = proof(mails[0]!), input: ResetInput = { ...p, newCredential: replacement, confirmation: "DELETE_OLD_VAULT" };
  assert.equal((await account.resetStatus(id, p)).state, "pending");
  await assert.rejects(account.reset(id, { ...input, confirmation: "" as ResetInput["confirmation"] }), denies("destructive_confirmation_required"));
  await assert.rejects(account.verifyEmail(id, p), denies("email_proof_invalid"));
  assert.deepEqual(await account.reset(id, input), { accountId: id, accountGeneration: "2", replayed: false });
  assert.deepEqual(await account.resetStatus(id, p), { state: "complete", accountId: id, accountGeneration: "2" });
  assert.deepEqual(await account.reset(id, input), { accountId: id, accountGeneration: "2", replayed: true });
  await assert.rejects(account.reset(id, { ...input, newCredential: "ef".repeat(32) }), denies("idempotency_conflict"));
  const cleared = store.read(id)!;
  assert.equal(cleared.sequence, 0); assert.deepEqual(cleared.devices, {}); assert.deepEqual(cleared.environments, {}); assert.deepEqual(cleared.grants, {}); assert.deepEqual(cleared.sessions, []); assert.deepEqual(cleared.events, []); assert.deepEqual(cleared.idempotency, {});
  assert.equal(cleared.recoverySigningPublicKey, null); assert.equal(cleared.recoveryReceivingPublicKey, null); assert.equal(cleared.trustRoot, undefined); assert.equal(cleared.bootChallenges, undefined); assert.equal(cleared.recoveryRotations, undefined); assert.equal(cleared.emailProofs, undefined); assert.equal((cleared as unknown as Record<string, unknown>).futurePairingNonce, undefined);
  assert.equal(JSON.stringify(cleared).includes(p.token), false); assert.equal(JSON.stringify(cleared).includes(replacement), false);
  await assert.rejects(vault.pull(id, auth("reader"), 0), denies("generation_stale"));
  await assert.rejects(vault.mutate(id, auth(), mutation()), denies("generation_stale"));
  await assert.rejects(boot.bootSession(id, "reader", "1", challenge.challengeId, Buffer.alloc(64, 1).toString("base64url")), denies("generation_stale"));
  await assert.rejects(vault.login(email, clientCredential), denies("unauthorized")); assert.equal((await vault.login(email, replacement)).accountGeneration, "2");
}));
test("reset Argon2 happens outside transaction then CAS rejects changed verifier, generation and consumed proof", async () => context(async ({ store }, account, _, mails) => {
  store.create(await fixtureAccount()); await account.requestProof(email, "reset"); const p = proof(mails[0]!), input: ResetInput = { ...p, newCredential: replacement, confirmation: "DELETE_OLD_VAULT" };
  let inject = true;
  const hasher = { verify: wasmPassword.verify, hash: async (value: string): Promise<string> => {
    const hashed = await wasmPassword.hash(value);
    store.transaction(id, a => { if (inject) { a.passwordVerifier = "synthetic changed verifier"; inject = false; } }); // Would fail with nested BEGIN if derivation held a transaction.
    return hashed;
  } };
  const racing = new AccountLifecycle(store, hasher, () => now);
  await assert.rejects(racing.reset(id, input), denies("account_changed"));
  assert.equal(store.read(id)!.generation, "1"); assert.equal(Object.keys(store.read(id)!.devices).length, 4); assert.equal(store.read(id)!.resetReceipt, undefined);
}));
test("SQLite reset commit failure rolls back all state, and reopen preserves completion receipt without plaintext token", async () => context(async ({ store, sql }, account, _, mails, path) => {
  store.create(await fixtureAccount()); await account.requestProof(email, "reset"); const p = proof(mails[0]!), input: ResetInput = { ...p, newCredential: replacement, confirmation: "DELETE_OLD_VAULT" };
  const before = store.read(id)!; let fail = true;
  const injected: Sql = { execute: (query, params) => { if (fail && query.startsWith("UPDATE accounts")) { fail = false; throw new Error("synthetic reset write failure"); } sql.execute(query, params); }, rows: (query, params) => sql.rows(query, params), transaction: operation => sql.transaction(operation) };
  await assert.rejects(new AccountLifecycle(new SqlStore(injected), wasmPassword, () => now).reset(id, input), /synthetic reset write failure/);
  assert.deepEqual(store.read(id), before); await account.reset(id, input); sql.close();
  const reopened = nodeStore(path);
  try { const next = new AccountLifecycle(reopened.store, wasmPassword, () => now); assert.equal((await next.resetStatus(id, p)).state, "complete"); assert.equal((await next.reset(id, input)).replayed, true); assert.equal(JSON.stringify(reopened.store.read(id)).includes(p.token), false); }
  finally { reopened.sql.close(); }
}));
test("HTTP email verification/reset flows use bodies, exact shape, explicit destructive confirmation and no-store", async () => context(async (_, __, vault, mails) => {
  const request = (path: string, value: unknown) => new Request(`https://selfhost.example.invalid${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(value) });
  const registered = await route(request("/v1/register", { email, credential: clientCredential }), vault); assert.equal(registered.status, 200);
  const p = proof(mails[0]!), base = `/v1/accounts/${p.accountId}`;
  const verified = await route(request(`${base}/email-verification/complete`, { accountGeneration: p.accountGeneration, challengeId: p.challengeId, token: p.token }), vault); assert.equal(verified.status, 200); assert.equal(verified.headers.get("cache-control"), "no-store");
  const start = await route(request("/v1/account-reset/request", { email }), vault); assert.equal(start.status, 200); const resetProof = proof(mails[1]!);
  const input = { accountGeneration: resetProof.accountGeneration, challengeId: resetProof.challengeId, token: resetProof.token, newCredential: replacement, confirmation: "DELETE_OLD_VAULT" };
  assert.equal((await route(request(`${base}/account-reset/complete`, { ...input, confirmation: "NO" }), vault)).status, 400);
  assert.equal((await route(request(`${base}/account-reset/complete`, { ...input, deviceId: "admin" }), vault)).status, 400);
  assert.equal((await route(request(`${base}/account-reset/complete`, input), vault)).status, 200);
  assert.equal((await route(new Request(`https://selfhost.example.invalid${base}/account-reset/status?token=${resetProof.token}`), vault)).status, 405);
  assert.equal((await route(request(`${base}/account-reset/status`, { accountGeneration: resetProof.accountGeneration, challengeId: resetProof.challengeId, token: resetProof.token }), vault)).status, 200);
}));
test("official EmailService adapter uses structured send only and propagates failures for sanitized handling", async () => {
  const messages: unknown[] = [], binding = { send: async (value: unknown) => { messages.push(value); return { messageId: "synthetic" }; } } as SendEmail;
  assert.equal(cloudflareEmail(undefined, "noreply@example.invalid"), undefined); assert.equal(cloudflareEmail(binding, ""), undefined);
  await cloudflareEmail(binding, "noreply@example.invalid")!.send({ to: email, subject: "合成测试", text: "合成内容" });
  assert.deepEqual(messages, [{ from: "noreply@example.invalid", to: email, subject: "合成测试", text: "合成内容" }]);
  assert.throws(() => cloudflareEmail(binding, "header\n@example.invalid"), denies("email_sender_invalid"));
});

test("reset commit rechecks generation, token hash and expiry after Argon2; invalid proof skips derivation", async () => {
  for (const mode of ["generation", "token", "expiry"] as const) await context(async ({ store }, account, _, mails) => {
    store.create(await fixtureAccount()); await account.requestProof(email, "reset"); const p = proof(mails[0]!), input: ResetInput = { ...p, newCredential: replacement, confirmation: "DELETE_OLD_VAULT" }; let count = 0;
    const hasher = { verify: wasmPassword.verify, hash: async (value: string): Promise<string> => { count++; const result = await wasmPassword.hash(value); store.transaction(id, a => { if (mode === "generation") a.generation = "2"; else if (mode === "token") a.emailProofs![0]!.tokenHash = "00".repeat(32); else a.emailProofs![0]!.expiresAt = now; }); return result; } };
    const racing = new AccountLifecycle(store, hasher, () => now);
    await assert.rejects(racing.reset(id, { ...input, token: Buffer.alloc(32, 99).toString("base64url") }), denies("email_proof_invalid")); assert.equal(count, 0);
    await assert.rejects(racing.reset(id, input), denies(mode === "generation" ? "generation_stale" : "email_proof_invalid")); assert.equal(count, 1);
    assert.equal(Object.keys(store.read(id)!.devices).length, 4); assert.equal(store.read(id)!.resetReceipt, undefined);
  });
});
test("two simultaneous identical reset submissions commit one generation and preserve the same receipt", async () => context(async ({ store }, account, _, mails) => {
  store.create(await fixtureAccount()); await account.requestProof(email, "reset"); const p = proof(mails[0]!), input: ResetInput = { ...p, newCredential: replacement, confirmation: "DELETE_OLD_VAULT" };
  const results = await Promise.all([account.reset(id, input), account.reset(id, input)]); assert.equal(results.filter(r => r.replayed === false).length, 1); assert.ok(results.every(r => r.accountGeneration === "2"));
  assert.equal(store.read(id)!.generation, "2"); assert.equal((await account.resetStatus(id, p)).state, "complete");
}));
