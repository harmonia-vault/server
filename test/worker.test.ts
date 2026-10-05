import test from "node:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { canonical, trustRootPayload, type TrustRoot } from "../src/lifecycle-wire.js";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { build } from "esbuild";
import { Miniflare } from "miniflare";
import { fixtureAccount, clientCredential, email, mutation, tokenFor, seeds, recoveryKeys, recoverySeed, grant } from "./fixtures.js";
import { workerPassword } from "../src/worker-password.js";
import { DUMMY_VERIFIER, hashCredential, verifyCredential } from "../src/password.js";
test("Workers Argon2id adapter interoperates with Node WASM without reducing parameters", async () => {
  const wasm = await hashCredential(clientCredential);
  assert.equal(await workerPassword.verify(clientCredential, wasm), true);
  const js = await workerPassword.hash(clientCredential);
  assert.equal(await verifyCredential(clientCredential, js), true);
});
test("actual local workerd SQLite DO checks permissions and persists accepted pull sequence", { timeout: 120000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "harmonia-workers-test-"));
  let mf: Miniflare | undefined;
  try {
    const bundle = await build({ entryPoints: ["test/worker-harness.ts"], absWorkingDir: process.cwd(), bundle: true, write: false,
      format: "esm", platform: "browser", target: "es2023", external: ["cloudflare:workers", "node:*"], define: { Buffer: "Buffer" },
      banner: { js: 'import { Buffer } from "node:buffer";' } });
    const script = bundle.outputFiles[0]!.text;
    mf = new Miniflare({ modules: true, script, compatibilityDate: "2026-07-30", compatibilityFlags: ["nodejs_compat"],
      durableObjects: { INSTANCES: { className: "InstanceRegistry", useSQLite: true }, ACCOUNTS: { className: "SyntheticVault", useSQLite: true }, FIXTURES: { className: "SyntheticVault", useSQLite: true } }, d1Databases: { DIRECTORY: "directory" },
      durableObjectsPersist: join(dir, "objects"), d1Persist: join(dir, "d1") });
    const account = await fixtureAccount();
    const oldRecovery = recoveryKeys(recoverySeed);
    const manifest: TrustRoot = { rootDeviceId: "admin", rootSigningPublicKey: account.devices.admin!.signingPublicKey, rootReceivingPublicKey: account.devices.admin!.receivingPublicKey, recoveryGeneration: "1", recoverySigningPublicKey: oldRecovery.signingPublicKey, recoveryReceivingPublicKey: oldRecovery.receivingPublicKey, signature: "" };
    manifest.signature = Buffer.from(ed25519.sign(canonical(trustRootPayload(account.id, account.generation, manifest)), oldRecovery.signingSeed)).toString("base64url"); account.trustRoot = manifest;
    assert.equal((await mf.dispatchFetch("https://selfhost.example.invalid/test/seed", { method: "POST", headers: {"Harmonia-Protocol-Major":"2", "content-type": "application/json" }, body: JSON.stringify(account) })).status, 200);
    const headers = {"Harmonia-Protocol-Major":"2","content-type": "application/json", authorization: `Bearer ${tokenFor("writer")}`, "x-harmonia-device-id": "writer", "x-harmonia-account-generation": "1" };
    const write = await mf.dispatchFetch("https://selfhost.example.invalid/v1/accounts/synthetic-account/mutations", { method: "POST", headers, body: JSON.stringify(mutation()) });
    assert.equal(write.status, 200, await write.text());
    const pull = await mf.dispatchFetch("https://selfhost.example.invalid/v1/accounts/synthetic-account/pull?after=0&capability=issuer-recovery-dag-v1", { headers });
    assert.equal(pull.status, 200);
    const result = await pull.json() as { sequence: number; events: unknown[] };
    assert.equal(result.sequence, 4); assert.equal(result.events.length, 1);
    const call = (path: string, value: unknown, extra: Record<string, string> = {}) => mf!.dispatchFetch(`https://selfhost.example.invalid/v1/accounts/synthetic-account/${path}`, { method: "POST", headers: {"Harmonia-Protocol-Major":"2", "content-type": "application/json", ...extra }, body: JSON.stringify(value) });
    const sign = (payload: string[], key: Uint8Array) => Buffer.from(ed25519.sign(canonical(payload), key)).toString("base64url");
    const bootChallenge = await (await call("boot-challenges", { deviceId: "reader", accountGeneration: "1" })).json() as { challengeId: string; signingPayload: string[] };
    const bootBody = { deviceId: "reader", accountGeneration: "1", challengeId: bootChallenge.challengeId, signature: sign(bootChallenge.signingPayload, seeds.reader!) };
    const boot = await call("boot-sessions", bootBody); assert.equal(boot.status, 200, await boot.clone().text());
    assert.equal((await call("boot-sessions", bootBody)).status, 403);
    const bootToken = (await boot.json() as { token: string }).token;
    assert.equal((await mf.dispatchFetch("https://selfhost.example.invalid/v1/accounts/synthetic-account/pull?after=0&capability=issuer-recovery-dag-v1", { headers: { ...headers, authorization: `Bearer ${bootToken}`, "x-harmonia-device-id": "reader" } })).status, 200);
    const challenge = await (await call("recovery-challenges", { accountGeneration: "1" })).json() as { challengeId: string; signingPayload: string[] };
    const recovered = await call("recovery-sessions", { accountGeneration: "1", challengeId: challenge.challengeId, signature: sign(challenge.signingPayload, oldRecovery.signingSeed) }); assert.equal(recovered.status, 200, await recovered.clone().text());
    const recoveryToken = (await recovered.json() as { token: string }).token;
    const restrictedHeaders = { "Harmonia-Protocol-Major":"2", authorization: `Bearer ${recoveryToken}`, "x-harmonia-account-generation": "1" };
    assert.equal((await mf.dispatchFetch("https://selfhost.example.invalid/v1/accounts/synthetic-account/pull?after=0&capability=issuer-recovery-dag-v1", { headers: { ...headers, authorization: `Bearer ${recoveryToken}` } })).status, 401);
    assert.equal((await call("recovery-rotations", {}, restrictedHeaders)).status, 404);
    const material = await mf.dispatchFetch("https://selfhost.example.invalid/v1/accounts/synthetic-account/recovery-vault-v2?capability=issuer-recovery-dag-v1", {headers:restrictedHeaders});assert.equal(material.status,200);
    assert.equal((await material.json() as {rotationRequired:boolean}).rotationRequired,true);
    const authorizationRefresh = await mf.dispatchFetch("https://selfhost.example.invalid/v1/accounts/synthetic-account/pull?after=0&capability=issuer-recovery-dag-v1&scope=authorizations", { headers });
    assert.equal(authorizationRefresh.status, 200); const projection = await authorizationRefresh.json() as { scope: string; events: unknown[] }; assert.equal(projection.scope, "authorizations"); assert.deepEqual(projection.events, []);
    const loginStart = performance.now();
    const login = await mf.dispatchFetch("https://selfhost.example.invalid/v1/login", { method: "POST", headers: {"Harmonia-Protocol-Major":"2", "content-type": "application/json" }, body: JSON.stringify({ email, credential: clientCredential }) });
    assert.equal(login.status, 200, await login.clone().text());
    console.log(`本地 workerd 首次登录 Argon2id（64 MiB、3 次、固定公开dummy验证值） ${Math.round(performance.now() - loginStart)} ms；这不是线上配额验收`);
    const token = (await login.json() as { token: string }).token;
    const impersonation = await mf.dispatchFetch("https://selfhost.example.invalid/v1/accounts/synthetic-account/pull?after=0&capability=issuer-recovery-dag-v1", { headers: { ...headers, authorization: `Bearer ${token}` } });
    assert.equal(impersonation.status, 403);
    const loginRequest = () => mf!.dispatchFetch("https://selfhost.example.invalid/v1/login", { method: "POST", headers: {"Harmonia-Protocol-Major":"2", "content-type": "application/json" }, body: JSON.stringify({ email, credential: clientCredential }) });
    const concurrent = await Promise.all([loginRequest(), loginRequest()]);
    assert.ok(concurrent.some(r => r.status === 200));
    assert.ok(concurrent.every(r => r.status === 200 || r.status === 429));
    const unknown = await mf.dispatchFetch("https://selfhost.example.invalid/v1/login", { method: "POST", headers: {"Harmonia-Protocol-Major":"2", "content-type": "application/json" }, body: JSON.stringify({ email: "unknown-synthetic@example.invalid", credential: clientCredential }) });
    assert.equal(unknown.status, 401);
  } finally { await mf?.dispose(); rmSync(dir, { recursive: true, force: true }); }
});

test("Workers Argon2 resource admission rejects truly overlapping derivation without lowering parameters", async () => {
  const first = workerPassword.verify(clientCredential, DUMMY_VERIFIER);
  await assert.rejects(workerPassword.verify(clientCredential, DUMMY_VERIFIER), error => error instanceof Error && error.message === "password_capacity_reached");
  assert.equal(await first, false);
  assert.equal(await workerPassword.verify("00".repeat(32), DUMMY_VERIFIER), true);
});
