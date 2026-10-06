import {enrollmentV5Fields, type EnrollmentApprovalV5} from "../src/issuer-dag.js";
import type {RecoveryDAGAccount} from "../src/recovery-dag-account.js";
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { build } from "esbuild";
import { Miniflare } from "miniflare";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { nodeHarness, sign, seeds, b64, type Harness, vector } from "./recovery-origin-fixtures.js";
import { relayFields } from "../src/enrollment.js";
import { canonical, hash, pairingContextFields, type PairingContext } from "../src/enrollment-wire.js";
import { grantBytes } from "../src/protocol.js";
import { grantKey, type SignedGrant } from "../src/model.js";
import type { SyntheticVault } from "./pending-pairings-worker-harness.js";
interface H { send: Harness["send"]; read: () => Promise<RecoveryDAGAccount>; change: (fn: (a: RecoveryDAGAccount) => void) => Promise<void>; close: () => Promise<void> }
async function runtime(kind: "node" | "workerd"): Promise<H> {
  const h = await nodeHarness(true);
  if (kind === "node") return { send: h.send, read: async () => h.read(), change: async f => { h.change(f); }, close: h.close };
  const a = h.account; await h.close();
  const dir = mkdtempSync(join(tmpdir(), "harmonia-pending-workerd-")), built = await build({ entryPoints: ["test/pending-pairings-worker-harness.ts"], absWorkingDir: process.cwd(), bundle: true, write: false, format: "esm", platform: "browser", target: "es2023", external: ["cloudflare:workers", "node:*"], banner: { js: 'import { Buffer } from "node:buffer";' } });
  const mf = new Miniflare({ modules: true, script: built.outputFiles[0]!.text, compatibilityDate: "2026-07-30", compatibilityFlags: ["nodejs_compat"], durableObjects: { INSTANCES: { className: "InstanceRegistry", useSQLite: true }, ACCOUNTS: { className: "SyntheticVault", useSQLite: true }, FIXTURES: { className: "SyntheticVault", useSQLite: true } }, d1Databases: { DIRECTORY: "directory" }, durableObjectsPersist: join(dir, "objects"), d1Persist: join(dir, "directory") });
  await mf.dispatchFetch("https://synthetic.invalid/test/seed", { method: "POST", body: JSON.stringify(a) });
  const stub = (await mf.getDurableObjectNamespace("FIXTURES")).getByName(a.id) as unknown as DurableObjectStub<SyntheticVault>;
  return { send: async (path, method, body, who = "B", generation = "1", accountId = a.id) => {
    const token = b64(Buffer.alloc(32, { login: 61, A: 65, B: 62, C: 63 }[who] ?? 66));
    const response = await mf.dispatchFetch(`https://synthetic.invalid/v1/accounts/${accountId}${path}`, { method, headers: { "Harmonia-Protocol-Major":"2", "content-type": "application/json", authorization: `Bearer ${token}`, "x-harmonia-account-generation": generation, ...(["A", "B", "C"].includes(who) ? { "x-harmonia-device-id": `device-${who}` } : {}) }, ...(method === "GET" ? {} : { body: JSON.stringify(body) }) });
    if (response.status === 200 && path.startsWith("/pairing-requests-")) assert.equal(response.headers.get("cache-control"), "no-store"); return { status: response.status, data: await response.json() };
  }, read: async () => JSON.parse(await stub.snapshotSynthetic(a.id)) as RecoveryDAGAccount, change: async f => { const copy = JSON.parse(await stub.snapshotSynthetic(a.id)) as RecoveryDAGAccount; f(copy); await stub.replaceSynthetic(a.id, JSON.stringify(copy)); }, close: async () => { await mf.dispose(); rmSync(dir, { recursive: true, force: true }); } };
}
const route = (version: "5") => `/pairing-requests-v${version}`;
async function begin(h: H, version: "5", key: string, approver = "B") {
  const seed = sha256(new TextEncoder().encode(`synthetic-sign-${key}`)), x = sha256(new TextEncoder().encode(`synthetic-recv-${key}`));
  const b = { idempotencyKey: key, deviceId: `candidate-${key}`, signingPublicKey: b64(ed25519.getPublicKey(seed)), receivingPublicKey: b64(x25519.getPublicKey(x)), approverDeviceId: `device-${approver}`, certificateVersion: version, capabilities: ["issuer-recovery-dag-v1"] };
  const response = await h.send(`/pairings-v${version}`, "POST", b, "login"); assert.equal(response.status, 200, JSON.stringify(response.data));
  return { key, version, seed, context: response.data.context as PairingContext };
}
async function approve(h: H, started: Awaited<ReturnType<typeof begin>>, complete = false) {
  const { key, version, seed, context } = started;
  for (const [side, kind, value, who] of [["initiator", "message", 71, "login"], ["approver", "message", 72, "B"], ["initiator", "confirmation", 73, "login"], ["approver", "confirmation", 74, "B"]] as const) {
    const relay = { side, kind, payload: b64(Buffer.alloc(32, value)) };
    const response = await h.send(`/pairings-v${version}/${key}/relay`, "POST", { ...relay, signature: sign(relayFields({ context } as any, relay), side === "initiator" ? seed : seeds.B!) }, who); assert.equal(response.status, 200, JSON.stringify(response.data));
  }
  const status = await h.send(`/pairings-v${version}/${key}`, "GET", undefined, "login"), p = await h.send(`/pull?after=0&capability=issuer-recovery-dag-v1`, "GET", undefined, "B"); assert.equal(p.status, 200, JSON.stringify(p.data));
  const a = await h.read(), parent = a.grants[grantKey("env-fixture", "device-B")]!, g = structuredClone(parent.grant);
  Object.assign(g, { issuerDeviceId: "device-B", subjectDeviceId: context.initiatorDeviceId, subjectSigningPublicKey: context.initiatorSigningPublicKey, subjectReceivingPublicKey: context.initiatorReceivingPublicKey, role: "ro", grantGeneration: "1", idempotencyKey: `grant-${key}` });
  const grant = { grant: g, signature: b64(ed25519.sign(grantBytes(g), seeds.B!)) }, base = { context, pairingProfile: vector.approval.pairingProfile, transcriptHash: hash(["harmonia/pairing-transcript/v1", b64(canonical(pairingContextFields(context))), status.data.messages.initiator, status.data.messages.approver]), grants: [grant], issuerProof: p.data.issuerEvidence, approverSignature: "" };
  const certificate: EnrollmentApprovalV5 = {...base, certificateVersion:"5", capabilities:["issuer-recovery-dag-v1"]};
  const fields = enrollmentV5Fields(certificate); certificate.approverSignature = sign(fields, seeds.B!);
  const accepted = await h.send(`/pairings-v${version}/${key}/approve`, "POST", { certificateVersion: version, capabilities: ["issuer-recovery-dag-v1"], grants: [grant], transcriptHash: base.transcriptHash, issuerProof: base.issuerProof, signature: certificate.approverSignature }, "B"); assert.equal(accepted.status, 200, JSON.stringify(accepted.data));
  if (complete) { const result = await h.send(`/pairings-v${version}/${key}/complete`, "POST", { signature: sign(fields, seed) }, "login"); assert.equal(result.status, 200, JSON.stringify(result.data)); }
}
for (const kind of ["node", "workerd"] as const) {
  test(`${kind} expired pairing removes transient payload but never reuses the operation ID`, async () => {
    const h = await runtime(kind);
    try {
      const attempt = await begin(h, '5', 'once');
      await h.change(a => { a.dagPairingSessions!.once!.context.expiresAt = '1'; });
      const retry = await h.send('/pairings-v5', 'POST', {
        idempotencyKey: 'once', deviceId: attempt.context.initiatorDeviceId,
        signingPublicKey: attempt.context.initiatorSigningPublicKey, receivingPublicKey: attempt.context.initiatorReceivingPublicKey,
        approverDeviceId: 'device-B', certificateVersion: '5', capabilities: ['issuer-recovery-dag-v1'],
      }, 'login');
      assert.equal(retry.status, 403); assert.equal(retry.data.error, 'challenge_invalid');
      const different = await h.send('/pairings-v5', 'POST', {
        idempotencyKey: 'once', deviceId: 'different-device',
        signingPublicKey: attempt.context.initiatorSigningPublicKey, receivingPublicKey: attempt.context.initiatorReceivingPublicKey,
        approverDeviceId: 'device-B', certificateVersion: '5', capabilities: ['issuer-recovery-dag-v1'],
      }, 'login');
      assert.equal(different.status, 403);
      assert.equal((await h.read()).dagPairingSessions!.once, undefined);
    } finally { await h.close(); }
  });
  test(`${kind}真实HTTP DAG最小投影/固定排序/别的approver与账户隔离/无降级`, { timeout: 120000 }, async () => {
    const h = await runtime(kind); try {
      const a = await begin(h, "5", "z-own"), b = await begin(h, "5", "a-own"); await begin(h, "5", "other-approver", "A");
      await h.change(account => { account.dagPairingSessions![a.key]!.context.expiresAt = "2090000001"; account.dagPairingSessions![b.key]!.context.expiresAt = "2090000001"; });
      const response = await h.send(route("5"), "GET"), r = response.data;
      assert.equal(response.status, 200); assert.deepEqual(Object.keys(r).sort(), ["accountGeneration", "capabilities", "certificateVersion", "requests"]); assert.equal(r.accountGeneration, "1"); assert.equal(r.certificateVersion, "5"); assert.deepEqual(r.capabilities, ["issuer-recovery-dag-v1"]); assert.deepEqual(r.requests.map((x: any) => x.idempotencyKey), ["a-own", "z-own"]);
      for (const x of r.requests) assert.deepEqual(Object.keys(x).sort(), ["expiresAt", "idempotencyKey", "initiatorDeviceId", "state"]);
      assert.deepEqual((await h.send(route("5"), "GET", undefined, "A")).data.requests.map((x: any) => x.idempotencyKey), ["other-approver"]);
      assert.equal((await h.send(route("5"), "GET", undefined, "B", "1", "other-account")).status, 401);
      assert.equal((await h.send(route("5") + "?capability=unknown", "GET")).status, 400);
      assert.equal((await h.send("/pairing-requests-v4", "GET")).status, 404); assert.equal((await h.send("/pairing-requests-v2", "GET")).status, 404);
      assert.equal((await h.send(route("5"), "POST", {})).status, 405);
      assert.equal((await h.send(route("5"), "GET", undefined, "login")).status, 401);
      await h.change(account => { const unbound = account.sessions.find(s => !s.deviceId)!; account.sessions.find(s => s.deviceId === "device-B")!.deviceId = "device-A"; assert.ok(unbound); });
      assert.equal((await h.send(route("5"), "GET", undefined, "B")).status, 403);
    } finally { await h.close(); }
  });
  test(`${kind}真实HTTP 到期/失效发起会话/错误代际或设备钥/只读与撤销都不泄提示`, { timeout: 120000 }, async () => {
    const h = await runtime(kind); try {
      const expired = await begin(h, "5", "expired"), wrong = await begin(h, "5", "wrong-key"), stale = await begin(h, "5", "stale-gen"), valid = await begin(h, "5", "valid");
      await h.change(a => { a.dagPairingSessions![expired.key]!.context.expiresAt = String(Math.floor(Date.now() / 1000) - 1); a.dagPairingSessions![wrong.key]!.context.approverReceivingPublicKey = b64(Buffer.alloc(32, 29)); a.dagPairingSessions![stale.key]!.context.accountGeneration = "2"; });
      assert.deepEqual((await h.send(route("5"), "GET")).data.requests.map((x: any) => x.idempotencyKey), [valid.key]);
      await h.change(a => { a.sessions.find(s => !s.deviceId)!.expiresAt = Math.floor(Date.now() / 1000) - 1; });
      assert.deepEqual((await h.send(route("5"), "GET")).data.requests, []);
      assert.equal((await h.send(route("5"), "GET", undefined, "B", "2")).status, 401);
      assert.equal((await h.send(route("5"), "GET", undefined, "C")).status, 403);
      await h.change(a => { a.devices["device-B"]!.revoked = true; });
      assert.equal((await h.send(route("5"), "GET")).status, 403);
    } finally { await h.close(); }
  });
  test(`${kind}真实HTTP DAGapproved提示/complete移除/当前授权变化即排除`, { timeout: 120000 }, async () => {
    const h = await runtime(kind); try {
      const v3 = await begin(h, "5", "approved-v3"); await approve(h, v3);
      for (const v of ["5"] as const) { const r = await h.send(route(v), "GET"); assert.equal(r.status, 200, JSON.stringify(r.data)); assert.deepEqual(r.data.requests.map((x: any) => x.state), ["approved"]); }
      const completed = await begin(h, "5", "completed-v3"); await approve(h, completed, true); assert.deepEqual((await h.send(route("5"), "GET")).data.requests.map((x: any) => x.idempotencyKey), [v3.key]);
      const a = await h.read(), old = a.grants[grantKey("env-fixture", "device-B")]!, grant = structuredClone(old.grant); Object.assign(grant, { issuerDeviceId: "device-A", grantGeneration: "2", role: "rw", idempotencyKey: "downgrade-B" });
      const changed = await h.send("/grants", "POST", { grant, signature: b64(ed25519.sign(grantBytes(grant), seeds.A!)) } satisfies SignedGrant, "A"); assert.equal(changed.status, 200, JSON.stringify(changed.data));
      for (const v of ["5"] as const) assert.equal((await h.send(route(v), "GET")).status, 403);
    } finally { await h.close(); }
  });
  test(`${kind}真实HTTP 64项容量/确定排序/只读序号/管理会话和授权到期`, { timeout: 120000 }, async () => {
    const h = await runtime(kind); try {
      const before = (await h.read()).sequence;
      for (let i = 63; i >= 0; i--) await begin(h, "5", `limit-${String(i).padStart(2, "0")}`);
      const r = await h.send(route("5"), "GET"); assert.equal(r.status, 200); assert.equal(r.data.requests.length, 64); assert.equal((await h.read()).sequence, before);
      assert.ok(r.data.requests.every((x: any, i: number, rows: any[]) => i === 0 || BigInt(rows[i - 1].expiresAt) < BigInt(x.expiresAt) || (rows[i - 1].expiresAt === x.expiresAt && rows[i - 1].idempotencyKey < x.idempotencyKey)));
      const extra = await h.send("/pairings-v5", "POST", { idempotencyKey: "limit-65", deviceId: "candidate-overflow", signingPublicKey: b64(ed25519.getPublicKey(Buffer.alloc(32, 91))), receivingPublicKey: b64(x25519.getPublicKey(Buffer.alloc(32, 92))), approverDeviceId: "device-B", certificateVersion: "5", capabilities: ["issuer-recovery-dag-v1"] }, "login"); assert.equal(extra.status, 429); assert.equal(extra.data.error, "pairing_capacity_reached");
      await h.change(a => { a.grants[grantKey("env-fixture", "device-B")]!.grant.expiresAt = String(Math.floor(Date.now() / 1000) - 1); });
      assert.equal((await h.send(route("5"), "GET")).status, 403);
      await h.change(a => { a.sessions.find(session => session.deviceId === "device-B")!.expiresAt = Math.floor(Date.now() / 1000) - 1; });
      assert.equal((await h.send(route("5"), "GET")).status, 401);
      await h.change(a => { a.generation = "2"; delete a.trustRoot; a.recoverySigningPublicKey = null; a.recoveryReceivingPublicKey = null; a.devices = {}; a.environments = {}; a.grants = {}; a.sessions = []; a.events = []; a.dagPairingSessions = {}; a.vaultInitializations = {}; }); assert.equal((await h.send(route("5"), "GET")).data.error, "generation_stale");
    } finally { await h.close(); }
  });
  test(`${kind}真实HTTP 同一管理者仍有其他Admin但approved来源已变/到期不再列`, { timeout: 120000 }, async () => {
    const h = await runtime(kind); try {
      const v3 = await begin(h, "5", "authority-changed"); await approve(h, v3);
      await h.change(a => { const old = a.grants[grantKey("env-fixture", "device-B")]!, other = structuredClone(old); other.grant.environmentId = "other-env"; a.environments["other-env"] = { ...a.environments["env-fixture"]!, id: "other-env" }; a.grants[grantKey("other-env", "device-B")] = other; const current = structuredClone(old); current.grant.grantGeneration = "2"; current.grant.expiresAt = String(Math.floor(Date.now() / 1000) - 1); a.grants[grantKey("env-fixture", "device-B")] = current; });
      const expired = await h.send(route("5"), "GET"); assert.equal(expired.status, 200); assert.deepEqual(expired.data.requests, []);
      await h.change(a => { const original = a.grantHistory!.find(x => x.grant.grant.subjectDeviceId === "device-B")!.grant; const current = structuredClone(original); current.grant.grantGeneration = "2"; current.signature = b64(ed25519.sign(grantBytes(current.grant), seeds.A!)); a.grants[grantKey("env-fixture", "device-B")] = current; });
      const changed = await h.send(route("5"), "GET"); assert.equal(changed.status, 200); assert.deepEqual(changed.data.requests, []);
    } finally { await h.close(); }
  });
}
