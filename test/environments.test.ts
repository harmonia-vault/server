import test from "node:test";
import assert from "node:assert/strict";
import { ed25519 } from "@noble/curves/ed25519.js";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { nodeStore } from "../src/node-store.js";
import { route } from "../src/http.js";
import { Fault, grantKey } from "../src/model.js";
import { EnvironmentService, environmentChangeBytes, environmentGrantsHash, environmentMutationsHash, deviceRevocationBytes, revocationAuthorityHash,
 type EnvironmentAccount, type EnvironmentChange, type SignedEnvironmentChange, type DeviceRevocation } from "../src/environments.js";
import { auth, grant, mutation, now, seeds, seed, signGrant } from "./fixtures.js";
const b64 = (v: Uint8Array): string => Buffer.from(v).toString("base64url");
const denies = (code: string) => (e: unknown): boolean => e instanceof Fault && e.code === code;
function sign(c: EnvironmentChange, signer = c.deviceId): SignedEnvironmentChange { return { change: c, signature: b64(ed25519.sign(environmentChangeBytes(c), seeds[signer]!)) }; }
function create(environmentId = "prod", overrides: Partial<EnvironmentChange> = {}): EnvironmentChange {
 const own = signGrant(grant("admin", { environmentId, idempotencyKey: `create-${environmentId}-admin` }));
 return { accountId: "synthetic-account", accountGeneration: "1", deviceId: "admin", environmentId, operation: "create", authorityEnvironmentId: "dev", authorityKeyVersion: "1", authorityGrantGeneration: "1", previousKeyVersion: "0", keyVersion: "1", expectedSequence: "0", idempotencyKey: `create-${environmentId}`, labelPayload: b64(Buffer.alloc(40, 17)), recoveryGeneration: "1", recoveryEnvelope: b64(Buffer.alloc(80, 18)), grants: [own], mutations: [], ...overrides };
}
function update(operation: "rename" | "delete", overrides: Partial<EnvironmentChange> = {}): EnvironmentChange {
 return create("dev", { operation, previousKeyVersion: "1", labelPayload: operation === "delete" ? "" : b64(Buffer.alloc(40, 19)), recoveryEnvelope: "", grants: [], idempotencyKey: `${operation}-dev`, ...overrides });
}
function rotate(overrides: Partial<EnvironmentChange> = {}): EnvironmentChange {
 const grants = ["admin", "reader", "writer"].map(id => signGrant(grant(id, { keyVersion: "2", grantGeneration: "2", idempotencyKey: `rotation-${id}` })));
 const value = mutation("admin", { keyVersion: "2", grantGeneration: "2", idempotencyKey: "rotation-value", payload: b64(Buffer.alloc(40, 20)) });
 return create("dev", { operation: "rotate", previousKeyVersion: "1", keyVersion: "2", expectedSequence: "1", idempotencyKey: "rotate-dev", labelPayload: "", grants, mutations: [value], ...overrides });
}
interface Harness { store: ReturnType<typeof nodeStore>["store"]; environments: EnvironmentService; vault: Awaited<ReturnType<typeof seed>>; advance(n: number): void; path: string }
async function withVault(run: (h: Harness) => Promise<void>): Promise<void> {
 const dir = mkdtempSync(join(tmpdir(), "harmonia-environments-")), path = join(dir, "synthetic.sqlite"); const { store, sql } = nodeStore(path); let clock = now;
 try { const vault = await seed(store); await run({ store, vault, environments: new EnvironmentService(store, () => clock), advance: n => { clock += n; }, path }); }
 finally { sql.close(); rmSync(dir, { recursive: true, force: true }); }
}
test("可信Admin签名创建独立环境，恢复封套与自身授权原子保存；重试不变成新写", async () => withVault(async h => {
 const signed = sign(create()); const result = await h.environments.change("synthetic-account", auth("admin"), signed); assert.equal(result.sequence, 1);
 assert.deepEqual(await h.environments.change("synthetic-account", auth("admin"), signed), { sequence: 1, replayed: true });
 assert.equal(h.store.read("synthetic-account")!.environments.prod!.recoveryGeneration, "1");
 assert.deepEqual((await h.environments.list("synthetic-account", auth("admin"))).environments.map(e => e.environmentId).sort(), ["dev", "prod"]);
 assert.deepEqual((await h.environments.list("synthetic-account", auth("reader"))).environments.map(e => e.environmentId), ["dev"]);
 const reopened = nodeStore(h.path); try { assert.equal((reopened.store.read("synthetic-account") as EnvironmentAccount).environmentHistory!.length, 1); } finally { reopened.sql.close(); }
 const changed = structuredClone(signed.change); changed.labelPayload = b64(Buffer.alloc(40, 21)); await assert.rejects(h.environments.change("synthetic-account", auth("admin"), sign(changed)), denies("idempotency_conflict"));
 assert.equal(h.store.read("synthetic-account")!.sequence, 1);
}));
test("账号登录不是可信设备；RO与RW、过期Admin、错误generation不得创建环境", async () => withVault(async h => {
 const login = await h.vault.login("synthetic@example.invalid", "ab".repeat(32));
 await assert.rejects(h.environments.change("synthetic-account", { ...auth("admin"), token: login.token }, sign(create())), denies("device_proof_required"));
 for (const deviceId of ["reader", "writer"]) await assert.rejects(h.environments.change("synthetic-account", auth(deviceId), sign(create("prod", { deviceId, authorityGrantGeneration: "1" }))), denies("admin_required"));
 await assert.rejects(h.environments.change("synthetic-account", { ...auth("admin"), accountGeneration: "2" }, sign(create())), denies("generation_stale"));
 h.store.transaction("synthetic-account", a => { a.grants[grantKey("dev", "admin")] = signGrant(grant("admin", { expiresAt: String(now) })); });
 await assert.rejects(h.environments.change("synthetic-account", auth("admin"), sign(create())), denies("environment_forbidden")); assert.equal(h.store.read("synthetic-account")!.sequence, 0);
}));
test("临时Admin不能创建更长寿的管理授权，缺少或错误恢复封套不留下半个环境", async () => withVault(async h => {
 h.store.transaction("synthetic-account", a => { a.grants[grantKey("dev", "admin")] = signGrant(grant("admin", { expiresAt: String(now + 60) })); });
 await assert.rejects(h.environments.change("synthetic-account", auth("admin"), sign(create())), denies("expiry_escalation"));
 const valid = create(); valid.grants = [signGrant(grant("admin", { environmentId: "prod", expiresAt: String(now + 60), idempotencyKey: "create-prod-admin" }))];
 const stale = structuredClone(valid); stale.recoveryGeneration = "2";
 await assert.rejects(h.environments.change("synthetic-account", auth("admin"), sign(stale)), denies("recovery_generation_stale"));
 const missing = { ...valid, recoveryEnvelope: "" }; assert.throws(() => sign(missing), denies("encoding_invalid"));
 assert.equal(Object.hasOwn(h.store.read("synthetic-account")!.environments, "prod"), false);
 assert.equal((await h.environments.change("synthetic-account", auth("admin"), sign(valid))).sequence, 1);
}));
test("修改名称只接受密文及当前检查点，签名篡改和并发旧快照拒绝", async () => withVault(async h => {
 const renamed = sign(update("rename")); await h.environments.change("synthetic-account", auth("admin"), renamed);
 assert.equal((h.store.read("synthetic-account") as EnvironmentAccount).environmentLabels!.dev, renamed.change.labelPayload);
 assert.equal((await h.environments.change("synthetic-account", auth("admin"), renamed)).replayed, true);
 const tampered = structuredClone(renamed); tampered.change.labelPayload = b64(Buffer.alloc(40, 22)); await assert.rejects(h.environments.change("synthetic-account", auth("admin"), tampered), denies("signature_invalid"));
 await assert.rejects(h.environments.change("synthetic-account", auth("admin"), sign(update("rename", { idempotencyKey: "second-rename" }))), denies("environment_snapshot_stale"));
 assert.throws(() => sign(update("rename", { labelPayload: "my private environment" })), denies("encoding_invalid"));
}));
test("删除保留manager签名墓碑、清当前grants与密文，环境ID不能重新创建；结果不明可查本人收据", async () => withVault(async h => {
 await h.vault.mutate("synthetic-account", auth("writer"), mutation());
 await h.environments.change("synthetic-account", auth("admin"), sign(create("prod", { expectedSequence: "1" })));
 const deletion = sign(update("delete", { expectedSequence: "2" })); const result = await h.environments.change("synthetic-account", auth("admin"), deletion); assert.equal(result.sequence, 3);
 const a = h.store.read("synthetic-account") as EnvironmentAccount;
 assert.equal(Object.hasOwn(a.environments, "dev"), false); assert.equal(a.events.length, 0);
 assert.equal(Object.values(a.grants).some(g => g.grant.environmentId === "dev"), false);
 assert.deepEqual(a.environmentHistory!.at(-1)!.change, deletion); assert.deepEqual(a.environmentHistory!.at(-1)!.subjects, ["admin", "reader", "writer"]);
 assert.deepEqual(await h.environments.changeStatus("synthetic-account", auth("admin"), "delete-dev"), { state: "complete", sequence: 3 });
 assert.deepEqual(await h.environments.changeStatus("synthetic-account", auth("reader"), "delete-dev"), { state: "unknown" });
 const reused = create("dev", { authorityEnvironmentId: "prod", expectedSequence: "3" });
 await assert.rejects(h.environments.change("synthetic-account", auth("admin"), sign(reused)), denies("environment_id_spent"));
 assert.deepEqual((await h.vault.pull("synthetic-account", auth("reader"), 0)).grants, []);
}));
test("轮换原子替换全部有效设备/恢复封套与存活变量，旧版本立刻拒写，所有客户端只能拉到新密文", async () => withVault(async h => {
 await h.vault.mutate("synthetic-account", auth("writer"), mutation());
 const change = sign(rotate()); const result = await h.environments.change("synthetic-account", auth("admin"), change); assert.equal(result.sequence, 3);
 assert.deepEqual(await h.environments.change("synthetic-account", auth("admin"), change), { sequence: 3, replayed: true });
 const a = h.store.read("synthetic-account")!; assert.equal(a.environments.dev!.keyVersion, "2"); assert.equal(a.environments.dev!.recoveryKeyVersion, "2");
 for (const id of ["admin", "reader", "writer"]) assert.equal(a.grants[grantKey("dev", id)]!.grant.keyVersion, "2");
 const pulled = await h.vault.pull("synthetic-account", auth("reader"), 0); assert.equal(pulled.events.length, 1); assert.equal(pulled.events[0]!.mutation.mutation.keyVersion, "2");
 await assert.rejects(h.vault.mutate("synthetic-account", auth("writer"), mutation("writer", { idempotencyKey: "write-old-version" })), denies("grant_stale"));
 assert.deepEqual(await h.vault.mutate("synthetic-account", auth("admin"), change.change.mutations[0]!), { sequence: 3, replayed: true });
}));
test("轮换缺任一有效设备封套、变量重加密、恢复包或改变现有角色都原子回滚", async () => withVault(async h => {
 await h.vault.mutate("synthetic-account", auth("writer"), mutation()); const original = structuredClone(h.store.read("synthetic-account"));
 for (const [patch, error] of [
  [{ grants: rotate().grants.slice(0, 2) }, "device_envelope_set_incomplete"],
  [{ mutations: [] }, "value_reencryption_set_incomplete"],
  [{ grants: rotate().grants.map(g => g.grant.subjectDeviceId === "reader" ? signGrant({ ...g.grant, role: "admin" }) : g) }, "rotation_grant_changed"],
  [{ recoveryGeneration: "2" }, "recovery_generation_stale"],
 ] as [Partial<EnvironmentChange>, string][]) {
  await assert.rejects(h.environments.change("synthetic-account", auth("admin"), sign(rotate(patch))), denies(error));
  assert.deepEqual(h.store.read("synthetic-account"), original);
 }
}));
test("轮换快照与共享写并发时拒绝丢值；已删除变量不能通过轮换复活", async () => withVault(async h => {
 await h.vault.mutate("synthetic-account", auth("writer"), mutation());
 await h.vault.mutate("synthetic-account", auth("writer"), mutation("writer", { idempotencyKey: "write-next", name: "SECOND_KEY" }));
 await assert.rejects(h.environments.change("synthetic-account", auth("admin"), sign(rotate())), denies("environment_snapshot_stale"));
 await h.vault.mutate("synthetic-account", auth("writer"), mutation("writer", { idempotencyKey: "delete-first", operation: "delete", payload: "" }));
 await assert.rejects(h.environments.change("synthetic-account", auth("admin"), sign(rotate({ expectedSequence: "3" }))), denies("value_reencryption_set_incomplete"));
 assert.equal(h.store.read("synthetic-account")!.environments.dev!.keyVersion, "1");
}));
test("轮换不重置过期/撤销主体grant代际，临时Admin可保持已存在永久授权而不扩展它", async () => withVault(async h => {
 h.store.transaction("synthetic-account", a => {
  a.grants[grantKey("dev", "reader")] = signGrant(grant("reader", { expiresAt: String(now), grantGeneration: "7" }));
  a.grants[grantKey("dev", "admin")] = signGrant(grant("admin", { expiresAt: String(now + 100) }));
 });
 await h.vault.mutate("synthetic-account", auth("writer"), mutation());
 const rotation = rotate({ grants: [signGrant(grant("admin", { keyVersion: "2", grantGeneration: "2", expiresAt: String(now + 100), idempotencyKey: "rotation-admin" })), signGrant(grant("writer", { keyVersion: "2", grantGeneration: "2", idempotencyKey: "rotation-writer" }))] });
 await h.environments.change("synthetic-account", auth("admin"), sign(rotation));
 assert.equal(h.store.read("synthetic-account")!.grants[grantKey("dev", "reader")]!.grant.grantGeneration, "7");
 const regrant = signGrant(grant("reader", { keyVersion: "2", grantGeneration: "8", expiresAt: String(now + 100), idempotencyKey: "regrant-reader" }));
 assert.equal((await h.vault.changeGrant("synthetic-account", auth("admin"), regrant)).sequence, 4);
}));
function signRevocation(r: DeviceRevocation) { return { revocation: r, signature: b64(ed25519.sign(deviceRevocationBytes(r), seeds[r.deviceId]!)) }; }
test("全环境Admin以会话绑定一次nonce撤销设备，全部旧会话/请求立刻失效，幂等不增加序号", async () => withVault(async h => {
 const c = await h.environments.revocationChallenge("synthetic-account", auth("admin"), "reader", "revoke-reader");
 assert.deepEqual(await h.environments.revocationChallenge("synthetic-account", auth("admin"), "reader", "revoke-reader"), c);
 assert.deepEqual(await h.environments.revocationStatus("synthetic-account", auth("admin"), "revoke-reader"), { state: "pending", expiresAt: String(now + 120) });
 const signed = signRevocation(c); const result = await h.environments.revokeDevice("synthetic-account", auth("admin"), signed); assert.equal(result.sequence, 1);
 assert.deepEqual(await h.environments.revokeDevice("synthetic-account", auth("admin"), signed), { sequence: 1, replayed: true });
 assert.deepEqual(await h.environments.revocationStatus("synthetic-account", auth("admin"), "revoke-reader"), { state: "complete", sequence: 1 });
 assert.deepEqual(await h.environments.revocationStatus("synthetic-account", auth("writer"), "revoke-reader"), { state: "unknown" });
 const a = h.store.read("synthetic-account")!; assert.equal(a.devices.reader!.revoked, true); assert.equal(a.sessions.some(s => s.deviceId === "reader"), false); assert.equal(a.grants[grantKey("dev", "reader")], undefined);
 await assert.rejects(h.vault.pull("synthetic-account", auth("reader"), 0), e => e instanceof Fault && ["unauthorized", "device_untrusted"].includes(e.code));
 await assert.rejects(h.vault.deviceChallenge("synthetic-account", auth("reader")), e => e instanceof Fault && ["unauthorized", "device_untrusted"].includes(e.code));
}));
test("仅部分环境Admin不能撤销全局设备；签名、短时nonce、会话、账号和精确subject公钥均绑定", async () => withVault(async h => {
 await h.environments.change("synthetic-account", auth("admin"), sign(create()));
 h.store.transaction("synthetic-account", a => { a.grants[grantKey("prod", "admin")] = signGrant(grant("admin", { environmentId: "prod", role: "ro" })); });
 await assert.rejects(h.environments.revocationChallenge("synthetic-account", auth("admin"), "reader", "revoke-reader"), denies("all_environment_admin_required"));
 h.store.transaction("synthetic-account", a => { a.grants[grantKey("prod", "admin")] = signGrant(grant("admin", { environmentId: "prod" })); });
 const c = await h.environments.revocationChallenge("synthetic-account", auth("admin"), "reader", "revoke-reader");
 await assert.rejects(h.environments.revokeDevice("synthetic-account", auth("admin"), { revocation: c, signature: b64(Buffer.alloc(64)) }), denies("signature_invalid"));
 await assert.rejects(h.environments.revokeDevice("synthetic-account", auth("admin"), signRevocation({ ...c, subjectReceivingPublicKey: b64(Buffer.alloc(32, 33)) })), denies("challenge_invalid"));
 await assert.rejects(h.environments.revokeDevice("synthetic-account", auth("admin"), signRevocation({ ...c, sessionHash: "0".repeat(64) })), denies("binding_invalid"));
 h.advance(120); await assert.rejects(h.environments.revokeDevice("synthetic-account", auth("admin"), signRevocation(c)), denies("challenge_invalid")); assert.equal(h.store.read("synthetic-account")!.devices.reader!.revoked, false);
}));
test("撤销nonce发出后Admin被降权或新增环境，完成阶段逐次重查阻止越权", async () => withVault(async h => {
 const c = await h.environments.revocationChallenge("synthetic-account", auth("admin"), "reader", "revoke-reader");
 await h.environments.change("synthetic-account", auth("admin"), sign(create()));
 await assert.rejects(h.environments.revokeDevice("synthetic-account", auth("admin"), signRevocation(c)), denies("authority_set_stale"));
 assert.equal(h.store.read("synthetic-account")!.devices.reader!.revoked, false);
 const next = await h.environments.revocationChallenge("synthetic-account", auth("admin"), "reader", "revoke-reader-next");
 h.store.transaction("synthetic-account", a => { a.grants[grantKey("dev", "admin")] = signGrant(grant("admin", { role: "ro" })); });
 await assert.rejects(h.environments.revokeDevice("synthetic-account", auth("admin"), signRevocation(next)), denies("all_environment_admin_required"));
}));
test("环境签域拒绝额外明文字段/重复清单/非规范检查点与64位溢出", () => {
 assert.throws(() => environmentChangeBytes({ ...create(), plaintext: "synthetic-only" } as EnvironmentChange), denies("fields_invalid"));
 assert.throws(() => environmentChangeBytes(create("prod", { expectedSequence: "01" })), denies("generation_invalid"));
 assert.throws(() => environmentChangeBytes(create("prod", { expectedSequence: "9007199254740992" })), denies("checkpoint_invalid"));
 assert.throws(() => environmentChangeBytes(create("prod", { keyVersion: "18446744073709551616" })), denies("generation_invalid"));
 assert.throws(() => environmentGrantsHash([create().grants[0]!, create().grants[0]!] ), denies("grant_duplicate"));
 assert.throws(() => environmentMutationsHash([rotate().mutations[0]!, rotate().mutations[0]!] ), denies("mutation_duplicate"));
});

test("独立Go生成的环境/撤销向量与Node canonical bytes、manifest hash和Ed25519签名完全一致", () => {
 const v = JSON.parse(readFileSync(new URL("./vectors/environment-lifecycle-v1.json", import.meta.url), "utf8")) as { syntheticSigningSeedHex: string; signingPublicKey: string; changes: { signed: SignedEnvironmentChange; payloadBase64: string; grantsHash: string; mutationsHash: string }[]; revocation: { signed: { revocation: DeviceRevocation; signature: string }; payloadBase64: string; authoritiesHash: string } };
 const key = Buffer.from(v.syntheticSigningSeedHex, "hex"); assert.equal(b64(ed25519.getPublicKey(key)), v.signingPublicKey);
 for (const item of v.changes) {
  const payload = environmentChangeBytes(item.signed.change); assert.equal(b64(payload), item.payloadBase64);
  assert.equal(environmentGrantsHash(item.signed.change.grants), item.grantsHash); assert.equal(environmentMutationsHash(item.signed.change.mutations), item.mutationsHash);
  assert.equal(b64(ed25519.sign(payload, key)), item.signed.signature);
  assert.ok(ed25519.verify(Buffer.from(item.signed.signature, "base64url"), payload, Buffer.from(v.signingPublicKey, "base64url"), { zip215: false }));
 }
 const item = v.revocation, payload = deviceRevocationBytes(item.signed.revocation); assert.equal(b64(payload), item.payloadBase64);
 assert.equal(revocationAuthorityHash(item.signed.revocation.authorities), item.authoritiesHash); assert.equal(b64(ed25519.sign(payload, key)), item.signed.signature);
});

test("暂未定义账号级管理授权时，删除最后环境原子拒绝而不隐式升级登录或根公钥权限", async () => withVault(async h => {
 await h.vault.mutate("synthetic-account", auth("writer"), mutation());
 const before = structuredClone(h.store.read("synthetic-account"));
 await assert.rejects(h.environments.change("synthetic-account", auth("admin"), sign(update("delete", { expectedSequence: "1" }))), denies("last_environment_requires_account_management"));
 assert.deepEqual(h.store.read("synthetic-account"), before);
 assert.deepEqual(await h.environments.changeStatus("synthetic-account", auth("admin"), "delete-dev"), { state: "unknown" });
}));

test("真实HTTP轮换允许两项合法大密文超过100k，同时保持环境1MB和普通请求100k硬上限", async () => withVault(async h => {
 const packet = b64(Buffer.alloc(40040, 91));
 await h.vault.mutate("synthetic-account", auth("writer"), mutation("writer", { payload: packet }));
 await h.vault.mutate("synthetic-account", auth("writer"), mutation("writer", { idempotencyKey: "large-second-value", name: "SECOND_KEY", payload: packet }));
 const values = ["SYNTHETIC_KEY", "SECOND_KEY"].map(name => mutation("admin", { name, keyVersion: "2", grantGeneration: "2", idempotencyKey: `large-rotation-${name}`, payload: packet }));
 const signed = sign(rotate({ expectedSequence: "2", mutations: values })), body = JSON.stringify(signed); assert.ok(Buffer.byteLength(body) > 100000); assert.ok(Buffer.byteLength(body) < 1000000);
 const request = (path: string, data: string) => new Request(`https://selfhost.example.invalid/v1/accounts/synthetic-account/${path}`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${auth("admin").token}`, "x-harmonia-device-id": "admin", "x-harmonia-account-generation": "1" }, body: data });
 const response = await route(request("environment-changes", body), h.vault); assert.equal(response.status, 200, JSON.stringify(await response.clone().json()));
 assert.deepEqual(await response.json(), { sequence: 5, replayed: false }); assert.equal(h.store.read("synthetic-account")!.environments.dev!.keyVersion, "2");
 const before = structuredClone(h.store.read("synthetic-account"));
 const oversized = await route(request("environment-changes", JSON.stringify({ ...signed, padding: "x".repeat(1000000) })), h.vault); assert.equal(oversized.status, 413); assert.deepEqual(await oversized.json(), { error: "body_too_large" });
 const ordinary = await route(request("mutations", JSON.stringify({ ...values[0], padding: "x".repeat(100000) })), h.vault); assert.equal(ordinary.status, 413);
 assert.deepEqual(h.store.read("synthetic-account"), before);
}));

test("最大合法双密文轮换超出账号历史容量时受控503并整笔回滚，不改版本或吞掉存活变量", async () => withVault(async h => {
 const packet = b64(Buffer.alloc(65576, 92));
 await h.vault.mutate("synthetic-account", auth("writer"), mutation("writer", { payload: packet }));
 await h.vault.mutate("synthetic-account", auth("writer"), mutation("writer", { idempotencyKey: "capacity-second-value", name: "SECOND_KEY", payload: packet }));
 const values = ["SYNTHETIC_KEY", "SECOND_KEY"].map(name => mutation("admin", { name, keyVersion: "2", grantGeneration: "2", idempotencyKey: `capacity-rotation-${name}`, payload: packet }));
 const signed = sign(rotate({ expectedSequence: "2", mutations: values })); const before = structuredClone(h.store.read("synthetic-account"));
 await assert.rejects(h.environments.change("synthetic-account", auth("admin"), signed), denies("account_capacity_reached"));
 assert.deepEqual(h.store.read("synthetic-account"), before);
 assert.deepEqual(await h.environments.changeStatus("synthetic-account", auth("admin"), "rotate-dev"), { state: "unknown" });
}));
