import test from "node:test";
import assert from "node:assert/strict";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { nodeStore } from "../src/node-store.js";
import { VaultService } from "../src/service.js";
import { Fault, grantKey, type Auth, type SignedGrant } from "../src/model.js";
import { grantBytes, mutationBytes } from "../src/protocol.js";
import { EnrollmentService, relayFields, type LoginAuth, type Relay } from "../src/enrollment.js";
import { canonical, enrollmentFields, initializationHash, grantsHash, own, transcriptHash,
  type EnrollmentAccount, type EnrollmentCertificate, type InitializationProposal, type PairingContext, type PairingRecord } from "../src/enrollment-wire.js";
import { fixtureAccount, email, clientCredential, recoveryKeys, now } from "./fixtures.js";
const vector = JSON.parse(readFileSync(new URL("./vectors/vault-initialization-v1.json", import.meta.url), "utf8")) as {
  proposal: InitializationProposal; proof: { proposalHash: string }; syntheticRootSigningSeedHex: string; syntheticRecoverySeedHex: string;
};
const accountId = "account-test";
const rootSeed = Buffer.from(vector.syntheticRootSigningSeedHex, "hex");
const recoverySeed = Buffer.from(vector.syntheticRecoverySeedHex, "hex");
const recovery = recoveryKeys(recoverySeed, accountId);
const b64 = (v: Uint8Array): string => Buffer.from(v).toString("base64url");
const sign = (fields: unknown, seed: Uint8Array): string => b64(ed25519.sign(canonical(fields), seed));
const denies = (code: string) => (e: unknown): boolean => e instanceof Fault && e.code === code;
interface Harness { store: ReturnType<typeof nodeStore>["store"]; service: EnrollmentService; vault: VaultService; login: LoginAuth; path: string; advance: (n: number) => void }
async function withEmpty(run: (h: Harness) => Promise<void>, verified = true): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "harmonia-enrollment-")), path = join(dir, "synthetic.sqlite");
  const { store, sql } = nodeStore(path); let clock = now;
  try {
    const a = await fixtureAccount(accountId); a.devices = {}; a.environments = {}; a.grants = {}; a.events = []; a.sessions = [];
    a.recoverySigningPublicKey = null; a.recoveryReceivingPublicKey = null; a.verified = verified; store.create(a);
    const vault = new VaultService(store, { allowRegistration: true, requireEmailVerification: false }, () => clock);
    const login = await vault.login(email, clientCredential);
    await run({ store, path, vault, service: new EnrollmentService(store, true, () => clock), login, advance: n => { clock += n; } });
  } finally { sql.close(); rmSync(dir, { recursive: true, force: true }); }
}
async function initialize(h: Harness): Promise<Auth> {
  const challenge = await h.service.initialize(accountId, h.login, vector.proposal);
  const rootSignature = sign(challenge.signingPayload, rootSeed), recoverySignature = sign(challenge.signingPayload, recovery.signingSeed);
  await h.service.completeInitialization(accountId, h.login, vector.proposal.idempotencyKey, challenge.challengeId as string, rootSignature, recoverySignature);
  const deviceAuth = { ...h.login, deviceId: vector.proposal.device.id };
  const proof = await h.vault.deviceChallenge(accountId, deviceAuth);
  const bound = await h.vault.deviceSession(accountId, deviceAuth, proof.challengeId, sign(proof.signingPayload, rootSeed));
  return { token: bound.token, accountGeneration: "1", deviceId: vector.proposal.device.id };
}
test("初始化哈希与独立 Go HPKE / Node 签名向量相同，双签原子创建根与全部封套", async () => withEmpty(async h => {
  assert.equal(initializationHash(accountId, "1", vector.proposal), vector.proof.proposalHash);
  const c = await h.service.initialize(accountId, h.login, vector.proposal);
  assert.equal(Object.keys(h.store.read(accountId)!.devices).length, 0);
  const signature = sign(c.signingPayload, rootSeed), recoverySignature = sign(c.signingPayload, recovery.signingSeed);
  const completed = await h.service.completeInitialization(accountId, h.login, vector.proposal.idempotencyKey, c.challengeId as string, signature, recoverySignature);
  assert.equal(completed.state, "complete"); assert.equal(completed.sequence, 1);
  assert.equal((await h.service.completeInitialization(accountId, h.login, vector.proposal.idempotencyKey, c.challengeId as string, signature, recoverySignature)).replayed, true);
  const state = h.store.read(accountId) as EnrollmentAccount;
  assert.equal(state.trustRoot!.rootSigningPublicKey, vector.proposal.device.signingPublicKey);
  assert.deepEqual(Object.keys(state.environments).sort(), ["environment-alpha", "environment-beta"]);
  assert.equal(state.environments["environment-alpha"]!.recoveryGeneration, "1");
  const reopened = nodeStore(h.path); try { assert.equal((reopened.store.read(accountId) as EnrollmentAccount).trustRoot!.signature, vector.proposal.trustRootSignature); } finally { reopened.sql.close(); }
  const other = structuredClone(vector.proposal); other.idempotencyKey = "replace-existing-vault";
  await assert.rejects(h.service.initialize(accountId, h.login, other), denies("vault_already_initialized"));
}));
test("缺恢复持钥证明、错误会话/代际、过期 nonce 不创建任何设备或环境", async () => withEmpty(async h => {
  const c = await h.service.initialize(accountId, h.login, vector.proposal);
  const root = sign(c.signingPayload, rootSeed);
  await assert.rejects(h.service.completeInitialization(accountId, h.login, vector.proposal.idempotencyKey, c.challengeId as string, root, root), denies("signature_invalid"));
  assert.equal(h.store.read(accountId)!.sequence, 0);
  assert.equal(Object.keys(h.store.read(accountId)!.devices).length, 0);
  const otherLogin = await h.vault.login(email, clientCredential);
  await assert.rejects(h.service.completeInitialization(accountId, otherLogin, vector.proposal.idempotencyKey, c.challengeId as string, root, sign(c.signingPayload, recovery.signingSeed)), denies("challenge_invalid"));
  h.advance(120);
  await assert.rejects(h.service.completeInitialization(accountId, h.login, vector.proposal.idempotencyKey, c.challengeId as string, root, sign(c.signingPayload, recovery.signingSeed)), denies("challenge_invalid"));
}));
test("初始化严格拒绝短码/明文额外字段、管理钥替换、重复环境与未验证邮箱", async () => withEmpty(async h => {
  await assert.rejects(h.service.initialize(accountId, h.login, { ...vector.proposal, shortCode: "12345678" } as InitializationProposal), denies("fields_invalid"));
  const modified = structuredClone(vector.proposal); modified.device.signingPublicKey = b64(ed25519.getPublicKey(Buffer.alloc(32, 91)));
  await assert.rejects(h.service.initialize(accountId, h.login, modified), denies("signature_invalid"));
  const duplicate = structuredClone(vector.proposal); duplicate.environments.push(duplicate.environments[0]!);
  await assert.rejects(h.service.initialize(accountId, h.login, duplicate), denies("initial_environments_invalid"));
  h.store.transaction(accountId, a => { a.verified = false; });
  await assert.rejects(h.service.initialize(accountId, h.login, vector.proposal), denies("email_verification_required"));
}));
const newSeed = Buffer.alloc(32, 71), newReceiving = x25519.getPublicKey(Buffer.alloc(32, 72));
async function relayed(h: Harness, manager: Auth): Promise<PairingRecord> {
  const view = await h.service.beginPairing(accountId, h.login, { idempotencyKey: "pairing-synthetic-1", deviceId: "device-cli",
    signingPublicKey: b64(ed25519.getPublicKey(newSeed)), receivingPublicKey: b64(newReceiving), approverDeviceId: manager.deviceId });
  const context = view.context as PairingContext;
  for (const [side, kind, value, keys, credentials] of [
    ["initiator", "message", 81, newSeed, h.login], ["approver", "message", 82, rootSeed, manager],
    ["initiator", "confirmation", 83, newSeed, h.login], ["approver", "confirmation", 84, rootSeed, manager],
  ] as const) {
    const relay = { side, kind, payload: b64(Buffer.alloc(32, value)) };
    const r = { context } as PairingRecord;
    await h.service.relay(accountId, credentials, "pairing-synthetic-1", { ...relay, signature: sign(relayFields(r, relay), keys) });
  }
  return own((h.store.read(accountId) as EnrollmentAccount).pairingSessions, "pairing-synthetic-1")!;
}
function certificate(record: PairingRecord, role: "ro" | "rw" | "admin" = "ro"): EnrollmentCertificate {
  const g = structuredClone(vector.proposal.environments[0]!.grant.grant);
  g.subjectDeviceId = record.context.initiatorDeviceId; g.subjectSigningPublicKey = record.context.initiatorSigningPublicKey;
  g.subjectReceivingPublicKey = record.context.initiatorReceivingPublicKey; g.role = role; g.idempotencyKey = "new-device-grant";
  const grant = { grant: g, signature: b64(ed25519.sign(grantBytes(g), rootSeed)) };
  const c: EnrollmentCertificate = { context: record.context, pairingProfile: "boringssl-spake2-edwards25519-draft02-v1",
    transcriptHash: transcriptHash(record), grants: [grant], approverSignature: "" };
  c.approverSignature = sign(enrollmentFields(c), rootSeed);
  return c;
}
test("中继仅公开消息，可信手机签批准与新设备双签后才原子入网；RO仍不能写", async () => withEmpty(async h => {
  const manager = await initialize(h), record = await relayed(h, manager), cert = certificate(record);
  await assert.rejects(h.vault.deviceChallenge(accountId, { ...h.login, deviceId: "device-cli" }), denies("device_untrusted"));
  await h.service.approve(accountId, manager, record.idempotencyKey, { grants: cert.grants, transcriptHash: cert.transcriptHash, signature: cert.approverSignature });
  assert.equal(Object.hasOwn(h.store.read(accountId)!.devices, "device-cli"), false);
  const signature = sign(enrollmentFields(cert), newSeed);
  const result = await h.service.completePairing(accountId, h.login, record.idempotencyKey, signature);
  assert.equal(result.state, "complete"); assert.equal(result.sequence, 2);
  assert.equal((await h.service.completePairing(accountId, h.login, record.idempotencyKey, signature)).replayed, true);
  assert.equal(h.store.read(accountId)!.grants[grantKey(cert.grants[0]!.grant.environmentId, "device-cli")]!.grant.role, "ro");
  const challenge = await h.vault.deviceChallenge(accountId, { ...h.login, deviceId: "device-cli" });
  const bound = await h.vault.deviceSession(accountId, { ...h.login, deviceId: "device-cli" }, challenge.challengeId, sign(challenge.signingPayload, newSeed));
  assert.equal((await h.vault.pull(accountId, { token: bound.token, accountGeneration: "1", deviceId: "device-cli" }, 0)).grants.length, 1);
  const mutation = { accountId, accountGeneration: "1", deviceId: "device-cli", environmentId: cert.grants[0]!.grant.environmentId, keyVersion: "1", grantGeneration: "1", operation: "put" as const, idempotencyKey: "ro-write", name: "SYNTHETIC_KEY", payload: b64(Buffer.alloc(40, 90)) };
  await assert.rejects(h.vault.mutate(accountId, { token: bound.token, accountGeneration: "1", deviceId: "device-cli" }, { mutation, signature: b64(ed25519.sign(mutationBytes(mutation), newSeed)) }), denies("write_forbidden"));
  // 此单元测试的中继数据是合成声明；真正 SPAKE2 与 HPKE 在根跨语言验收中验证。
}));
test("批准之后管理手机被降权或授权到期，完成阶段重查阻止新设备生效", async () => withEmpty(async h => {
  const manager = await initialize(h), record = await relayed(h, manager), cert = certificate(record);
  await h.service.approve(accountId, manager, record.idempotencyKey, { grants: cert.grants, transcriptHash: cert.transcriptHash, signature: cert.approverSignature });
  h.store.transaction(accountId, a => { a.grants[grantKey(cert.grants[0]!.grant.environmentId, manager.deviceId)]!.grant.role = "ro"; });
  await assert.rejects(h.service.completePairing(accountId, h.login, record.idempotencyKey, sign(enrollmentFields(cert), newSeed)), denies("admin_required"));
  assert.equal(Object.hasOwn(h.store.read(accountId)!.devices, "device-cli"), false); assert.equal(h.store.read(accountId)!.sequence, 1);
}));
test("未双向确认、未绑定管理会话、换 transcript、错误新设备签名不能入网", async () => withEmpty(async h => {
  const manager = await initialize(h);
  const proposal = { idempotencyKey: "pairing-synthetic-1", deviceId: "device-cli", signingPublicKey: b64(ed25519.getPublicKey(newSeed)), receivingPublicKey: b64(newReceiving), approverDeviceId: manager.deviceId };
  await h.service.beginPairing(accountId, h.login, proposal);
  await assert.rejects(h.service.approve(accountId, manager, proposal.idempotencyKey, { grants: [vector.proposal.environments[0]!.grant], transcriptHash: "0".repeat(64), signature: b64(Buffer.alloc(64)) }), denies("pairing_confirmation_required"));
  await assert.rejects(h.service.pairingStatus(accountId, { ...h.login, token: b64(Buffer.alloc(32, 88)), deviceId: manager.deviceId }, proposal.idempotencyKey), denies("unauthorized"));
  await assert.rejects(h.service.relay(accountId, manager, proposal.idempotencyKey, { side: "initiator", kind: "message", payload: b64(Buffer.alloc(32, 81)), signature: b64(Buffer.alloc(64)) }), denies("pairing_step_invalid"));
  const record = await relayed(h, manager), cert = certificate(record);
  await assert.rejects(h.service.approve(accountId, manager, record.idempotencyKey, { grants: cert.grants, transcriptHash: "0".repeat(64), signature: cert.approverSignature }), denies("pairing_transcript_mismatch"));
  await h.service.approve(accountId, manager, record.idempotencyKey, { grants: cert.grants, transcriptHash: cert.transcriptHash, signature: cert.approverSignature });
  await assert.rejects(h.service.completePairing(accountId, h.login, record.idempotencyKey, sign(enrollmentFields(cert), rootSeed)), denies("signature_invalid"));
  assert.equal(Object.hasOwn(h.store.read(accountId)!.devices, "device-cli"), false);
}));

test("外部畸形清单返回结构化错误，重复管理签公钥不能形成新配对", async () => withEmpty(async h => {
  const malformed = structuredClone(vector.proposal);
  malformed.environments = [null, malformed.environments[0]] as unknown as InitializationProposal["environments"];
  await assert.rejects(h.service.initialize(accountId, h.login, malformed), denies("fields_invalid"));
  assert.throws(() => grantsHash([null, vector.proposal.environments[0]!.grant] as unknown as SignedGrant[]), denies("fields_invalid"));
  assert.equal(h.store.read(accountId)!.sequence, 0);
  const manager = await initialize(h);
  await assert.rejects(h.service.beginPairing(accountId, h.login, {
    idempotencyKey: "duplicate-manager-key", deviceId: "alias-device", approverDeviceId: manager.deviceId,
    signingPublicKey: vector.proposal.device.signingPublicKey, receivingPublicKey: b64(newReceiving),
  }), denies("pairing_identity_invalid"));
  assert.equal(Object.hasOwn((h.store.read(accountId) as EnrollmentAccount).pairingSessions ?? {}, "duplicate-manager-key"), false);
  assert.equal(h.store.read(accountId)!.sequence, 1);
}));
