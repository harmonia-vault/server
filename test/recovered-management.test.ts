import test from "node:test";
import assert from "node:assert/strict";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { nodeHarness, workerHarness, b64, sign, vector, resign, type Harness } from "./recovery-origin-fixtures.js";
import { completeContinuous, completeRecovered } from "./recovered-management-fixtures.js";
import { transitionHash } from "../src/recovery-authority-wire.js";
import { environmentChangeBytes, environmentSubmissionContent, type EnvironmentChange, type SignedEnvironmentChangeV2 } from "../src/environments.js";
import { environmentOriginBytes, environmentChangeHash, environmentRights } from "../src/environment-origin.js";
import { grantBytes, mutationBytes } from "../src/protocol.js";
import { tokenHash } from "../src/service.js";
import { canonical, hash, pairingContextFields, pairingProfile } from "../src/enrollment-wire.js";
import { relayFields } from "../src/enrollment.js";
import { issuerAuthorityHash } from "../src/issuer-proof.js";
import { verifyIssuerRecoveryGraph, enrollmentV4Fields, type EnrollmentApprovalV4 } from "../src/issuer-recovery.js";
import type { Grant, SignedGrant, SignedMutation } from "../src/model.js";
const capability = "issuer-recovery-v1";
const key = (who: "E" | "F") => Buffer.alloc(32, who === "E" ? 6 : 7);
const signedGrant = (grant: Grant): SignedGrant => ({ grant, signature: b64(ed25519.sign(grantBytes(grant), key(grant.issuerDeviceId.slice(-1) as "E" | "F"))) });
const signedMutation = (mutation: SignedMutation["mutation"]): SignedMutation => ({ mutation, signature: b64(ed25519.sign(mutationBytes(mutation), key(mutation.deviceId.slice(-1) as "E" | "F"))) });
async function response(h: Harness, path: string, method = "GET", body?: unknown, who = "E") {
  const r = await h.send(path, method, body, who);
  assert.equal(r.status, 200, JSON.stringify(r.data)); return r.data;
}
async function control(h: Harness, environmentId: string, who = "E", management = false) {
  const c = await response(h, `/${management ? "grant-management" : "issuer-evidence"}?environmentId=${environmentId}&capability=${capability}`, "GET", undefined, who);
  assert.equal(c.issuerEvidence.profile, "harmonia/issuer-proof/v3");
  const graph = verifyIssuerRecoveryGraph(c.issuerEvidence);
  assert.equal(graph.identities.has(`device-${who}`), true); return c;
}
function packet(change: EnvironmentChange, authority: SignedGrant, before: SignedGrant[]): SignedEnvironmentChangeV2 {
  const signature = b64(ed25519.sign(environmentChangeBytes(change), key(change.deviceId.slice(-1) as "E" | "F")));
  const origin = { accountId: change.accountId, accountGeneration: change.accountGeneration, actorDeviceId: change.deviceId, environmentId: change.environmentId, operation: change.operation as "create" | "rotate", authorityEnvironmentId: change.authorityEnvironmentId, authorityKeyVersion: change.authorityKeyVersion, authorityGrantGeneration: change.authorityGrantGeneration, previousKeyVersion: change.previousKeyVersion, keyVersion: change.keyVersion, expectedSequence: change.expectedSequence, idempotencyKey: change.idempotencyKey, changeHash: environmentChangeHash(environmentChangeBytes(change), signature), authorityHash: issuerAuthorityHash(authority), before: before.map(environmentRights), after: change.grants.map(environmentRights) };
  return { change, signature, origin: { origin, signature: b64(ed25519.sign(environmentOriginBytes(origin), key(change.deviceId.slice(-1) as "E" | "F"))) } };
}
async function createEnvironment(h: Harness, source: string, environmentId: string, who: "E" | "F", id: string) {
  const c = await control(h, source, who), authority = c.grants.find((g: SignedGrant) => g.grant.subjectDeviceId === `device-${who}`) as SignedGrant;
  const grant = signedGrant({ ...authority.grant, issuerDeviceId: `device-${who}`, environmentId, keyVersion: "1", grantGeneration: "1", role: "admin", idempotencyKey: `${id}-self`, envelope: b64(Buffer.alloc(80, 121)) });
  const change: EnvironmentChange = { accountId: h.account.id, accountGeneration: "1", deviceId: `device-${who}`, environmentId, operation: "create", authorityEnvironmentId: source, authorityKeyVersion: authority.grant.keyVersion, authorityGrantGeneration: authority.grant.grantGeneration, previousKeyVersion: "0", keyVersion: "1", expectedSequence: String(c.sequence), idempotencyKey: id, labelPayload: b64(Buffer.alloc(40, 122)), recoveryGeneration: "2", recoveryEnvelope: b64(Buffer.alloc(80, 123)), grants: [grant], mutations: [] };
  const p = packet(change, authority, []), accepted = await response(h, "/environment-changes-v3", "POST", p, who);
  assert.equal(accepted.sequence, c.sequence + 1); return { grant, packet: p, accepted };
}
async function pairF(h: Harness) {
  const pub = b64(ed25519.getPublicKey(key("F"))), receiver = b64(x25519.getPublicKey(Buffer.alloc(32, 24))), id = "management-E-F";
  const begin = await response(h, "/pairings-v4", "POST", { idempotencyKey: id, deviceId: "device-F", signingPublicKey: pub, receivingPublicKey: receiver, approverDeviceId: "device-E", certificateVersion: "4", capabilities: [capability] }, "login"), context = begin.context;
  for (const [side, kind, value, who] of [["initiator", "message", 71, "login"], ["approver", "message", 72, "E"], ["initiator", "confirmation", 73, "login"], ["approver", "confirmation", 74, "E"]] as const) {
    const relay = { side, kind, payload: b64(Buffer.alloc(32, value)) };
    await response(h, `/pairings-v4/${id}/relay`, "POST", { ...relay, signature: sign(relayFields({ context } as any, relay), key(side === "initiator" ? "F" : "E")) }, who);
  }
  const status = await response(h, `/pairings-v4/${id}`, "GET", undefined, "login"), c = await control(h, "environment-Y"), authority = c.grants.find((g: SignedGrant) => g.grant.subjectDeviceId === "device-E") as SignedGrant;
  const grant = signedGrant({ ...authority.grant, subjectDeviceId: "device-F", subjectSigningPublicKey: pub, subjectReceivingPublicKey: receiver, grantGeneration: "1", role: "ro", idempotencyKey: "management-pair-F-Y", envelope: b64(Buffer.alloc(80, 124)) });
  const certificate: EnrollmentApprovalV4 = { certificateVersion: "4", capabilities: [capability], context, pairingProfile, transcriptHash: hash(["harmonia/pairing-transcript/v1", b64(canonical(pairingContextFields(context))), status.messages.initiator, status.messages.approver]), grants: [grant], issuerProof: c.issuerEvidence, approverSignature: "" };
  certificate.approverSignature = sign(enrollmentV4Fields(certificate), key("E"));
  await response(h, `/pairings-v4/${id}/approve`, "POST", { certificateVersion: "4", capabilities: [capability], grants: [grant], transcriptHash: certificate.transcriptHash, issuerProof: certificate.issuerProof, signature: certificate.approverSignature });
  await response(h, `/pairings-v4/${id}/complete`, "POST", { signature: sign(enrollmentV4Fields(certificate), key("F")) }, "login");
  const challenge = await response(h, "/boot-challenges", "POST", { deviceId: "device-F", accountGeneration: "1" }, "login"), session = await response(h, "/boot-sessions", "POST", { deviceId: "device-F", accountGeneration: "1", challengeId: challenge.challengeId, signature: sign(challenge.signingPayload, key("F")) }, "login");
  h.setToken("F", session.token); return grant;
}
async function prepare(h: Harness) { const transition = await completeContinuous(h, true); await completeRecovered(h, transitionHash(transition.packet)); await pairF(h); }
for (const [runtime, harness] of [["Node真实TCP", nodeHarness], ["workerd真实HTTP", workerHarness]] as const) {
  test(`${runtime} recovered E新增Z→未授权F归档→F读写及Admin管理→轮换→原ID确认→rename/delete`, { timeout: 120000 }, async () => {
    const h = await harness(); try {
      await prepare(h);
      const created = await createEnvironment(h, "environment-Y", "environment-Z", "E", "management-create-Z");
      const initial = await control(h, "environment-Z", "E", true), subject = initial.subjects.find((s: any) => s.deviceId === "device-F");
      assert.equal(subject.currentGrant, null); assert.equal(subject.highestGrantGeneration, "0");
      const graph = verifyIssuerRecoveryGraph(initial.issuerEvidence); assert.equal(graph.identities.get("device-F")!.signing, subject.signingPublicKey);
      assert.deepEqual(Object.keys(initial).sort(), ["accountGeneration", "accountId", "environmentId", "issuerEvidence", "keyVersion", "sequence", "subjects"]);
      const grant = signedGrant({ ...created.grant.grant, subjectDeviceId: "device-F", subjectSigningPublicKey: subject.signingPublicKey, subjectReceivingPublicKey: subject.receivingPublicKey, role: "rw", idempotencyKey: "management-F-Z-rw", envelope: b64(Buffer.alloc(80, 125)) });
      const accepted = await response(h, "/grants", "POST", grant), receipt = await response(h, `/grant-status?idempotencyKey=${grant.grant.idempotencyKey}`);
      assert.equal(receipt.sequence, accepted.sequence); assert.equal(receipt.contentHash, await tokenHash(b64(grantBytes(grant.grant)) + "." + grant.signature));
      const mutation = signedMutation({ accountId: h.account.id, accountGeneration: "1", deviceId: "device-F", environmentId: "environment-Z", keyVersion: "1", grantGeneration: "1", operation: "put", idempotencyKey: "management-F-put-Z", name: "SYNTHETIC_Z", payload: b64(Buffer.alloc(40, 126)) });
      await response(h, "/mutations", "POST", mutation, "F");
      const pull = await response(h, `/pull?after=0&capability=${capability}`, "GET", undefined, "F");
      verifyIssuerRecoveryGraph(pull.issuerEvidence); assert.ok(pull.events.some((e: any) => e.mutation.mutation.name === "SYNTHETIC_Z"));
      assert.equal(pull.events.some((e: any) => e.mutation.mutation.environmentId === "env-fixture"), false);
      const admin = signedGrant({ ...grant.grant, grantGeneration: "2", role: "admin", idempotencyKey: "management-F-Z-admin" }); await response(h, "/grants", "POST", admin);
      const child = await createEnvironment(h, "environment-Z", "environment-W", "F", "management-F-create-W");
      assert.equal((await h.send(`/grant-management?environmentId=environment-W&capability=${capability}`, "GET", undefined, "E")).status, 403);
      const c = await control(h, "environment-Z", "F"), before = c.grants as SignedGrant[], authority = before.find(g => g.grant.subjectDeviceId === "device-F")!, grants = before.map(g => signedGrant({ ...g.grant, issuerDeviceId: "device-F", keyVersion: "2", grantGeneration: String(BigInt(g.grant.grantGeneration) + 1n), idempotencyKey: `management-rotate-Z-${g.grant.subjectDeviceId}`, envelope: b64(Buffer.alloc(80, 127)) }));
      const nextMutation = signedMutation({ ...mutation.mutation, keyVersion: "2", grantGeneration: grants.find(g => g.grant.subjectDeviceId === "device-F")!.grant.grantGeneration, idempotencyKey: "management-Z-reencrypt", payload: b64(Buffer.alloc(40, 128)) });
      const change: EnvironmentChange = { ...created.packet.change, deviceId: "device-F", operation: "rotate", authorityEnvironmentId: "environment-Z", authorityKeyVersion: "1", authorityGrantGeneration: authority.grant.grantGeneration, previousKeyVersion: "1", keyVersion: "2", expectedSequence: String(c.sequence), idempotencyKey: "management-F-rotate-Z", labelPayload: b64(Buffer.alloc(40, 129)), recoveryEnvelope: b64(Buffer.alloc(80, 130)), grants, mutations: [nextMutation] };
      const rotation = packet(change, authority, before), rotated = await response(h, "/environment-changes-v3", "POST", rotation, "F"); assert.equal(rotated.sequence, c.sequence + 2);
      const status = await response(h, `/environment-changes-v3/${change.idempotencyKey}`, "GET", undefined, "F"), expectedHash = await tokenHash(environmentSubmissionContent(environmentChangeBytes(change), rotation.signature, rotation.origin));
      assert.deepEqual(status, { state: "complete", sequence: rotated.sequence, contentHash: expectedHash });
      const retry = await response(h, "/environment-changes-v3", "POST", rotation, "F"); assert.equal(retry.replayed, true); assert.equal(retry.sequence, rotated.sequence);
      assert.deepEqual(await response(h, `/environment-changes-v2/${change.idempotencyKey}`, "GET", undefined, "F"), status);
      const v2 = await h.send("/environment-changes-v2", "POST", rotation, "F"); assert.equal(v2.status, 403);
      const current = await control(h, "environment-Z", "E", true); assert.equal(current.sequence, rotated.sequence); assert.equal(current.keyVersion, "2");
      assert.equal(current.subjects.find((s: any) => s.deviceId === "device-F").highestGrantGeneration, "3");
      for (const op of ["rename", "delete"] as const) {
        const w = await control(h, "environment-W", "F"), g = w.grants.find((g: SignedGrant) => g.grant.subjectDeviceId === "device-F");
        const change: EnvironmentChange = { ...child.packet.change, operation: op, previousKeyVersion: "1", authorityEnvironmentId: "environment-W", authorityGrantGeneration: g.grant.grantGeneration, expectedSequence: String(w.sequence), idempotencyKey: `management-F-${op}-W`, labelPayload: op === "delete" ? "" : b64(Buffer.alloc(40, 131)), recoveryEnvelope: "", grants: [], mutations: [] };
        await response(h, "/environment-changes", "POST", { change, signature: b64(ed25519.sign(environmentChangeBytes(change), key("F"))) }, "F");
      }
      const final = await response(h, `/pull?after=0&capability=${capability}`, "GET", undefined, "F"); verifyIssuerRecoveryGraph(final.issuerEvidence);
      assert.ok(final.environmentEvents.some((e: any) => e.change.change.operation === "delete"));
      const safeControl = await control(h, "environment-Z", "F");
      for (const payload of [mutation.mutation.payload, nextMutation.mutation.payload, created.packet.change.labelPayload, change.labelPayload]) assert.equal(JSON.stringify(safeControl).includes(payload), false);
      assert.equal(Object.hasOwn(safeControl, "environments"), false); assert.equal(Object.hasOwn(safeControl, "events"), false);
    } finally { await h.close(); }
  });
  test(`${runtime} 显式P3控制/完整双签receipt不降级，none只历史来源且当前权限变化拒绝`, { timeout: 120000 }, async () => {
    const h = await harness(); try {
      await prepare(h); const created = await createEnvironment(h, "environment-Y", "environment-Z", "E", "none-create-Z");
      const c = await control(h, "environment-Z", "E", true), f = c.subjects.find((s: any) => s.deviceId === "device-F"), grant = signedGrant({ ...created.grant.grant, subjectDeviceId: "device-F", subjectSigningPublicKey: f.signingPublicKey, subjectReceivingPublicKey: f.receivingPublicKey, role: "rw", idempotencyKey: "none-F-Z", envelope: b64(Buffer.alloc(80, 132)) }); await response(h, "/grants", "POST", grant);
      const none = signedGrant({ ...grant.grant, grantGeneration: "2", role: "none", envelope: "", idempotencyKey: "none-revoke-F-Z" }); await response(h, "/grants", "POST", none);
      const management = await control(h, "environment-Z", "E", true); assert.equal(management.subjects.find((s: any) => s.deviceId === "device-F").highestGrantGeneration, "2"); assert.equal(management.issuerEvidence.authorities.some((a: any) => a.grant.grant.role === "none"), false);
      assert.equal((await h.send(`/issuer-evidence?environmentId=environment-Z&capability=issuer-origin-v1`, "GET", undefined, "E")).status, 403);
      assert.equal((await h.send(`/grant-management?environmentId=environment-Z&capability=issuer-origin-v1`, "GET", undefined, "E")).status, 403);
      assert.equal((await h.send(`/issuer-evidence?environmentId=environment-Z&capability=${capability}&capability=issuer-origin-v1`, "GET", undefined, "E")).status, 400);
      const before = management.sequence, bad = structuredClone(created.packet); bad.origin.signature = b64(Buffer.alloc(64, 133));
      assert.equal((await h.send("/environment-changes-v3", "POST", bad, "E")).status, 409); assert.equal((await control(h, "environment-Z", "E", true)).sequence, before);
      const own = signedGrant({ ...created.grant.grant, grantGeneration: "2", role: "ro", idempotencyKey: "none-E-downgrade-Z" }); await response(h, "/grants", "POST", own);
      assert.equal((await h.send(`/issuer-evidence?environmentId=environment-Z&capability=${capability}`, "GET", undefined, "E")).status, 403);
      // 创建Z的权限父环境是Y；Z降权并不撤销仍合法的Y创建权。
      const y = await control(h, "environment-Y"), source = y.grants.find((g: SignedGrant) => g.grant.subjectDeviceId === "device-E") as SignedGrant;
      await response(h, "/grants", "POST", signedGrant({ ...source.grant, grantGeneration: String(BigInt(source.grant.grantGeneration) + 1n), role: "ro", idempotencyKey: "none-E-source-Y-ro" }));
      assert.equal((await h.send("/environment-changes-v3", "POST", created.packet, "E")).status, 403);
      assert.equal((await response(h, "/environment-changes-v3/none-create-Z")).sequence, created.accepted.sequence);
      assert.equal((await response(h, `/grant-status?idempotencyKey=${none.grant.idempotencyKey}`)).accepted, true);
      assert.equal((await h.send(`/issuer-evidence?environmentId=environment-Z&capability=${capability}`, "GET", undefined, "login")).status, 401);
      assert.equal((await h.send("/environment-changes-v3?capability=issuer-recovery-v1", "POST", created.packet, "E")).status, 400);
    } finally { await h.close(); }
  });
}
test("Node新P3管理缺未授权设备归档拒绝且v3写入SQL失败原子回滚，v2原包跨v3只旧序号", async () => {
  const h = await nodeHarness(); try {
    const transition = await completeContinuous(h, false); await completeRecovered(h, transitionHash(transition.packet)); await pairF(h);
    const originalPacket = structuredClone(vector.creation); originalPacket.change.expectedSequence = "11"; originalPacket.origin.origin.expectedSequence = "11"; originalPacket.change.labelPayload = b64(Buffer.alloc(40, 102)); resign(originalPacket);
    const old = await response(h, `/environment-changes-v2/${originalPacket.change.idempotencyKey}`, "GET", undefined, "B"), before = h.read().sequence;
    const replay = await response(h, "/environment-changes-v3", "POST", originalPacket, "B"); assert.equal(replay.sequence, old.sequence); assert.equal(replay.replayed, true); assert.equal(h.read().sequence, before);
    const c = await control(h, "environment-Y"), g = c.grants.find((g: SignedGrant) => g.grant.subjectDeviceId === "device-E"), self = signedGrant({ ...g.grant, environmentId: "environment-Z", keyVersion: "1", grantGeneration: "1", role: "admin", idempotencyKey: "atomic-Z-self" });
    const change: EnvironmentChange = { accountId: h.account.id, accountGeneration: "1", deviceId: "device-E", environmentId: "environment-Z", operation: "create", authorityEnvironmentId: "environment-Y", authorityKeyVersion: "1", authorityGrantGeneration: g.grant.grantGeneration, previousKeyVersion: "0", keyVersion: "1", expectedSequence: String(c.sequence), idempotencyKey: "atomic-Z", labelPayload: b64(Buffer.alloc(40, 134)), recoveryGeneration: "2", recoveryEnvelope: b64(Buffer.alloc(80, 135)), grants: [self], mutations: [] }, p = packet(change, g, []), state = JSON.stringify(h.read()), restore = h.failNextCommit!();
    try { assert.equal((await h.send("/environment-changes-v3", "POST", p, "E")).status, 500); } finally { restore(); }
    assert.equal(JSON.stringify(h.read()), state); assert.deepEqual(await response(h, "/environment-changes-v3/atomic-Z"), { state: "unknown" }); await response(h, "/environment-changes-v3", "POST", p);
    const saved = structuredClone(h.read()); h.change(a => { delete a.deviceEnrollments!["device-F"]; });
    assert.equal((await h.send(`/grant-management?environmentId=environment-Z&capability=${capability}`, "GET", undefined, "E")).status, 403); h.change(a => Object.assign(a, saved));
    assert.equal((await control(h, "environment-Z", "E", true)).subjects.find((s: any) => s.deviceId === "device-F").highestGrantGeneration, "0");
  } finally { await h.close(); }
});
