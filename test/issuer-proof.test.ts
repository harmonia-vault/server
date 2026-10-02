import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { once } from "node:events";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { build } from "esbuild";
import { Miniflare } from "miniflare";
import { nodeStore } from "../src/node-store.js";
import { nodeServer } from "../src/node-runtime.js";
import { VaultService, tokenHash } from "../src/service.js";
import { Fault, grantKey, type Auth, type SignedGrant } from "../src/model.js";
import { canonical, enrollmentFields, hash, pairingContextFields, type EnrollmentAccount, type PairingContext } from "../src/enrollment-wire.js";
import { relayFields } from "../src/enrollment.js";
import { archivedIssuerEnrollment, enrollmentV2Fields, issuerAuthorityHash, issuerProofCanonical, issuerProofHash, verifyIssuerProof, type EnrollmentApprovalV2, type IssuerProof } from "../src/issuer-proof.js";
import { deviceRevocationBytes, environmentChangeBytes, type EnvironmentChange } from "../src/environments.js";
import { grantBytes } from "../src/protocol.js";
import { fixtureAccount } from "./fixtures.js";
const vector = JSON.parse(readFileSync(new URL("./vectors/issuer-proof-v1.json", import.meta.url), "utf8")) as {
  approval: EnrollmentApprovalV2;
  proofHash: string;
  proofCanonicalHex: string;
  certificateSigningHex: string;
  syntheticSigningSeedsHex: Record<string, string>;
};
const b64 = (v: Uint8Array) => Buffer.from(v).toString("base64url");
const seeds = Object.fromEntries(Object.entries(vector.syntheticSigningSeedsHex).map(([k, v]) => [k, Buffer.from(v, "hex")]));
const sign = (fields: unknown, seed: Uint8Array) => b64(ed25519.sign(canonical(fields), seed));
const bad = (f: () => unknown) => assert.throws(f, (e: unknown) => e instanceof Fault);
test("Go v2 固定 16 字段与 proof 摘要完全互操作，祖先证书过期仍仅作为历史来源", () => {
  const c = vector.approval;
  assert.equal(Buffer.from(issuerProofCanonical(c.issuerProof)).toString("hex"), vector.proofCanonicalHex);
  assert.equal(issuerProofHash(c.issuerProof), vector.proofHash);
  assert.equal(Buffer.from(canonical(enrollmentV2Fields(c))).toString("hex"), vector.certificateSigningHex);
  assert.equal(enrollmentV2Fields(c).length, 16);
  assert.equal(verifyIssuerProof(c).size, 2);
});
test("自洽重签外层也不能绕过身份替换、来源图回放、跨环境或跨版本", () => {
  const changes: [
    string,
    (p: IssuerProof) => void
  ][] = [
    ["wrong-generation", p => {
        p.accountGeneration = "2";
      }],
    ["self-admin-B", p => {
        p.authorities[1]!.parentHash = "";
      }],
    ["missing-parent", p => {
        p.authorities[1]!.parentHash = "0".repeat(64);
      }],
    ["cycle", p => {
        p.authorities[0]!.parentHash = issuerAuthorityHash(p.authorities[1]!.grant);
      }],
    ["wrong-target", p => {
        p.targets[0]!.authorityHash = issuerAuthorityHash(p.authorities[0]!.grant);
      }],
    ["wrong-environment", p => {
        p.targets[0]!.environmentId = "other-env";
      }],
    ["wrong-key-version", p => {
        p.authorities[1]!.grant.grant.keyVersion = "2";
        p.authorities[1]!.grant.signature = b64(ed25519.sign(grantBytes(p.authorities[1]!.grant.grant), seeds.A!));
      }],
    ["missing-child-signature", p => {
        p.path[0]!.approval.initiatorSignature = b64(Buffer.alloc(64));
      }],
    ["unknown-field", p => {
        (p as IssuerProof & {
          unknown: boolean;
        }).unknown = true;
      }],
    ["duplicate-authority", p => {
        p.authorities.push(structuredClone(p.authorities[0]!));
      }],
    ["duplicate-target", p => {
        p.targets.push(structuredClone(p.targets[0]!));
      }],
  ];
  for (const [name, change] of changes) {
    const c = structuredClone(vector.approval);
    delete c.initiatorSignature;
    c.issuerProof.authorities.sort((a, b) => a.grant.grant.subjectDeviceId.localeCompare(b.grant.grant.subjectDeviceId));
    change(c.issuerProof);
    bad(() => {
      c.approverSignature = sign(enrollmentV2Fields(c), seeds.B!);
      verifyIssuerProof(c);
    });
    assert.ok(name);
  }
  const c = structuredClone(vector.approval);
  c.issuerProof.path[0]!.certificateVersion = "1";
  c.issuerProof.path[0]!.issuerProofHash = "0".repeat(64);
  bad(() => enrollmentV2Fields(c));
});
interface Harness {
  account: EnrollmentAccount;
  send: (path: string, method: string, body: unknown, who?: string) => Promise<{
    status: number;
    data: any;
  }>;
  read: () => EnrollmentAccount;
  change: (f: (a: EnrollmentAccount) => void) => void;
  close: () => Promise<void>;
  resetGeneration: () => Promise<void>;
  failNextCommit?: () => () => void;
}
const token = (who: string) => b64(Buffer.alloc(32, { login: 61, B: 62, C: 63, D: 64 }[who] ?? 65));
async function accountFixture(): Promise<EnrollmentAccount> {
  const p = vector.approval.issuerProof, a = await fixtureAccount(p.accountId, "chain@example.invalid") as EnrollmentAccount, n = Math.floor(Date.now() / 1000);
  a.devices = {};
  a.grants = {};
  a.sessions = [];
  a.events = [];
  a.sequence = 2;
  a.idempotency = {};
  a.pairingSessions = {};
  a.trustRoot = structuredClone(p.trustRoot);
  a.recoverySigningPublicKey = p.trustRoot.recoverySigningPublicKey;
  a.recoveryReceivingPublicKey = p.trustRoot.recoveryReceivingPublicKey;
  a.environments = { "env-fixture": { id: "env-fixture", keyVersion: "1", recoveryGeneration: "1", recoveryKeyVersion: "1", recoveryEnvelope: p.authorities.find(x => x.parentHash === "")!.grant.grant.envelope } };
  a.grantHistory = p.authorities.map(x => ({ sequence: x.parentHash ? 2 : 1, grant: structuredClone(x.grant), authorization: x.parentHash ? structuredClone(p.authorities.find(y => issuerAuthorityHash(y.grant) === x.parentHash)!.grant) : null }));
  for (const authority of p.authorities) {
    const g = authority.grant.grant;
    a.devices[g.subjectDeviceId] = { id: g.subjectDeviceId, signingPublicKey: g.subjectSigningPublicKey, receivingPublicKey: g.subjectReceivingPublicKey, revoked: false };
    a.grants[grantKey(g.environmentId, g.subjectDeviceId)] = structuredClone(authority.grant);
  }
  a.deviceEnrollments = { "device-B": structuredClone(p.path[0]!.approval) };
  for (const who of ["login", "A", "B", "C"]) {
    a.sessions.push({ tokenHash: await tokenHash(token(who)), generation: "1", kind: "login", expiresAt: n + 3600, ...(who !== "login" ? { deviceId: `device-${who}` } : {}) });
  }
  return a;
}
async function nodeHarness(): Promise<Harness> {
  const dir = mkdtempSync(join(tmpdir(), "harmonia-v2-node-")), db = nodeStore(join(dir, "state.sqlite")), a = await accountFixture();
  db.store.create(a);
  const server = nodeServer(new VaultService(db.store, { allowRegistration: false, requireEmailVerification: true }));
  server.server.listen(0, "127.0.0.1");
  await once(server.server, "listening");
  const base = `http://127.0.0.1:${(server.server.address() as {
    port: number;
  }).port}`;
  return { account: a, send: async (path, method, body, who = "login") => {
      const response = await fetch(`${base}/v1/accounts/${a.id}${path}`, { method, headers: { "content-type": "application/json", authorization: `Bearer ${token(who)}`, "x-harmonia-account-generation": "1", ...(who !== "login" ? { "x-harmonia-device-id": `device-${who}` } : {}) }, ...(method === "GET" ? {} : { body: JSON.stringify(body) }) });
      return { status: response.status, data: await response.json() };
    }, read: () => db.store.read(a.id) as EnrollmentAccount, change: f => db.store.transaction(a.id, x => f(x as EnrollmentAccount)), resetGeneration: async () => {
      db.store.transaction(a.id, x => {
        x.generation = "2";
        x.devices = {};
        x.grants = {};
        x.environments = {};
        x.events = [];
        x.sessions = [];
        x.recoverySigningPublicKey = null;
        x.recoveryReceivingPublicKey = null;
        delete (x as EnrollmentAccount).trustRoot;
      });
    }, failNextCommit: () => {
      const execute = db.sql.execute.bind(db.sql);
      let failed = false;
      db.sql.execute = (query, params) => {
        if (!failed && query.startsWith("UPDATE accounts")) {
          failed = true;
          throw Error("synthetic SQL UPDATE failure");
        }
        execute(query, params);
      };
      return () => {
        db.sql.execute = execute;
      };
    }, close: async () => {
      server.closeNotifications();
      server.server.close();
      await once(server.server, "close");
      db.sql.close();
      rmSync(dir, { recursive: true, force: true });
    } };
}
async function workerHarness(): Promise<Harness> {
  const dir = mkdtempSync(join(tmpdir(), "harmonia-v2-worker-")), a = await accountFixture();
  const built = await build({ entryPoints: ["test/worker-harness.ts"], absWorkingDir: process.cwd(), bundle: true, write: false, format: "esm", platform: "browser", target: "es2023", external: ["cloudflare:workers", "node:*"], banner: { js: 'import { Buffer } from "node:buffer";' } });
  const mf = new Miniflare({ modules: true, script: built.outputFiles[0]!.text, compatibilityDate: "2026-07-30", compatibilityFlags: ["nodejs_compat"], durableObjects: { ACCOUNTS: { className: "SyntheticVault", useSQLite: true }, FIXTURES: { className: "SyntheticVault", useSQLite: true } }, d1Databases: { DIRECTORY: "directory" }, durableObjectsPersist: join(dir, "objects"), d1Persist: join(dir, "directory") });
  await mf.dispatchFetch("https://synthetic.invalid/test/seed", { method: "POST", body: JSON.stringify(a) });
  return { account: a, send: async (path, method, body, who = "login") => {
      const response = await mf.dispatchFetch(`https://synthetic.invalid/v1/accounts/${a.id}${path}`, { method, headers: { "content-type": "application/json", authorization: `Bearer ${token(who)}`, "x-harmonia-account-generation": "1", ...(who !== "login" ? { "x-harmonia-device-id": `device-${who}` } : {}) }, ...(method === "GET" ? {} : { body: JSON.stringify(body) }) });
      return { status: response.status, data: await response.json() };
    }, read: () => a, change: () => {
      throw Error("worker fixture changes must use public signed routes");
    }, resetGeneration: async () => {
      assert.equal((await mf.dispatchFetch(`https://synthetic.invalid/test/reset-generation/${a.id}`, { method: "POST" })).status, 200);
    }, close: async () => {
      await mf.dispose();
      rmSync(dir, { recursive: true, force: true });
    } };
}
async function ready(h: Harness, device = "C", approver = "B"): Promise<{
  record: any;
  certificate: EnrollmentApprovalV2;
  key: string;
}> {
  const key = `pairing-v2-${device}`, seed = device === "C" ? seeds.C! : Buffer.alloc(32, 7), recv = device === "C" ? vector.approval.context.initiatorReceivingPublicKey : b64(x25519.getPublicKey(Buffer.alloc(32, 17)));
  const started = await h.send("/pairings-v2", "POST", { idempotencyKey: key, deviceId: `device-${device}`, signingPublicKey: b64(ed25519.getPublicKey(seed)), receivingPublicKey: recv, approverDeviceId: `device-${approver}`, certificateVersion: "2", capabilities: ["issuer-proof-v1"] });
  assert.equal(started.status, 200, JSON.stringify(started.data));
  assert.equal(started.data.certificateVersion, "2");
  const context = started.data.context as PairingContext;
  const maker = approver === "B" ? seeds.B! : seeds.C!;
  for (const [side, kind, value, keys, who] of [["initiator", "message", 71, seed, "login"], ["approver", "message", 72, maker, approver], ["initiator", "confirmation", 73, seed, "login"], ["approver", "confirmation", 74, maker, approver]] as const) {
    const relay = { side, kind, payload: b64(Buffer.alloc(32, value)) };
    const sent = await h.send(`/pairings-v2/${key}/relay`, "POST", { ...relay, signature: sign(relayFields({ context } as any, relay), keys) }, who);
    assert.equal(sent.status, 200, JSON.stringify(sent.data));
  }
  const status = await h.send(`/pairings-v2/${key}`, "GET", undefined);
  const transcript = hash(["harmonia/pairing-transcript/v1", b64(canonical(pairingContextFields(context))), status.data.messages.initiator, status.data.messages.approver]);
  const g = structuredClone(vector.approval.grants[0]!.grant);
  Object.assign(g, { issuerDeviceId: `device-${approver}`, subjectDeviceId: `device-${device}`, subjectSigningPublicKey: context.initiatorSigningPublicKey, subjectReceivingPublicKey: recv, role: "admin", expiresAt: "0", idempotencyKey: `grant-${device}` });
  const certificate: EnrollmentApprovalV2 = { certificateVersion: "2", context, pairingProfile: vector.approval.pairingProfile, transcriptHash: transcript, grants: [{ grant: g, signature: b64(ed25519.sign(grantBytes(g), maker)) }], issuerProof: structuredClone(vector.approval.issuerProof), approverSignature: "" };
  return { record: status.data, certificate, key };
}
function approval(c: EnrollmentApprovalV2, seed = seeds.B!): unknown {
  c.approverSignature = sign(enrollmentV2Fields(c), seed);
  return { certificateVersion: "2", capabilities: ["issuer-proof-v1"], grants: c.grants, transcriptHash: c.transcriptHash, issuerProof: c.issuerProof, signature: c.approverSignature };
}
for (const [runtime, create] of [["Node TCP", nodeHarness], ["workerd HTTP", workerHarness]] as const) {
  test(`${runtime} 明确协商 v2、历史归档与当前 Admin 双重验证，v1 降级拒绝`, { timeout: 120000 }, async () => {
    const h = await create();
    try {
      const { certificate: c, key } = await ready(h);
      const old = await h.send("/pairings", "POST", { idempotencyKey: "downgrade", deviceId: "device-C", signingPublicKey: c.context.initiatorSigningPublicKey, receivingPublicKey: c.context.initiatorReceivingPublicKey, approverDeviceId: "device-B" });
      assert.equal(old.status, 403);
      assert.equal(old.data.error, "issuer_proof_capability_required");
      const unknown = await h.send("/pairings", "POST", { idempotencyKey: "unknown-v1-fields", deviceId: "device-C", signingPublicKey: c.context.initiatorSigningPublicKey, receivingPublicKey: c.context.initiatorReceivingPublicKey, approverDeviceId: "device-B", certificateVersion: "2", capabilities: ["issuer-proof-v1"] });
      assert.equal(unknown.status, 400);
      const wrong = await h.send(`/pairings/${key}`, "GET", undefined);
      assert.equal(wrong.status, 404);
      const input = approval(c);
      for (const malformed of [{ ...(input as object), issuerProof: null }, { ...(input as object), grants: [null] }]) {
        const invalid = await h.send(`/pairings-v2/${key}/approve`, "POST", malformed, "B");
        assert.equal(invalid.status, 400, JSON.stringify(invalid.data));
        assert.equal((await h.send(`/pairings-v2/${key}`, "GET", undefined)).data.approval, null);
      }
      const noCap = await h.send(`/pairings-v2/${key}/approve`, "POST", { ...(input as object), capabilities: [] }, "B");
      assert.equal(noCap.status, 400);
      const accepted = await h.send(`/pairings-v2/${key}/approve`, "POST", input, "B");
      assert.equal(accepted.status, 200, JSON.stringify(accepted.data));
      assert.equal(accepted.data.approval.certificateVersion, "2");
      const finish = await h.send(`/pairings-v2/${key}/complete`, "POST", { signature: sign(enrollmentV2Fields(c), seeds.C!) });
      assert.equal(finish.status, 200, JSON.stringify(finish.data));
      assert.equal(finish.data.sequence, 3);
      const retry = await h.send(`/pairings-v2/${key}/complete`, "POST", { signature: sign(enrollmentV2Fields(c), seeds.C!) });
      assert.equal(retry.status, 200);
      assert.equal(retry.data.replayed, true);
      const beginRetry = await h.send("/pairings-v2", "POST", { idempotencyKey: key, deviceId: "device-C", signingPublicKey: c.context.initiatorSigningPublicKey, receivingPublicKey: c.context.initiatorReceivingPublicKey, approverDeviceId: "device-B", certificateVersion: "2", capabilities: ["issuer-proof-v1"] });
      assert.equal(beginRetry.status, 200);
      assert.equal(beginRetry.data.state, "complete");
    }
    finally {
      await h.close();
    }
  });
  test(`${runtime} 批准后撤销或更改精确 Admin authority，完成拒绝且事务无新增设备`, { timeout: 120000 }, async () => {
    const h = await create();
    try {
      const { certificate: c, key } = await ready(h);
      assert.equal((await h.send(`/pairings-v2/${key}/approve`, "POST", approval(c), "B")).status, 200);
      const current = structuredClone(h.account.grants[grantKey("env-fixture", "device-B")]!.grant);
      Object.assign(current, { grantGeneration: "2", idempotencyKey: "downgrade-after-approval", role: "ro" });
      const signed = { grant: current, signature: b64(ed25519.sign(grantBytes(current), seeds.A!)) };
      // Public signed grant update uses a fixture root-bound session available in both adapters.
      const response = await h.send("/grants", "POST", signed, "A");
      assert.equal(response.status, 200, JSON.stringify(response.data));
      const completed = await h.send(`/pairings-v2/${key}/complete`, "POST", { signature: sign(enrollmentV2Fields(c), seeds.C!) });
      assert.equal(completed.status, 403);
      assert.equal(completed.data.error, "admin_required");
      const status = await h.send(`/pairings-v2/${key}`, "GET", undefined);
      assert.equal(status.data.state, "approved");
      assert.equal(status.data.sequence, null);
      assert.equal((await h.send("/device-challenges", "POST", {}, "C")).status, 403);
    }
    finally {
      await h.close();
    }
  });
  test(`${runtime} 完成的 v2 归档可继续形成 A→B→C→D，历史证明不恢复当前权限`, { timeout: 120000 }, async () => {
    const h = await create();
    try {
      const first = await ready(h), c = first.certificate;
      assert.equal((await h.send(`/pairings-v2/${first.key}/approve`, "POST", approval(c), "B")).status, 200);
      c.initiatorSignature = sign(enrollmentV2Fields(c), seeds.C!);
      const completed = await h.send(`/pairings-v2/${first.key}/complete`, "POST", { signature: c.initiatorSignature });
      assert.equal(completed.status, 200, JSON.stringify(completed.data));
      const second = await ready(h, "D", "C"), d = second.certificate;
      d.issuerProof.path.push(archivedIssuerEnrollment(c));
      const parent = issuerAuthorityHash(d.issuerProof.authorities.find(a => a.grant.grant.subjectDeviceId === "device-B")!.grant);
      d.issuerProof.authorities.push({ grant: structuredClone(c.grants[0]!), parentHash: parent });
      d.issuerProof.targets = [{ environmentId: "env-fixture", authorityHash: issuerAuthorityHash(c.grants[0]!) }];
      const approved = await h.send(`/pairings-v2/${second.key}/approve`, "POST", approval(d, seeds.C!), "C");
      assert.equal(approved.status, 200, JSON.stringify(approved.data));
      d.initiatorSignature = sign(enrollmentV2Fields(d), Buffer.alloc(32, 7));
      const done = await h.send(`/pairings-v2/${second.key}/complete`, "POST", { signature: d.initiatorSignature });
      assert.equal(done.status, 200, JSON.stringify(done.data));
      assert.equal(done.data.sequence, 4);
      assert.equal(done.data.approval.issuerProof.path[1].certificateVersion, "2");
      assert.equal(verifyIssuerProof(done.data.approval).size, 3);
      if (runtime === "Node TCP") {
        const a = h.read();
        assert.equal((a.deviceEnrollments!["device-D"] as EnrollmentApprovalV2).issuerProof.path.length, 2);
        assert.equal(a.grantHistory!.at(-1)!.authorization!.grant.subjectDeviceId, "device-C");
      }
    }
    finally {
      await h.close();
    }
  });
  test(`${runtime} 当前 Admin 内容变化即使角色仍是 Admin，也不能完成旧审批`, { timeout: 120000 }, async () => {
    const h = await create();
    try {
      const { certificate: c, key } = await ready(h);
      assert.equal((await h.send(`/pairings-v2/${key}/approve`, "POST", approval(c), "B")).status, 200);
      const g = structuredClone(h.account.grants[grantKey("env-fixture", "device-B")]!.grant);
      Object.assign(g, { grantGeneration: "2", idempotencyKey: "replace-current-admin" });
      const changed = await h.send("/grants", "POST", { grant: g, signature: b64(ed25519.sign(grantBytes(g), seeds.A!)) }, "A");
      assert.equal(changed.status, 200, JSON.stringify(changed.data));
      const result = await h.send(`/pairings-v2/${key}/complete`, "POST", { signature: sign(enrollmentV2Fields(c), seeds.C!) });
      assert.equal(result.status, 403);
      assert.equal(result.data.error, "issuer_authority_changed");
      const status = await h.send(`/pairings-v2/${key}`, "GET", undefined);
      assert.equal(status.data.sequence, null);
      assert.equal(status.data.state, "approved");
      assert.equal((await h.send("/device-challenges", "POST", {}, "C")).data.error, "device_untrusted");
    }
    finally {
      await h.close();
    }
  });
  test(`${runtime} 新环境或跨版本缺签名生命周期来源，目录/自签 Admin 不能补权`, { timeout: 120000 }, async () => {
    const h = await create();
    try {
      const { certificate: c, key } = await ready(h);
      // 任意 root 新自签 grant 虽然图在密码学上自洽，仍没有初始化历史来源。
      const g = structuredClone(c.issuerProof.authorities.find(a => a.parentHash === "")!.grant.grant);
      g.idempotencyKey = "invented-root-authority";
      g.grantGeneration = "2";
      const root = { grant: g, signature: b64(ed25519.sign(grantBytes(g), seeds.A!)) };
      const rootHash = issuerAuthorityHash(root);
      c.issuerProof.authorities.push({ grant: root, parentHash: "" });
      const rejected = await h.send(`/pairings-v2/${key}/approve`, "POST", approval(c), "B");
      assert.equal(rejected.status, 403);
      assert.equal(rejected.data.error, "issuer_authority_unaccepted");
      assert.equal((await h.send(`/pairings-v2/${key}`, "GET", undefined)).data.approval, null);
      const original = structuredClone(vector.approval.issuerProof);
      c.issuerProof = original;
      c.issuerProof.path[0]!.approval.context.sessionId = "unaccepted-historical-session";
      const node = c.issuerProof.path[0]!;
      node.approval.approverSignature = sign(enrollmentFields(node.approval), seeds.A!);
      node.approval.initiatorSignature = sign(enrollmentFields(node.approval), seeds.B!);
      const archive = await h.send(`/pairings-v2/${key}/approve`, "POST", approval(c), "B");
      assert.equal(archive.status, 403);
      assert.equal(archive.data.error, "issuer_archive_mismatch");
      assert.equal((await h.send(`/pairings-v2/${key}`, "GET", undefined)).data.approval, null);
      assert.ok(rootHash);
    }
    finally {
      await h.close();
    }
  });
  test(`${runtime} 批准后全局撤销管理设备，已签历史仍不能完成入网`, { timeout: 120000 }, async () => {
    const h = await create();
    try {
      const { certificate: c, key } = await ready(h);
      assert.equal((await h.send(`/pairings-v2/${key}/approve`, "POST", approval(c), "B")).status, 200);
      const challenge = await h.send("/device-revocations", "POST", { subjectDeviceId: "device-B", idempotencyKey: "revoke-manager-B" }, "A");
      assert.equal(challenge.status, 200, JSON.stringify(challenge.data));
      const revoked = await h.send("/device-revocations/complete", "POST", { revocation: challenge.data, signature: b64(ed25519.sign(deviceRevocationBytes(challenge.data), seeds.A!)) }, "A");
      assert.equal(revoked.status, 200, JSON.stringify(revoked.data));
      const result = await h.send(`/pairings-v2/${key}/complete`, "POST", { signature: sign(enrollmentV2Fields(c), seeds.C!) });
      assert.equal(result.status, 403);
      assert.equal(result.data.error, "device_untrusted");
      assert.equal((await h.send(`/pairings-v2/${key}`, "GET", undefined)).data.sequence, null);
      assert.equal((await h.send(`/pairings-v2/${key}`, "GET", undefined, "B")).status, 401);
    }
    finally {
      await h.close();
    }
  });
  test(`${runtime} 当前授权期限到达后拒绝旧审批，账号代际变化也使请求失效`, { timeout: 120000 }, async () => {
    const h = await create();
    try {
      const { certificate: c, key } = await ready(h);
      assert.equal((await h.send(`/pairings-v2/${key}/approve`, "POST", approval(c), "B")).status, 200);
      const g = structuredClone(h.account.grants[grantKey("env-fixture", "device-B")]!.grant), deadline = Math.floor(Date.now() / 1000) + 1;
      Object.assign(g, { grantGeneration: "2", idempotencyKey: "expiring-admin", expiresAt: String(deadline) });
      const changed = await h.send("/grants", "POST", { grant: g, signature: b64(ed25519.sign(grantBytes(g), seeds.A!)) }, "A");
      assert.equal(changed.status, 200, JSON.stringify(changed.data));
      await new Promise(resolve => setTimeout(resolve, Math.max(1, deadline * 1000 - Date.now() + 20)));
      const result = await h.send(`/pairings-v2/${key}/complete`, "POST", { signature: sign(enrollmentV2Fields(c), seeds.C!) });
      assert.equal(result.status, 403);
      assert.equal(result.data.error, "environment_forbidden");
      await h.resetGeneration();
      const reset = await h.send(`/pairings-v2/${key}/complete`, "POST", { signature: sign(enrollmentV2Fields(c), seeds.C!) });
      assert.equal(reset.status, 401);
      assert.equal(reset.data.error, "generation_stale");
    }
    finally {
      await h.close();
    }
  });
  test(`${runtime} 真实新环境 Admin 已获授权，缺生命周期扩展证明仍拒绝 v2 扩权`, { timeout: 120000 }, async () => {
    const h = await create();
    try {
      const { certificate: c, key } = await ready(h);
      const existing = c.issuerProof.authorities.find(a => a.parentHash === "")!.grant;
      const rootGrant = structuredClone(existing.grant);
      Object.assign(rootGrant, { environmentId: "env-new", idempotencyKey: "new-environment-root" });
      const signedRoot = { grant: rootGrant, signature: b64(ed25519.sign(grantBytes(rootGrant), seeds.A!)) };
      const change: EnvironmentChange = { accountId: h.account.id, accountGeneration: "1", deviceId: "device-A", environmentId: "env-new", operation: "create",
        authorityEnvironmentId: "env-fixture", authorityKeyVersion: "1", authorityGrantGeneration: "1", previousKeyVersion: "0", keyVersion: "1", expectedSequence: "2", idempotencyKey: "create-new-environment",
        labelPayload: b64(Buffer.alloc(40, 80)), recoveryGeneration: "1", recoveryEnvelope: b64(Buffer.alloc(80, 81)), grants: [signedRoot], mutations: [] };
      const created = await h.send("/environment-changes", "POST", { change, signature: b64(ed25519.sign(environmentChangeBytes(change), seeds.A!)) }, "A");
      assert.equal(created.status, 200, JSON.stringify(created.data));
      const grantB = structuredClone(h.account.grants[grantKey("env-fixture", "device-B")]!.grant);
      Object.assign(grantB, { environmentId: "env-new", idempotencyKey: "new-environment-B" });
      const signedB = { grant: grantB, signature: b64(ed25519.sign(grantBytes(grantB), seeds.A!)) };
      assert.equal((await h.send("/grants", "POST", signedB, "A")).status, 200);
      const inherited = c.grants[0]!.grant;
      Object.assign(inherited, { environmentId: "env-new", idempotencyKey: "new-environment-C" });
      c.grants[0]!.signature = b64(ed25519.sign(grantBytes(inherited), seeds.B!));
      c.issuerProof.authorities.push({ grant: signedRoot, parentHash: "" }, { grant: signedB, parentHash: issuerAuthorityHash(signedRoot) });
      c.issuerProof.targets = [{ environmentId: "env-new", authorityHash: issuerAuthorityHash(signedB) }];
      const result = await h.send(`/pairings-v2/${key}/approve`, "POST", approval(c), "B");
      assert.equal(result.status, 403, JSON.stringify(result.data));
      assert.equal(result.data.error, "issuer_environment_evidence_required");
      assert.equal((await h.send(`/pairings-v2/${key}`, "GET", undefined)).data.approval, null);
      const tooLarge = await h.send(`/pairings-v2/${key}/approve`, "POST", { padding: "x".repeat(262144) }, "B");
      assert.equal(tooLarge.status, 413);
    }
    finally {
      await h.close();
    }
  });
}
test("Node SQLite 完成时真实 UPDATE 失败，设备/授权/归档/序号全部回滚并可安全重试", async () => {
  const h = await nodeHarness();
  try {
    const { certificate: c, key } = await ready(h);
    assert.equal((await h.send(`/pairings-v2/${key}/approve`, "POST", approval(c), "B")).status, 200);
    const before = JSON.stringify(h.read()), signature = sign(enrollmentV2Fields(c), seeds.C!);
    const restore = h.failNextCommit!();
    try {
      assert.equal((await h.send(`/pairings-v2/${key}/complete`, "POST", { signature })).status, 500);
    }
    finally {
      restore();
    }
    assert.equal(JSON.stringify(h.read()), before);
    assert.equal(Object.hasOwn(h.read().devices, "device-C"), false);
    const result = await h.send(`/pairings-v2/${key}/complete`, "POST", { signature });
    assert.equal(result.status, 200, JSON.stringify(result.data));
    assert.equal(result.data.sequence, 3);
  }
  finally {
    await h.close();
  }
});
