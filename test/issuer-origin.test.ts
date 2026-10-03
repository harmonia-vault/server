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
import { Fault, grantKey, type SignedGrant } from "../src/model.js";
import { canonical, hash, pairingContextFields, type EnrollmentAccount, type InitializationProposal, type PairingContext } from "../src/enrollment-wire.js";
import { EnrollmentService, relayFields } from "../src/enrollment.js";
import { issuerAuthorityHash } from "../src/issuer-proof.js";
import { environmentChangeBytes, environmentSubmissionContent, type SignedEnvironmentChangeV2 } from "../src/environments.js";
import { environmentChangeHash, environmentOriginBytes, environmentOriginHash, environmentRights, type EnvironmentOrigin } from "../src/environment-origin.js";
import { archivedOriginEnrollment, enrollmentV3Fields, issuerOriginCanonical, issuerOriginProofHash, verifyIssuerOriginProof, verifyIssuerOriginGraph, type EnrollmentApprovalV3, type IssuerOriginProof } from "../src/issuer-origin.js";
import { grantBytes, mutationBytes } from "../src/protocol.js";
import { fixtureAccount, recoveryKeys } from "./fixtures.js";
import { trustRootPayload } from "../src/trust-root.js";
const vector = JSON.parse(readFileSync(new URL("./vectors/environment-origin-v1.json", import.meta.url), "utf8")) as {
  approval: EnrollmentApprovalV3; rotation: SignedEnvironmentChangeV2; creation: SignedEnvironmentChangeV2;
  rotationSigningHex: string; creationSigningHex: string; rotationHash: string; proofHash: string; proofCanonicalHex: string;
  certificateSigningHex: string; syntheticSigningSeedsHex: Record<string, string>;
};
const b64 = (value: Uint8Array): string => Buffer.from(value).toString("base64url");
const seeds = Object.fromEntries(Object.entries(vector.syntheticSigningSeedsHex).map(([key,value]) => [key,Buffer.from(value,"hex")]));
const sign = (fields: unknown, seed: Uint8Array): string => b64(ed25519.sign(canonical(fields), seed));
function resign(packet: SignedEnvironmentChangeV2): void {
  packet.signature = b64(ed25519.sign(environmentChangeBytes(packet.change), seeds.B!));
  packet.origin.origin.changeHash = environmentChangeHash(environmentChangeBytes(packet.change), packet.signature);
  packet.origin.signature = b64(ed25519.sign(environmentOriginBytes(packet.origin.origin), seeds.B!));
}
interface Harness {
  account: EnrollmentAccount;
  send: (path: string, method: string, body: unknown, who?: string) => Promise<{
    status: number;
    data: any;
  }>;
  read: () => EnrollmentAccount;
  setToken: (who: string, value: string) => void;
  change: (f: (a: EnrollmentAccount) => void) => void;
  close: () => Promise<void>;
  resetGeneration: () => Promise<void>;
  failNextCommit?: () => () => void;
}
const token = (who: string) => b64(Buffer.alloc(32, { login: 61, B: 62, C: 63, D: 64 }[who] ?? 65));
async function accountFixture(includeReader = false, withOriginal = true): Promise<EnrollmentAccount> {
  const p = structuredClone(vector.approval.issuerProof); p.authorities = p.authorities.filter(node => !node.originHash && (includeReader || node.grant.grant.subjectDeviceId !== "device-C"));
  let a = await fixtureAccount(p.accountId, "chain@example.invalid") as EnrollmentAccount;
  const n = Math.floor(Date.now() / 1000);
  if (withOriginal) {
    // 声明在公开向量中的原始输入，先通过正式初始化双签事务接受；
    // 不能从当前 selfGrant 或后来的历史倒推、补造原初始化记录。
    const rootGrant = p.authorities.find(node => !node.parentHash)!.grant;
    const recovery = recoveryKeys(Buffer.alloc(32, 88), a.id), root = { ...p.trustRoot, recoverySigningPublicKey: recovery.signingPublicKey, recoveryReceivingPublicKey: recovery.receivingPublicKey, signature: "" };
    root.signature = sign(trustRootPayload(a.id, "1", root), recovery.signingSeed);
    const proposal: InitializationProposal = { idempotencyKey: "original-chain-initialization", device: { id: root.rootDeviceId, signingPublicKey: root.rootSigningPublicKey, receivingPublicKey: root.rootReceivingPublicKey }, recoveryGeneration: "1", recoverySigningPublicKey: recovery.signingPublicKey, recoveryReceivingPublicKey: recovery.receivingPublicKey, trustRootSignature: root.signature, environments: [{ environmentId: rootGrant.grant.environmentId, keyVersion: "1", recoveryEnvelope: b64(Buffer.alloc(80, 88)), grant: structuredClone(rootGrant) }] };
    a.devices = {}; a.environments = {}; a.grants = {}; a.grantHistory = []; a.events = []; a.sequence = 0; a.recoverySigningPublicKey = null; a.recoveryReceivingPublicKey = null;
    a.sessions = [{ tokenHash: await tokenHash(token("login")), generation: "1", kind: "login", expiresAt: n + 3600 }];
    const db = nodeStore(":memory:");
    try {
      db.store.create(a);
      const enrollment = new EnrollmentService(db.store), auth = { token: token("login"), accountGeneration: "1" };
      const challenge = await enrollment.initialize(a.id, auth, proposal);
      await enrollment.completeInitialization(a.id, auth, proposal.idempotencyKey, challenge.challengeId as string, sign(challenge.signingPayload, seeds.A!), sign(challenge.signingPayload, recovery.signingSeed));
      a = db.store.read(a.id)! as EnrollmentAccount;
      p.trustRoot = structuredClone(a.trustRoot!);
    } finally { db.sql.close(); }
  }
  a.devices = {};
  a.grants = {};
  a.sessions = [];
  a.events = [];
  a.sequence = 10;
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
  a.deviceEnrollments = { "device-B": structuredClone(p.path[0]!.approval), ...(includeReader ? { "device-C": structuredClone(p.identityPaths[0]![0]!.approval) } : {}) };
  for (const who of ["login", "A", "B", "C"]) {
    a.sessions.push({ tokenHash: await tokenHash(token(who)), generation: "1", kind: "login", expiresAt: n + 3600, ...(who !== "login" ? { deviceId: `device-${who}` } : {}) });
  }
  return a;
}
async function nodeHarness(includeReader = false, withOriginal = true): Promise<Harness> {
  const dir = mkdtempSync(join(tmpdir(), "harmonia-v2-node-")), db = nodeStore(join(dir, "state.sqlite")), a = await accountFixture(includeReader, withOriginal);
  db.store.create(a);
  const server = nodeServer(new VaultService(db.store, { allowRegistration: false, requireEmailVerification: true }));
  server.server.listen(0, "127.0.0.1");
  await once(server.server, "listening");
  const sessionTokens = new Map<string, string>();
  const base = `http://127.0.0.1:${(server.server.address() as {
    port: number;
  }).port}`;
  return { account: a, setToken: (who, value) => { sessionTokens.set(who, value); }, send: async (path, method, body, who = "login") => {
      const response = await fetch(`${base}/v1/accounts/${a.id}${path}`, { method, headers: { "content-type": "application/json", authorization: `Bearer ${sessionTokens.get(who) ?? token(who)}`, "x-harmonia-account-generation": "1", ...(who !== "login" ? { "x-harmonia-device-id": `device-${who}` } : {}) }, ...(method === "GET" ? {} : { body: JSON.stringify(body) }) });
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
async function workerHarness(includeReader = false, withOriginal = true): Promise<Harness> {
  const dir = mkdtempSync(join(tmpdir(), "harmonia-v2-worker-")), a = await accountFixture(includeReader, withOriginal);
  const built = await build({ entryPoints: ["test/worker-harness.ts"], absWorkingDir: process.cwd(), bundle: true, write: false, format: "esm", platform: "browser", target: "es2023", external: ["cloudflare:workers", "node:*"], banner: { js: 'import { Buffer } from "node:buffer";' } });
  const mf = new Miniflare({ modules: true, script: built.outputFiles[0]!.text, compatibilityDate: "2026-07-30", compatibilityFlags: ["nodejs_compat"], durableObjects: { INSTANCES: { className: "InstanceRegistry", useSQLite: true }, ACCOUNTS: { className: "SyntheticVault", useSQLite: true }, FIXTURES: { className: "SyntheticVault", useSQLite: true } }, d1Databases: { DIRECTORY: "directory" }, durableObjectsPersist: join(dir, "objects"), d1Persist: join(dir, "directory") });
  await mf.dispatchFetch("https://synthetic.invalid/test/seed", { method: "POST", body: JSON.stringify(a) });
  const sessionTokens = new Map<string, string>();
  return { account: a, setToken: (who, value) => { sessionTokens.set(who, value); }, send: async (path, method, body, who = "login") => {
      const response = await mf.dispatchFetch(`https://synthetic.invalid/v1/accounts/${a.id}${path}`, { method, headers: { "content-type": "application/json", authorization: `Bearer ${sessionTokens.get(who) ?? token(who)}`, "x-harmonia-account-generation": "1", ...(who !== "login" ? { "x-harmonia-device-id": `device-${who}` } : {}) }, ...(method === "GET" ? {} : { body: JSON.stringify(body) }) });
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

test("Go origin17项、proof9项和cert3固定16项跨语言编码与Ed签名一致", () => {
  assert.equal(Buffer.from(environmentOriginBytes(vector.rotation.origin.origin)).toString("hex"), vector.rotationSigningHex);
  assert.equal(Buffer.from(environmentOriginBytes(vector.creation.origin.origin)).toString("hex"), vector.creationSigningHex);
  assert.equal(environmentOriginHash(vector.rotation.origin), vector.rotationHash);
  assert.equal(Buffer.from(issuerOriginCanonical(vector.approval.issuerProof)).toString("hex"), vector.proofCanonicalHex);
  assert.equal(issuerOriginProofHash(vector.approval.issuerProof), vector.proofHash);
  assert.equal(Buffer.from(canonical(enrollmentV3Fields(vector.approval))).toString("hex"), vector.certificateSigningHex);
  assert.equal(verifyIssuerOriginProof(vector.approval).origins.size, 2);
});
test("重新签外层仍拒绝缺旧recipient父边、源Admin跨环境、自签新根和循环", () => {
  const changes: ((proof: IssuerOriginProof) => void)[] = [
    proof => { proof.authorities.find(node => node.previousGrantHash && node.grant.grant.subjectDeviceId === "device-A")!.previousGrantHash = ""; },
    proof => { proof.authorities.find(node => node.originHash)!.parentHash = issuerAuthorityHash(proof.authorities.find(node => !node.parentHash)!.grant); },
    proof => { proof.authorities.find(node => node.originHash)!.originHash = ""; },
    proof => { proof.origins = []; },
    proof => { proof.authorities.find(node => !node.parentHash)!.parentHash = issuerAuthorityHash(proof.authorities.find(node => node.originHash)!.grant); },
    proof => { proof.identityPaths.push(structuredClone(proof.path), structuredClone(proof.path)); },
    proof => { const row = proof.origins.find(origin => origin.origin.operation === "rotate")!.origin.before.find(row => row.role === "ro")!; proof.authorities = proof.authorities.filter(node => issuerAuthorityHash(node.grant) !== row.grantHash); },
    proof => { const row = proof.origins.find(origin => origin.origin.operation === "rotate")!.origin.after.find(row => row.subjectDeviceId === "device-A")!; proof.authorities = proof.authorities.filter(node => issuerAuthorityHash(node.grant) !== row.grantHash); },
    proof => { proof.origins[0]!.origin.before[0]!.expiresAt = "2030000500"; proof.origins[0]!.signature = b64(ed25519.sign(environmentOriginBytes(proof.origins[0]!.origin), seeds.B!)); },
  ];
  for (const change of changes) {
    const c = structuredClone(vector.approval); delete c.initiatorSignature;
    assert.throws(() => { change(c.issuerProof); c.approverSignature = sign(enrollmentV3Fields(c), seeds.B!); verifyIssuerOriginProof(c); }, (error: unknown) => error instanceof Fault);
  }
});
async function prepare(h: Harness, proof: IssuerOriginProof, target: SignedGrant, child = "C", approver = "B"): Promise<{ c: EnrollmentApprovalV3; key: string; input: unknown; childSeed: Uint8Array }> {
  const childSeed = child === "C" ? seeds.C! : Buffer.alloc(32, 7), receiver = child === "C" ? b64(x25519.getPublicKey(Buffer.alloc(32,13))) : b64(x25519.getPublicKey(Buffer.alloc(32,17)));
  const maker = seeds[approver]!, key = `pairing-v3-${child}`;
  const response = await h.send("/pairings-v3","POST",{idempotencyKey:key,deviceId:`device-${child}`,signingPublicKey:b64(ed25519.getPublicKey(childSeed)),receivingPublicKey:receiver,approverDeviceId:`device-${approver}`,certificateVersion:"3",capabilities:["issuer-origin-v1"]});
  assert.equal(response.status,200,JSON.stringify(response.data));
  assert.equal(response.data.certificateVersion,"3");
  const context = response.data.context as PairingContext;
  for (const [side, kind, value, seed, who] of [["initiator","message",71,childSeed,"login"],["approver","message",72,maker,approver],["initiator","confirmation",73,childSeed,"login"],["approver","confirmation",74,maker,approver]] as const) {
    const relay = {side,kind,payload:b64(Buffer.alloc(32,value))};
    const sent = await h.send(`/pairings-v3/${key}/relay`,"POST",{...relay,signature:sign(relayFields({context} as any,relay),seed)},who);
    assert.equal(sent.status,200,JSON.stringify(sent.data));
  }
  const status = await h.send(`/pairings-v3/${key}`,"GET",undefined);
  const g = structuredClone(target.grant);
  Object.assign(g,{issuerDeviceId:`device-${approver}`,subjectDeviceId:`device-${child}`,subjectSigningPublicKey:context.initiatorSigningPublicKey,subjectReceivingPublicKey:receiver,grantGeneration:"1",role:"admin",idempotencyKey:`grant-${child}-v3`});
  const c: EnrollmentApprovalV3 = {certificateVersion:"3",context,pairingProfile:vector.approval.pairingProfile,transcriptHash:hash(["harmonia/pairing-transcript/v1",b64(canonical(pairingContextFields(context))),status.data.messages.initiator,status.data.messages.approver]),grants:[{grant:g,signature:b64(ed25519.sign(grantBytes(g),maker))}],issuerProof:structuredClone(proof),approverSignature:""};
  c.issuerProof.targets=[{environmentId:g.environmentId,authorityHash:issuerAuthorityHash(target)}];
  c.approverSignature=sign(enrollmentV3Fields(c),maker);
  const input={certificateVersion:"3",capabilities:["issuer-origin-v1"],grants:c.grants,transcriptHash:c.transcriptHash,issuerProof:c.issuerProof,signature:c.approverSignature};
  return {c,key,input,childSeed};
}
function creation(): SignedEnvironmentChangeV2 {
  const packet=structuredClone(vector.creation);packet.change.expectedSequence="10";packet.origin.origin.expectedSequence="10";resign(packet);return packet;
}
for (const [runtime,create] of [["Node TCP",nodeHarness],["workerd HTTP",workerHarness]] as const) {
  test(`${runtime} B创建Y→批准C→归档C继续批准D，控制闭包不泄X数据`,{timeout:120000},async()=>{
    const h=await create();try {
      const packet=creation();
      assert.equal((await h.send("/environment-changes-v2","POST",packet,"B")).status,200);
      const proofResponse=await h.send("/pull?after=11&capability=issuer-origin-v1","GET",undefined,"B");
      assert.equal(proofResponse.status,200,JSON.stringify(proofResponse.data));
      const proof=proofResponse.data.issuerEvidence as IssuerOriginProof;
      assert.equal(proof.origins.length,1);assert.equal(proofResponse.data.environmentEvents.length,0);
      const first=await prepare(h,proof,packet.change.grants[0]!);
      assert.equal((await h.send(`/pairings-v2/${first.key}`,"GET",undefined)).status,404);
      const downgraded=await h.send(`/pairings-v3/${first.key}/approve`,"POST",{...(first.input as object),certificateVersion:"2",capabilities:["issuer-proof-v1"]},"B");assert.equal(downgraded.status,400);
      const approved=await h.send(`/pairings-v3/${first.key}/approve`,"POST",first.input,"B");assert.equal(approved.status,200,JSON.stringify(approved.data));
      first.c.initiatorSignature=sign(enrollmentV3Fields(first.c),first.childSeed);
      const complete=await h.send(`/pairings-v3/${first.key}/complete`,"POST",{signature:first.c.initiatorSignature});assert.equal(complete.status,200,JSON.stringify(complete.data));assert.equal(complete.data.sequence,12);
      assert.equal((await h.send(`/pairings-v3/${first.key}/complete`,"POST",{signature:first.c.initiatorSignature})).data.replayed,true);
      // 只有Y授权的C永远不能拿到X的标签、变量名或数据包。给X写入独特合成标记。
      const rootGrant=h.account.grants[grantKey("env-fixture","device-A")]!.grant;
      const label=b64(Buffer.alloc(40,98)),rename={accountId:h.account.id,accountGeneration:"1",deviceId:"device-A",environmentId:"env-fixture",operation:"rename" as const,authorityEnvironmentId:"env-fixture",authorityKeyVersion:"1",authorityGrantGeneration:rootGrant.grantGeneration,previousKeyVersion:"1",keyVersion:"1",expectedSequence:"12",idempotencyKey:"private-X-label",labelPayload:label,recoveryGeneration:"1",recoveryEnvelope:"",grants:[],mutations:[]};
      assert.equal((await h.send("/environment-changes","POST",{change:rename,signature:b64(ed25519.sign(environmentChangeBytes(rename),seeds.A!))},"A")).status,200);
      const mutation={accountId:h.account.id,accountGeneration:"1",deviceId:"device-A",environmentId:"env-fixture",keyVersion:"1",grantGeneration:rootGrant.grantGeneration,operation:"put" as const,idempotencyKey:"private-X-write",name:"PRIVATE_X_MARKER",payload:b64(Buffer.alloc(40,91))};
      assert.equal((await h.send("/mutations","POST",{mutation,signature:b64(ed25519.sign(mutationBytes(mutation),seeds.A!))},"A")).status,200);
      const cPull=await h.send("/pull?after=0&capability=issuer-origin-v1","GET",undefined,"C");assert.equal(cPull.status,200,JSON.stringify(cPull.data));assert.equal(cPull.data.events.length,0);
      const fullResponse=JSON.stringify(cPull.data);assert.equal(fullResponse.includes(label),false);assert.equal(fullResponse.includes("PRIVATE_X_MARKER"),false);assert.equal(fullResponse.includes(mutation.payload),false);
      const serialized=JSON.stringify(cPull.data.issuerEvidence);assert.equal(serialized.includes("PRIVATE_X_MARKER"),false);assert.equal(serialized.includes(mutation.payload),false);assert.equal(serialized.includes("labelPayload"),false);assert.equal(serialized.includes("mutations"),false);
      assert.equal(cPull.data.issuerEvidence.path.at(-1).certificateVersion,"3");verifyIssuerOriginGraph(cPull.data.issuerEvidence);
      const second=await prepare(h,cPull.data.issuerEvidence,first.c.grants[0]!,"D","C");
      assert.equal((await h.send(`/pairings-v3/${second.key}/approve`,"POST",second.input,"C")).status,200);
      const done=await h.send(`/pairings-v3/${second.key}/complete`,"POST",{signature:sign(enrollmentV3Fields(second.c),second.childSeed)});assert.equal(done.status,200,JSON.stringify(done.data));
      const expired=await h.send("/pull?after=0&scope=authorizations&capability=issuer-origin-v1","GET",undefined,"C");assert.equal(expired.status,200);assert.equal(expired.data.events.length,0);assert.ok(expired.data.issuerEvidence);
    } finally {await h.close();}
  });
  test(`${runtime} 临时B轮换X保留A永久旧权限，before伪造与两签重放拒绝`,{timeout:120000},async()=>{
    const h=await create(true);try {
      const packet=structuredClone(vector.rotation);
      const forged=structuredClone(packet);forged.origin.origin.before[0]!.grantHash="0".repeat(64);forged.origin.signature=b64(ed25519.sign(environmentOriginBytes(forged.origin.origin),seeds.B!));
      assert.equal((await h.send("/environment-changes-v2","POST",forged,"B")).status,403);
      assert.equal((await h.send("/environment-changes","POST",packet,"B")).status,400);
      const accepted=await h.send("/environment-changes-v2","POST",packet,"B");assert.equal(accepted.status,200,JSON.stringify(accepted.data));assert.equal(accepted.data.sequence,11);
      assert.equal((await h.send("/environment-changes-v2","POST",packet,"B")).data.replayed,true);
      const oldPull=await h.send("/pull?after=0","GET",undefined,"B");assert.equal(oldPull.status,200);assert.equal(Object.hasOwn(oldPull.data,"issuerEvidence"),false);assert.equal(Object.hasOwn(oldPull.data.environmentEvents[0],"origin"),false);
      const newPull=await h.send("/pull?after=0&capability=issuer-origin-v1","GET",undefined,"B");assert.ok(newPull.data.environmentEvents[0].origin);assert.deepEqual(Object.keys(newPull.data.environmentEvents[0].change).sort(),["change","signature"]);assert.deepEqual(Object.keys(oldPull.data.environmentEvents[0].change).sort(),["change","signature"]);
      assert.equal((await h.send("/environment-changes","POST",{change:packet.change,signature:packet.signature},"B")).status,409);
      const proofResponse=await h.send("/pull?after=11&capability=issuer-origin-v1","GET",undefined,"B");assert.equal(proofResponse.status,200,JSON.stringify(proofResponse.data));
      const proof=proofResponse.data.issuerEvidence as IssuerOriginProof;const full=verifyIssuerOriginGraph(proof);
      for(const origin of proof.origins) for(const row of [...origin.origin.before,...origin.origin.after])assert.deepEqual(environmentRights(full.authorities.get(row.grantHash)!.grant),row);
      assert.equal(full.identities.get("device-C")!.signing,h.account.devices["device-C"]!.signingPublicKey);
      const target=packet.change.grants.find(g=>g.grant.subjectDeviceId==="device-B")!, first=await prepare(h,proof,target,"D");
      assert.equal((await h.send(`/pairings-v3/${first.key}/approve`,"POST",first.input,"B")).status,200);
      const change=structuredClone(target.grant);Object.assign(change,{issuerDeviceId:"device-A",grantGeneration:"3",role:"ro",idempotencyKey:"downgrade-before-complete"});
      assert.equal((await h.send("/grants","POST",{grant:change,signature:b64(ed25519.sign(grantBytes(change),seeds.A!))},"A")).status,200);
      const refused=await h.send(`/pairings-v3/${first.key}/complete`,"POST",{signature:sign(enrollmentV3Fields(first.c),first.childSeed)});assert.equal(refused.status,403);assert.equal(refused.data.error,"admin_required");
      assert.equal((await h.send(`/pairings-v3/${first.key}`,"GET",undefined)).data.sequence,null);
    } finally {await h.close();}
  });
}
test("Node SQLite origin接受UPDATE失败回滚两个签名、来源、授权、封套和序号",async()=>{
  const h=await nodeHarness();try {
    const packet=creation(),before=JSON.stringify(h.read()),restore=h.failNextCommit!();
    try{assert.equal((await h.send("/environment-changes-v2","POST",packet,"B")).status,500);}finally{restore();}
    assert.equal(JSON.stringify(h.read()),before);
    const retry=await h.send("/environment-changes-v2","POST",packet,"B");assert.equal(retry.status,200,JSON.stringify(retry.data));assert.equal(retry.data.sequence,11);assert.equal(h.read().environmentHistory!.at(-1)!.origin!.signature,packet.origin.signature);
  }finally{await h.close();}
});

for (const [runtime,create] of [["Node TCP",nodeHarness],["workerd HTTP",workerHarness]] as const) {
  test(`${runtime} v3批准后精确Admin换代或到期、账号重置均拒绝完成`,{timeout:120000},async()=>{
    const h=await create();try {
      const packet=creation();assert.equal((await h.send("/environment-changes-v2","POST",packet,"B")).status,200);
      const response=await h.send("/pull?after=11&capability=issuer-origin-v1","GET",undefined,"B"),first=await prepare(h,response.data.issuerEvidence,packet.change.grants[0]!);
      assert.equal((await h.send(`/pairings-v3/${first.key}/approve`,"POST",first.input,"B")).status,200);
      // B不能把自身临时Admin永久化；同角色重签换代也使旧目标hash失效。
      const current=structuredClone(packet.change.grants[0]!.grant);Object.assign(current,{grantGeneration:"2",idempotencyKey:"replace-Y-admin"});
      assert.equal((await h.send("/grants","POST",{grant:current,signature:b64(ed25519.sign(grantBytes(current),seeds.B!))},"B")).status,200);
      const firstRefusal=await h.send(`/pairings-v3/${first.key}/complete`,"POST",{signature:sign(enrollmentV3Fields(first.c),first.childSeed)});assert.equal(firstRefusal.status,403);assert.equal(firstRefusal.data.error,"issuer_authority_changed");
      Object.assign(current,{grantGeneration:"3",idempotencyKey:"expire-Y-admin",expiresAt:String(Math.floor(Date.now()/1000)+1)});
      assert.equal((await h.send("/grants","POST",{grant:current,signature:b64(ed25519.sign(grantBytes(current),seeds.B!))},"B")).status,200);
      const deadline=Number(current.expiresAt);await new Promise(resolve=>setTimeout(resolve,Math.max(1,deadline*1000-Date.now()+20)));
      const expired=await h.send(`/pairings-v3/${first.key}/complete`,"POST",{signature:sign(enrollmentV3Fields(first.c),first.childSeed)});assert.equal(expired.status,403);assert.equal(expired.data.error,"environment_forbidden");
      await h.resetGeneration();const reset=await h.send(`/pairings-v3/${first.key}/complete`,"POST",{signature:sign(enrollmentV3Fields(first.c),first.childSeed)});assert.equal(reset.status,401);assert.equal(reset.data.error,"generation_stale");
    }finally{await h.close();}
  });
  test(`${runtime} 签名自洽但未接受origin被拒，cap重复与旧API未知字段不降级`,{timeout:120000},async()=>{
    const h=await create();try {
      const packet=creation();assert.equal((await h.send("/environment-changes-v2","POST",packet,"B")).status,200);
      const response=await h.send("/pull?after=11&capability=issuer-origin-v1","GET",undefined,"B"),proof=response.data.issuerEvidence as IssuerOriginProof;
      const origin=proof.origins[0]!,oldHash=environmentOriginHash(origin);origin.origin.expectedSequence="9";origin.signature=b64(ed25519.sign(environmentOriginBytes(origin.origin),seeds.B!));
      for(const node of proof.authorities)if(node.originHash===oldHash)node.originHash=environmentOriginHash(origin);
      const first=await prepare(h,proof,packet.change.grants[0]!);
      const denied=await h.send(`/pairings-v3/${first.key}/approve`,"POST",first.input,"B");assert.equal(denied.status,403);assert.equal(denied.data.error,"issuer_origin_unaccepted");
      assert.equal((await h.send(`/pairings-v3/${first.key}`,"GET",undefined)).data.approval,null);
      assert.equal((await h.send("/pull?after=0&capability=issuer-origin-v1&capability=issuer-origin-v1","GET",undefined,"B")).status,400);
      assert.equal((await h.send("/pairings-v2","POST",{idempotencyKey:"wrong-profile",deviceId:"device-C",signingPublicKey:first.c.context.initiatorSigningPublicKey,receivingPublicKey:first.c.context.initiatorReceivingPublicKey,approverDeviceId:"device-B",certificateVersion:"3",capabilities:["issuer-origin-v1"]})).status,400);
    }finally{await h.close();}
  });
}
test("Node 历史origin必须精确绑定接受的完整change与同seq grants，v3完成SQL失败回滚",async()=>{
  const h=await nodeHarness();try {
    const packet=creation();assert.equal((await h.send("/environment-changes-v2","POST",packet,"B")).status,200);
    const response=await h.send("/pull?after=11&capability=issuer-origin-v1","GET",undefined,"B"),first=await prepare(h,response.data.issuerEvidence,packet.change.grants[0]!);
    const original=h.read().environmentHistory![0]!;
    h.change(a=>{a.environmentHistory![0]!.change.change.labelPayload=b64(Buffer.alloc(40,96));a.environmentHistory![0]!.change.signature=b64(ed25519.sign(environmentChangeBytes(a.environmentHistory![0]!.change.change),seeds.B!));});
    const historyDenied=await h.send(`/pairings-v3/${first.key}/approve`,"POST",first.input,"B");assert.equal(historyDenied.status,403);assert.equal(historyDenied.data.error,"issuer_origin_unaccepted");
    h.change(a=>{a.environmentHistory![0]=original;});
    assert.equal((await h.send(`/pairings-v3/${first.key}/approve`,"POST",first.input,"B")).status,200);
    const before=JSON.stringify(h.read()),restore=h.failNextCommit!(),signature=sign(enrollmentV3Fields(first.c),first.childSeed);
    try{assert.equal((await h.send(`/pairings-v3/${first.key}/complete`,"POST",{signature})).status,500);}finally{restore();}
    assert.equal(JSON.stringify(h.read()),before);assert.equal(Object.hasOwn(h.read().devices,"device-C"),false);
    assert.equal((await h.send(`/pairings-v3/${first.key}/complete`,"POST",{signature})).status,200);
  }finally{await h.close();}
});

for (const [runtime,create] of [["Node TCP",nodeHarness],["workerd HTTP",workerHarness]] as const) {
  test(`${runtime} 仅Y只读C获得受签控制闭包却不能写入或管理，撤销后仅null来源`,{timeout:120000},async()=>{
    const h=await create();try {
      const packet=creation();assert.equal((await h.send("/environment-changes-v2","POST",packet,"B")).status,200);
      const proof=(await h.send("/pull?after=11&capability=issuer-origin-v1","GET",undefined,"B")).data.issuerEvidence as IssuerOriginProof;
      const first=await prepare(h,proof,packet.change.grants[0]!);first.c.grants[0]!.grant.role="ro";first.c.grants[0]!.signature=b64(ed25519.sign(grantBytes(first.c.grants[0]!.grant),seeds.B!));first.c.approverSignature=sign(enrollmentV3Fields(first.c),seeds.B!);(first.input as any).signature=first.c.approverSignature;
      assert.equal((await h.send(`/pairings-v3/${first.key}/approve`,"POST",first.input,"B")).status,200);
      assert.equal((await h.send(`/pairings-v3/${first.key}/complete`,"POST",{signature:sign(enrollmentV3Fields(first.c),first.childSeed)})).status,200);
      const read=await h.send("/pull?after=12&capability=issuer-origin-v1","GET",undefined,"C");assert.equal(read.status,200);assert.equal(read.data.issuerEvidence.targets.length,1);assert.equal(read.data.issuerEvidence.targets[0].environmentId,"environment-Y");assert.equal(verifyIssuerOriginGraph(read.data.issuerEvidence).authorities.get(read.data.issuerEvidence.targets[0].authorityHash)!.grant.grant.role,"ro");
      const g=first.c.grants[0]!.grant,m={accountId:h.account.id,accountGeneration:"1",deviceId:"device-C",environmentId:g.environmentId,keyVersion:g.keyVersion,grantGeneration:g.grantGeneration,operation:"put" as const,idempotencyKey:"RO-forged-value",name:"READ_ONLY_TEST",payload:b64(Buffer.alloc(40,97))};
      assert.equal((await h.send("/mutations","POST",{mutation:m,signature:b64(ed25519.sign(mutationBytes(m),seeds.C!))},"C")).status,403);
      const manager=await h.send("/pairings-v3","POST",{idempotencyKey:"RO-manager",deviceId:"device-D",signingPublicKey:b64(ed25519.getPublicKey(Buffer.alloc(32,7))),receivingPublicKey:b64(x25519.getPublicKey(Buffer.alloc(32,17))),approverDeviceId:"device-C",certificateVersion:"3",capabilities:["issuer-origin-v1"]});assert.equal(manager.status,403);assert.equal(manager.data.error,"admin_required");
      const revoked=structuredClone(g);Object.assign(revoked,{grantGeneration:"2",role:"none",envelope:"",idempotencyKey:"revoke-only-Y"});
      assert.equal((await h.send("/grants","POST",{grant:revoked,signature:b64(ed25519.sign(grantBytes(revoked),seeds.B!))},"B")).status,200);
      const refresh=await h.send("/pull?after=0&scope=authorizations&capability=issuer-origin-v1","GET",undefined,"C");assert.equal(refresh.status,200);assert.ok(refresh.data.issuerEvidence);assert.equal(refresh.data.issuerEvidence.authorities.some((node: {grant:SignedGrant})=>node.grant.grant.role==="none"),false);assert.equal(refresh.data.events.length,0);assert.equal(refresh.data.environmentEvents.length,0);assert.equal(refresh.data.grants[0].grant.role,"none");
    }finally{await h.close();}
  });
}

for (const [runtime,create] of [["Node TCP",nodeHarness],["workerd HTTP",workerHarness]] as const) {
  test(`${runtime} managerControl含永久RO旧recipient精确双签身份，轮换后RO仍仅读`,{timeout:120000},async()=>{
    const h=await create(true);try {
      const path="/issuer-evidence?environmentId=env-fixture&capability=issuer-origin-v1";
      const control=await h.send(path,"GET",undefined,"B");assert.equal(control.status,200,JSON.stringify(control.data));assert.deepEqual(Object.keys(control.data).sort(),["grants","issuerEvidence","sequence"]);assert.equal(control.data.sequence,10);assert.equal(control.data.grants.length,3);assert.equal(control.data.issuerEvidence.targets.length,1);
      const graph=verifyIssuerOriginGraph(control.data.issuerEvidence);assert.equal(graph.identities.get("device-C")!.signing,h.account.devices["device-C"]!.signingPublicKey);assert.equal(control.data.grants.find((g:SignedGrant)=>g.grant.subjectDeviceId==="device-C").grant.role,"ro");assert.equal(control.data.grants.find((g:SignedGrant)=>g.grant.subjectDeviceId==="device-C").grant.expiresAt,"0");assert.equal(JSON.stringify(control.data).includes("recoveryEnvelope"),false);assert.equal(JSON.stringify(control.data).includes("labelPayload"),false);
      assert.equal((await h.send(path,"GET",undefined,"C")).status,403);assert.equal((await h.send(path,"GET",undefined,"login")).status,401);assert.equal((await h.send("/issuer-evidence?environmentId=env-fixture","GET",undefined,"B")).status,400);
      const packet=structuredClone(vector.rotation);assert.equal((await h.send("/environment-changes-v2","POST",packet,"B")).status,200);
      const receipt=await h.send(`/environment-changes-v2/${packet.change.idempotencyKey}`,"GET",undefined,"B");assert.equal(receipt.status,200);assert.equal(receipt.data.contentHash,await tokenHash(environmentSubmissionContent(environmentChangeBytes(packet.change),packet.signature,packet.origin)));assert.equal(receipt.data.sequence,11);
      const read=await h.send("/pull?after=11&capability=issuer-origin-v1","GET",undefined,"C");assert.equal(read.status,200,JSON.stringify(read.data));assert.equal(read.data.grants[0].grant.keyVersion,"2");assert.equal(read.data.grants[0].grant.role,"ro");assert.equal(read.data.grants[0].grant.expiresAt,"0");const verified=verifyIssuerOriginGraph(read.data.issuerEvidence);assert.ok([...verified.authorities.values()].some(node=>node.previousGrantHash&&node.grant.grant.subjectDeviceId==="device-C"));
    }finally{await h.close();}
  });
}

for (const [runtime,create] of [["Node TCP",nodeHarness],["workerd HTTP",workerHarness]] as const) {
  test(`${runtime} 正式新环境的root自签不能冒充原初始化genesis`,{timeout:120000},async()=>{
    const h=await create();try {
      const packet=creation(),root=h.account.grants[grantKey("env-fixture","device-A")]!,g=structuredClone(root.grant);
      Object.assign(g,{environmentId:"environment-Y",idempotencyKey:"root-new-Y"});
      const signed={grant:g,signature:b64(ed25519.sign(grantBytes(g),seeds.A!))};
      Object.assign(packet.change,{deviceId:"device-A",idempotencyKey:"root-create-Y",grants:[signed]});packet.signature=b64(ed25519.sign(environmentChangeBytes(packet.change),seeds.A!));
      Object.assign(packet.origin.origin,{actorDeviceId:"device-A",idempotencyKey:packet.change.idempotencyKey,changeHash:environmentChangeHash(environmentChangeBytes(packet.change),packet.signature),authorityHash:issuerAuthorityHash(root),after:[environmentRights(signed)]});packet.origin.signature=b64(ed25519.sign(environmentOriginBytes(packet.origin.origin),seeds.A!));
      assert.equal((await h.send("/environment-changes-v2","POST",packet,"A")).status,200);
      const b=structuredClone(h.account.grants[grantKey("env-fixture","device-B")]!.grant);Object.assign(b,{environmentId:"environment-Y",idempotencyKey:"B-new-Y"});const bGrant={grant:b,signature:b64(ed25519.sign(grantBytes(b),seeds.A!))};
      assert.equal((await h.send("/grants","POST",bGrant,"A")).status,200);
      const response=await h.send("/pull?after=12&capability=issuer-origin-v1","GET",undefined,"B"),proof=response.data.issuerEvidence as IssuerOriginProof;assert.equal(response.status,200,JSON.stringify(response.data));
      const forged=proof.authorities.find(node=>node.grant.grant.subjectDeviceId==="device-A"&&node.grant.grant.environmentId==="environment-Y")!;forged.parentHash="";forged.originHash="";forged.previousGrantHash="";proof.origins=[];
      const first=await prepare(h,proof,bGrant);const denial=await h.send(`/pairings-v3/${first.key}/approve`,"POST",first.input,"B");assert.equal(denial.status,403);assert.equal(denial.data.error,"issuer_environment_evidence_required");assert.equal((await h.send(`/pairings-v3/${first.key}`,"GET",undefined)).data.approval,null);
      if(runtime==="Node TCP"){
        h.change(a=>{const grant=structuredClone(signed);a.grantHistory!.unshift({sequence:1,grant,authorization:null});});
        const fakeGenesis=await h.send(`/pairings-v3/${first.key}/approve`,"POST",first.input,"B");assert.equal(fakeGenesis.status,403);assert.equal(fakeGenesis.data.error,"issuer_environment_evidence_required");
      }
    }finally{await h.close();}
  });
}

for (const [runtime,create] of [["Node TCP",nodeHarness],["workerd HTTP",workerHarness]] as const) {
  test(`${runtime} 普通拉取包含另一已入网writer的历史双签身份，暂停流不拉普通数据`,{timeout:120000},async()=>{
    const h=await create();try {
      const initial=(await h.send("/pull?after=10&capability=issuer-origin-v1","GET",undefined,"B")).data.issuerEvidence as IssuerOriginProof;
      // D的原审批候选不含C；后续必须从实际返回事件扩写入者来源，不能靠目录补公钥。
      const rootProof=structuredClone(initial);rootProof.identityPaths=[structuredClone(rootProof.path)];rootProof.path=[];
      const currentB=h.account.grants[grantKey("env-fixture","device-B")]!,currentA=h.account.grants[grantKey("env-fixture","device-A")]!;
      const writer=await prepare(h,initial,currentB,"C","B");
      writer.c.grants[0]!.grant.role="rw";writer.c.grants[0]!.signature=b64(ed25519.sign(grantBytes(writer.c.grants[0]!.grant),seeds.B!));writer.c.approverSignature=sign(enrollmentV3Fields(writer.c),seeds.B!);(writer.input as any).signature=writer.c.approverSignature;
      assert.equal((await h.send(`/pairings-v3/${writer.key}/approve`,"POST",writer.input,"B")).status,200);
      assert.equal((await h.send(`/pairings-v3/${writer.key}/complete`,"POST",{signature:sign(enrollmentV3Fields(writer.c),writer.childSeed)})).status,200);
      const reader=await prepare(h,rootProof,currentA,"D","A");
      reader.c.grants[0]!.grant.role="ro";reader.c.grants[0]!.signature=b64(ed25519.sign(grantBytes(reader.c.grants[0]!.grant),seeds.A!));reader.c.approverSignature=sign(enrollmentV3Fields(reader.c),seeds.A!);(reader.input as any).signature=reader.c.approverSignature;
      assert.equal((await h.send(`/pairings-v3/${reader.key}/approve`,"POST",reader.input,"A")).status,200);
      assert.equal((await h.send(`/pairings-v3/${reader.key}/complete`,"POST",{signature:sign(enrollmentV3Fields(reader.c),reader.childSeed)})).status,200);
      h.setToken("D",token("login"));
      const challenge=await h.send("/device-challenges","POST",{},"D");assert.equal(challenge.status,200,JSON.stringify(challenge.data));
      const fields=["harmonia/device-session/v1",h.account.id,"1","device-D",await tokenHash(token("login")),challenge.data.challengeId,challenge.data.nonce,String(challenge.data.expiresAt)];assert.deepEqual(challenge.data.signingPayload,fields);
      const bound=await h.send("/device-sessions","POST",{challengeId:challenge.data.challengeId,signature:sign(fields,reader.childSeed)},"D");assert.equal(bound.status,200,JSON.stringify(bound.data));h.setToken("D",bound.data.token);
      const g=writer.c.grants[0]!.grant,mutation={accountId:h.account.id,accountGeneration:"1",deviceId:"device-C",environmentId:g.environmentId,keyVersion:g.keyVersion,grantGeneration:g.grantGeneration,operation:"put" as const,idempotencyKey:"other-writer-value",name:"OTHER_WRITER_VALUE",payload:b64(Buffer.alloc(40,101))};
      assert.equal((await h.send("/mutations","POST",{mutation,signature:b64(ed25519.sign(mutationBytes(mutation),seeds.C!))},"C")).status,200);
      // 当前撤销不抹去已经接受写入时冻结的RW授权。
      const revoked=structuredClone(g);Object.assign(revoked,{issuerDeviceId:"device-A",grantGeneration:"2",role:"none",envelope:"",idempotencyKey:"other-writer-revoked"});
      assert.equal((await h.send("/grants","POST",{grant:revoked,signature:b64(ed25519.sign(grantBytes(revoked),seeds.A!))},"A")).status,200);
      const paused=await h.send("/pull?after=12&scope=authorizations&capability=issuer-origin-v1","GET",undefined,"D");assert.equal(paused.status,200,JSON.stringify(paused.data));assert.equal(paused.data.events.length,0);assert.equal(verifyIssuerOriginGraph(paused.data.issuerEvidence).identities.has("device-C"),false);
      const read=await h.send("/pull?after=12&capability=issuer-origin-v1","GET",undefined,"D");assert.equal(read.status,200,JSON.stringify(read.data));assert.equal(read.data.events.length,1);assert.deepEqual(read.data.events[0].authorization,writer.c.grants[0]);
      const graph=verifyIssuerOriginGraph(read.data.issuerEvidence);assert.equal(graph.identities.get("device-C")!.signing,writer.c.context.initiatorSigningPublicKey);assert.equal(graph.identities.get("device-C")!.receiving,writer.c.context.initiatorReceivingPublicKey);assert.deepEqual(graph.authorities.get(issuerAuthorityHash(writer.c.grants[0]!))!.grant,writer.c.grants[0]);
      const serialized=JSON.stringify(read.data.issuerEvidence);assert.equal(serialized.includes(mutation.name),false);assert.equal(serialized.includes(mutation.payload),false);assert.equal(serialized.includes("labelPayload"),false);assert.equal(serialized.includes("recoveryEnvelope"),false);
      if(runtime==="Node TCP"){
        h.change(a=>{a.grantHistory=a.grantHistory!.filter(row=>issuerAuthorityHash(row.grant)!==issuerAuthorityHash(writer.c.grants[0]!));});
        const missing=await h.send("/pull?after=12&capability=issuer-origin-v1","GET",undefined,"D");assert.equal(missing.status,403);assert.equal(missing.data.error,"issuer_authority_unaccepted");
      }
    }finally{await h.close();}
  });
}

for (const [runtime,create] of [["Node TCP",nodeHarness],["workerd HTTP",workerHarness]] as const) {
  test(`${runtime} 缺原双签初始化的旧夹具拒绝新来源能力，旧无cap读取仍可用`,{timeout:120000},async()=>{
    const h=await create(false,false);try {
      assert.equal((await h.send("/pull?after=0","GET",undefined,"B")).status,200);
      const proof=await h.send("/pull?after=0&capability=issuer-origin-v1","GET",undefined,"B");assert.equal(proof.status,403);assert.equal(proof.data.error,"initialization_evidence_required");
      const control=await h.send("/issuer-evidence?environmentId=env-fixture&capability=issuer-origin-v1","GET",undefined,"B");assert.equal(control.status,403);assert.equal(control.data.error,"initialization_evidence_required");
      const packet=creation(),rejected=await h.send("/environment-changes-v2","POST",packet,"B");assert.equal(rejected.status,403);assert.equal(rejected.data.error,"initialization_evidence_required");
      assert.equal((await h.send(`/environment-changes-v2/${packet.change.idempotencyKey}`,"GET",undefined,"B")).data.state,"unknown");
      assert.equal((await h.send("/pull?after=0","GET",undefined,"B")).data.sequence,10);
    }finally{await h.close();}
  });
}
