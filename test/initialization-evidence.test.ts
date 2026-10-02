import { once } from "node:events";
import { nodeServer } from "../src/node-runtime.js";
import { LifecycleService } from "../src/lifecycle.js";
import { originalInitialization } from "../src/initialization-evidence.js";
import { trustRootPayload } from "../src/trust-root.js";
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

test("恢复显式cap通过真实HTTP返回原双签initialization，旧响应无额外字段",async()=>withEmpty(async h=>{
  const auth=await initialize(h),server=nodeServer(h.vault);server.server.listen(0,"127.0.0.1");await once(server.server,"listening");
  const base=`http://127.0.0.1:${(server.server.address() as {port:number}).port}/v1/accounts/${accountId}`;
  const request=async(query:string,credentials=auth)=>{const response=await fetch(`${base}/recovery-vault${query}`,{headers:{authorization:`Bearer ${credentials.token}`,"x-harmonia-account-generation":"1","x-harmonia-device-id":credentials.deviceId}});return {status:response.status,data:await response.json() as Record<string,any>};};
  try {
    const legacy=await request("");assert.equal(legacy.status,200);assert.equal(Object.hasOwn(legacy.data,"originalInitialization"),false);
    const current=await request("?capability=issuer-origin-v1");assert.equal(current.status,200);const record=current.data.originalInitialization;assert.ok(record);assert.deepEqual(Object.keys(record).sort(),["deviceSignature","proof","proposal","recoverySignature","sequence"]);assert.equal(record.sequence,1);assert.equal(record.proof.proposalHash,initializationHash(accountId,"1",record.proposal));
    const fields=["harmonia/vault-initialize/v1",record.proof.accountId,record.proof.accountGeneration,record.proof.loginTokenHash,record.proof.challengeId,record.proof.nonce,record.proof.expiresAt,record.proof.proposalHash];
    assert.equal(ed25519.verify(Buffer.from(record.deviceSignature,"base64url"),canonical(fields),Buffer.from(record.proposal.device.signingPublicKey,"base64url"),{zip215:false}),true);assert.equal(ed25519.verify(Buffer.from(record.recoverySignature,"base64url"),canonical(fields),Buffer.from(record.proposal.recoverySigningPublicKey,"base64url"),{zip215:false}),true);assert.equal(JSON.stringify(record).includes(h.login.token),false);assert.equal(JSON.stringify(record).includes(auth.token),false);assert.equal(JSON.stringify(record).includes("passwordVerifier"),false);assert.equal(JSON.stringify(record).includes("email"),false);
    assert.equal((await request("?capability=wrong-profile")).status,400);assert.equal((await request("?capability=issuer-origin-v1&capability=issuer-origin-v1")).status,400);
    const state=h.store.read(accountId) as EnrollmentAccount,original=structuredClone(state.vaultInitializations!);
    h.store.transaction(accountId,a=>{(a as EnrollmentAccount).vaultInitializations![vector.proposal.idempotencyKey]!.complete!.deviceSignature=b64(Buffer.alloc(64));});
    assert.equal((await request("?capability=issuer-origin-v1")).status,403);
    h.store.transaction(accountId,a=>{(a as EnrollmentAccount).vaultInitializations=original;});
    assert.equal((await request("?capability=issuer-origin-v1")).status,200);
  }finally{server.closeNotifications();server.server.close();await once(server.server,"close");}
}));
test("恢复码轮换保持原初始化旧恢复pub受root签绑定，不把currentrec元数据当新genesis",async()=>withEmpty(async h=>{
  const auth=await initialize(h),service=new LifecycleService(h.store,()=>now),before=originalInitialization(h.store.read(accountId)!)!;
  const nextKeys=recoveryKeys(Buffer.alloc(32,109),accountId),prior=h.store.read(accountId)!.trustRoot!;
  const newRoot={...prior,recoveryGeneration:"2",recoverySigningPublicKey:nextKeys.signingPublicKey,recoveryReceivingPublicKey:nextKeys.receivingPublicKey,signature:""};newRoot.signature=sign(trustRootPayload(accountId,"1",newRoot),nextKeys.signingSeed);
  const challenge=await service.beginRotation(accountId,auth,{idempotencyKey:"rotation-preserve-original",newRecoveryGeneration:"2",newRecoverySigningPublicKey:nextKeys.signingPublicKey,newRecoveryReceivingPublicKey:nextKeys.receivingPublicKey,newTrustRoot:newRoot,envelopes:Object.values(h.store.read(accountId)!.environments).map(e=>({environmentId:e.id,keyVersion:e.keyVersion,envelope:b64(Buffer.alloc(80,110))}))});
  await service.completeRotation(accountId,auth,"rotation-preserve-original",challenge.challengeId as string,sign(challenge.signingPayload,nextKeys.signingSeed));
  const after=originalInitialization(h.store.read(accountId)!)!;assert.deepEqual(after,before);assert.notEqual(after.proposal.recoverySigningPublicKey,h.store.read(accountId)!.recoverySigningPublicKey);assert.equal(after.proposal.device.signingPublicKey,h.store.read(accountId)!.trustRoot!.rootSigningPublicKey);
}));
test("旧合成账号缺原初始化双签记录时明确null，不从grantHistory或currentSelfGrant补造",async()=>{
  const a=await fixtureAccount(accountId);assert.equal(originalInitialization(a),null);
});
