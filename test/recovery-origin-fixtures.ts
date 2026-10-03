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
import { EnrollmentService, relayFields } from "../src/enrollment.js";
import { grantKey, type SignedGrant } from "../src/model.js";
import { canonical, hash, pairingContextFields, type EnrollmentAccount, type InitializationProposal, type PairingContext } from "../src/enrollment-wire.js";
import { environmentChangeBytes, deviceRevocationBytes, type SignedEnvironmentChangeV2 } from "../src/environments.js";
import { environmentChangeHash, environmentOriginBytes } from "../src/environment-origin.js";
import { enrollmentV3Fields, type EnrollmentApprovalV3, type IssuerOriginProof } from "../src/issuer-origin.js";
import { issuerAuthorityHash } from "../src/issuer-proof.js";
import { grantBytes, mutationBytes } from "../src/protocol.js";
import { fixtureAccount, recoveryKeys } from "./fixtures.js";
import { trustRootPayload } from "../src/trust-root.js";
export const vector = JSON.parse(readFileSync(new URL("./vectors/environment-origin-v1.json", import.meta.url), "utf8")) as { approval: EnrollmentApprovalV3; creation: SignedEnvironmentChangeV2; rotation: SignedEnvironmentChangeV2; syntheticSigningSeedsHex: Record<string,string> };
export const b64 = (value: Uint8Array): string => Buffer.from(value).toString("base64url");
export const seeds: Record<string, Uint8Array> = Object.fromEntries(Object.entries(vector.syntheticSigningSeedsHex as Record<string,string>).map(([key,value]) => [key,Buffer.from(value,"hex")]));
export const sign = (fields: unknown, seed: Uint8Array): string => b64(ed25519.sign(canonical(fields), seed));
const token = (who: string) => b64(Buffer.alloc(32, { login:61,A:65,B:62,C:63 }[who] ?? 66));
export interface Harness {
  account: EnrollmentAccount;
  send: (path:string,method:string,body?:unknown,who?:string,generation?:string,accountId?:string)=>Promise<{status:number;data:any}>;
  setToken: (who:string,token:string)=>void;
  read: ()=>EnrollmentAccount;
  change: (f:(account:EnrollmentAccount)=>void)=>void;
  failNextCommit?: ()=>()=>void;
  close: ()=>Promise<void>;
}
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

export async function nodeHarness(includeReader = false): Promise<Harness> {
  const dir=mkdtempSync(join(tmpdir(),"harmonia-recovery-origin-node-")),db=nodeStore(join(dir,"state.sqlite")),a=await accountFixture(includeReader),sessionTokens=new Map<string,string>();
  db.store.create(a);
  const server=nodeServer(new VaultService(db.store,{allowRegistration:false,requireEmailVerification:true}));server.server.listen(0,"127.0.0.1");await once(server.server,"listening");
  const base=`http://127.0.0.1:${(server.server.address() as {port:number}).port}`;
  return {account:a,setToken:(who,value)=>{sessionTokens.set(who,value);},send:async(path,method,body,who="B",generation="1",accountId=a.id)=>{
    const response=await fetch(`${base}/v1/accounts/${accountId}${path}`,{method,headers:{"content-type":"application/json",authorization:`Bearer ${sessionTokens.get(who)??token(who)}`,"x-harmonia-account-generation":generation,...(["A","B","C","E","F"].includes(who)?{"x-harmonia-device-id":`device-${who}`}:{})},...(method==="GET"?{}:{body:JSON.stringify(body)})});return {status:response.status,data:await response.json()};
  },read:()=>db.store.read(a.id) as EnrollmentAccount,change:f=>db.store.transaction(a.id,account=>f(account as EnrollmentAccount)),failNextCommit:()=>{
    const execute=db.sql.execute.bind(db.sql);let failed=false;db.sql.execute=(query,params)=>{if(!failed&&query.startsWith("UPDATE accounts")){failed=true;throw Error("synthetic SQLite recovery commit failure");}execute(query,params);};return()=>{db.sql.execute=execute;};
  },close:async()=>{server.closeNotifications();server.server.close();await once(server.server,"close");db.sql.close();rmSync(dir,{recursive:true,force:true});}};
}
export async function workerHarness(includeReader = false): Promise<Harness> {
  const dir=mkdtempSync(join(tmpdir(),"harmonia-recovery-origin-worker-")),a=await accountFixture(includeReader),sessionTokens=new Map<string,string>();
  const built=await build({entryPoints:["test/worker-harness.ts"],absWorkingDir:process.cwd(),bundle:true,write:false,format:"esm",platform:"browser",target:"es2023",external:["cloudflare:workers","node:*"],banner:{js:'import { Buffer } from "node:buffer";'}});
  const mf=new Miniflare({modules:true,script:built.outputFiles[0]!.text,compatibilityDate:"2026-07-30",compatibilityFlags:["nodejs_compat"],durableObjects:{INSTANCES:{className:"InstanceRegistry",useSQLite:true},ACCOUNTS:{className:"SyntheticVault",useSQLite:true},FIXTURES:{className:"SyntheticVault",useSQLite:true}},d1Databases:{DIRECTORY:"directory"},durableObjectsPersist:join(dir,"objects"),d1Persist:join(dir,"directory")});
  await mf.dispatchFetch("https://synthetic.invalid/test/seed",{method:"POST",body:JSON.stringify(a)});
  return {account:a,setToken:(who,value)=>{sessionTokens.set(who,value);},send:async(path,method,body,who="B",generation="1",accountId=a.id)=>{
    const response=await mf.dispatchFetch(`https://synthetic.invalid/v1/accounts/${accountId}${path}`,{method,headers:{"content-type":"application/json",authorization:`Bearer ${sessionTokens.get(who)??token(who)}`,"x-harmonia-account-generation":generation,...(["A","B","C","E","F"].includes(who)?{"x-harmonia-device-id":`device-${who}`}:{})},...(method==="GET"?{}:{body:JSON.stringify(body)})});return {status:response.status,data:await response.json()};
  },read:()=>a,change:()=>{throw Error("workerd tests must use public signed routes");},close:async()=>{await mf.dispose();rmSync(dir,{recursive:true,force:true});}};
}
export function resign(packet: SignedEnvironmentChangeV2): void {
  packet.signature=b64(ed25519.sign(environmentChangeBytes(packet.change),seeds.B!));packet.origin.origin.changeHash=environmentChangeHash(environmentChangeBytes(packet.change),packet.signature);packet.origin.signature=b64(ed25519.sign(environmentOriginBytes(packet.origin.origin),seeds.B!));
}
export async function recoverChallenge(h:Harness): Promise<{challenge:any;signature:string}> {
  const response=await h.send("/recovery-challenges","POST",{accountGeneration:"1"},"login");assert.equal(response.status,200,JSON.stringify(response.data));const c=response.data;
  const fields=["harmonia/recovery-proof/v1",h.account.id,"1","1",c.challengeId,c.nonce,String(c.expiresAt)];assert.deepEqual(c.signingPayload,fields);
  return {challenge:c,signature:sign(fields,recoveryKeys(Buffer.alloc(32,88),h.account.id).signingSeed)};
}
export async function freshRecovery(h:Harness): Promise<any> {
  const {challenge,signature}=await recoverChallenge(h),response=await h.send("/recovery-sessions","POST",{accountGeneration:"1",challengeId:challenge.challengeId,signature},"login");assert.equal(response.status,200,JSON.stringify(response.data));assert.equal(response.data.rotationRequired,true);h.setToken("R",response.data.token);return response.data;
}
export async function revoke(h:Harness,who:string): Promise<void> {
  const challenge=await h.send("/device-revocations","POST",{subjectDeviceId:`device-${who}`,idempotencyKey:`revoke-${who}`} ,"B");assert.equal(challenge.status,200,JSON.stringify(challenge.data));
  const response=await h.send("/device-revocations/complete","POST",{revocation:challenge.data,signature:b64(ed25519.sign(deviceRevocationBytes(challenge.data),seeds.B!))},"B");assert.equal(response.status,200,JSON.stringify(response.data));
}
/** 公开合成中继用于服务安全测试；真实PAKE/HPKE由独立Go联合验收。 */
export async function setupEnvironments(h:Harness): Promise<{sequence:number;writer:SignedGrant;newX:SignedGrant;newY:SignedGrant;packets:string[]}> {
  const initialB=h.account.grants[grantKey("env-fixture","device-B")]!;
  const put=async(g:SignedGrant,who:string,id:string,name:string,value:number)=>{
    const mutation={accountId:h.account.id,accountGeneration:"1",deviceId:`device-${who}`,environmentId:g.grant.environmentId,keyVersion:g.grant.keyVersion,grantGeneration:g.grant.grantGeneration,operation:"put" as const,idempotencyKey:id,name,payload:b64(Buffer.alloc(40,value))};
    const response=await h.send("/mutations","POST",{mutation,signature:b64(ed25519.sign(mutationBytes(mutation),seeds[who]!))},who);assert.equal(response.status,200,JSON.stringify(response.data));return {sequence:response.data.sequence as number,payload:mutation.payload};
  };
  const oldX=await put(initialB,"B","original-X","SOURCE_X",101),creation=structuredClone(vector.creation) as SignedEnvironmentChangeV2;
  creation.change.expectedSequence=String(oldX.sequence);creation.origin.origin.expectedSequence=String(oldX.sequence);creation.change.labelPayload=b64(Buffer.alloc(40,102));resign(creation);
  const created=await h.send("/environment-changes-v2","POST",creation,"B");assert.equal(created.status,200,JSON.stringify(created.data));const newY=creation.change.grants[0]!;
  const proof=(await h.send(`/pull?after=${created.data.sequence}&capability=issuer-origin-v1`,"GET",undefined,"B")).data.issuerEvidence as IssuerOriginProof;
  const key="recovery-origin-C",pub=b64(ed25519.getPublicKey(seeds.C!)),receiver=b64(x25519.getPublicKey(Buffer.alloc(32,13)));
  const begin=await h.send("/pairings-v3","POST",{idempotencyKey:key,deviceId:"device-C",signingPublicKey:pub,receivingPublicKey:receiver,approverDeviceId:"device-B",certificateVersion:"3",capabilities:["issuer-origin-v1"]},"login");assert.equal(begin.status,200,JSON.stringify(begin.data));const context=begin.data.context as PairingContext;
  for(const [side,kind,value,who] of [["initiator","message",71,"login"],["approver","message",72,"B"],["initiator","confirmation",73,"login"],["approver","confirmation",74,"B"]] as const){const relay={side,kind,payload:b64(Buffer.alloc(32,value))};const result=await h.send(`/pairings-v3/${key}/relay`,"POST",{...relay,signature:sign(relayFields({context} as any,relay),side==="initiator"?seeds.C!:seeds.B!)},who);assert.equal(result.status,200,JSON.stringify(result.data));}
  const status=await h.send(`/pairings-v3/${key}`,"GET",undefined,"login"),g=structuredClone(newY.grant);Object.assign(g,{subjectDeviceId:"device-C",subjectSigningPublicKey:pub,subjectReceivingPublicKey:receiver,role:"rw",idempotencyKey:"recovery-writer-C"});const writer={grant:g,signature:b64(ed25519.sign(grantBytes(g),seeds.B!))};
  const certificate:EnrollmentApprovalV3={certificateVersion:"3",context,pairingProfile:vector.approval.pairingProfile,transcriptHash:hash(["harmonia/pairing-transcript/v1",b64(canonical(pairingContextFields(context))),status.data.messages.initiator,status.data.messages.approver]),grants:[writer],issuerProof:proof,approverSignature:""};certificate.issuerProof.targets=[{environmentId:g.environmentId,authorityHash:issuerAuthorityHash(newY)}];certificate.approverSignature=sign(enrollmentV3Fields(certificate),seeds.B!);
  const approved=await h.send(`/pairings-v3/${key}/approve`,"POST",{certificateVersion:"3",capabilities:["issuer-origin-v1"],grants:certificate.grants,transcriptHash:certificate.transcriptHash,issuerProof:certificate.issuerProof,signature:certificate.approverSignature},"B");assert.equal(approved.status,200,JSON.stringify(approved.data));
  assert.equal((await h.send(`/pairings-v3/${key}/complete`,"POST",{signature:sign(enrollmentV3Fields(certificate),seeds.C!)},"login")).status,200);
  const boot=await h.send("/boot-challenges","POST",{deviceId:"device-C",accountGeneration:"1"},"login");assert.equal(boot.status,200,JSON.stringify(boot.data));const fields=["harmonia/device-boot/v1",h.account.id,"1","device-C",pub,receiver,boot.data.challengeId,boot.data.nonce,String(boot.data.expiresAt)];assert.deepEqual(boot.data.signingPayload,fields);
  const session=await h.send("/boot-sessions","POST",{deviceId:"device-C",accountGeneration:"1",challengeId:boot.data.challengeId,signature:sign(fields,seeds.C!)},"login");assert.equal(session.status,200);h.setToken("C",session.data.token);
  const y=await put(writer,"C","new-Y","SOURCE_Y",103),rotation=structuredClone(vector.rotation) as SignedEnvironmentChangeV2;
  rotation.change.grants=rotation.change.grants.filter(grant=>grant.grant.subjectDeviceId!=="device-C");rotation.origin.origin.before=rotation.origin.origin.before.filter(row=>row.subjectDeviceId!=="device-C");rotation.origin.origin.after=rotation.origin.origin.after.filter(row=>row.subjectDeviceId!=="device-C");
  rotation.change.expectedSequence=String(y.sequence);rotation.origin.origin.expectedSequence=String(y.sequence);
  const newX=rotation.change.grants.find(grant=>grant.grant.subjectDeviceId==="device-B")!,mutation={accountId:h.account.id,accountGeneration:"1",deviceId:"device-B",environmentId:"env-fixture",keyVersion:"2",grantGeneration:"2",operation:"put" as const,idempotencyKey:"reencrypted-X",name:"SOURCE_X",payload:b64(Buffer.alloc(40,104))};rotation.change.mutations=[{mutation,signature:b64(ed25519.sign(mutationBytes(mutation),seeds.B!))}];resign(rotation);
  const rotated=await h.send("/environment-changes-v2","POST",rotation,"B");assert.equal(rotated.status,200,JSON.stringify(rotated.data));assert.equal(rotated.data.sequence,y.sequence+2);
  return {sequence:rotated.data.sequence,writer,newX,newY,packets:[oldX.payload,y.payload,mutation.payload,creation.change.labelPayload]};
}
