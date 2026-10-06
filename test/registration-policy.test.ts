import {DAGEnrollmentService} from "../src/dag-enrollment.js";
import { emailVerification, resetProof } from "./email-proof.js";
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { nodeStore, NodeSql } from "../src/node-store.js";
import { SqlStore, type Sql } from "../src/store.js";
import { nodeServer } from "../src/node-runtime.js";
import { VaultService, type Policy } from "../src/service.js";
import { AccountLifecycle, type ProofInput } from "../src/account-lifecycle.js";
import { EnrollmentService } from "../src/enrollment.js";
import { LifecycleService } from "../src/lifecycle.js";
import { wasmPassword } from "../src/password.js";
import { Fault } from "../src/model.js";
import type { Email } from "../src/email-transport.js";
import { trustRootPayload } from "../src/trust-root.js";
import { fixtureAccount, now, clientCredential, seeds, recoveryKeys, recoverySeed } from "./fixtures.js";
const denies = (code:string) => (e:unknown):boolean => e instanceof Fault && e.code===code;
const b64=(v:Uint8Array):string=>Buffer.from(v).toString("base64url");
const sign=(v:unknown,k:Uint8Array):string=>b64(ed25519.sign(new TextEncoder().encode(JSON.stringify(v)),k));
async function harness(run:(h:{store:SqlStore;vault:VaultService;policy:Policy;mails:Email[];request:(path:string,value?:unknown)=>Promise<Response>;advance:(n:number)=>void;path:string})=>Promise<void>, policy:Policy={allowRegistration:false,requireEmailVerification:true}):Promise<void>{
 let clock=now;const dir=mkdtempSync(join(tmpdir(),"harmonia-registration-policy-")),path=join(dir,"synthetic.sqlite"),{store,sql}=nodeStore(path,()=>clock),mails:Email[]=[];
 const vault=new VaultService(store,policy,()=>clock,wasmPassword,{send:async m=>{mails.push(m);}}),runtime=nodeServer(vault);
 await new Promise<void>(resolve=>runtime.server.listen(0,"127.0.0.1",resolve));const address=runtime.server.address() as {port:number};
 // This registration fixture advances its synthetic clock past send cooldowns.
 const request=async(path:string,value?:unknown):Promise<Response>=>{
   const response=await fetch(`http://127.0.0.1:${address.port}${path}`,value===undefined?{headers:{"Harmonia-Protocol-Major":"2"}}:{method:"POST",headers: {"Harmonia-Protocol-Major":"2", "content-type":"application/json"},body:JSON.stringify(value)});
   if(response.status===429){const fault=await response.clone().json() as {error:string;retryAfterSeconds:number};if(fault.error==='email_request_limited'){clock+=fault.retryAfterSeconds;return request(path,value);}}
   return response;
 };
 try{await run({store,vault,policy,mails,request,advance:n=>{clock+=n;},path});}finally{runtime.closeNotifications();runtime.server.closeAllConnections();await new Promise<void>((resolve,reject)=>runtime.server.close(e=>e?reject(e):resolve()));sql.close();rmSync(dir,{recursive:true,force:true});}
}
for(const open of [false,true])for(const required of [false,true])test(`真实NodeTCP 两开关 ${open}/${required} 首号与后续注册遵循冻结要求`,async()=>harness(async h=>{
 const info=await h.request("/instance-info"),v=await info.json() as any;assert.equal(info.headers.get("cache-control"),"no-store");assert.deepEqual(Object.keys(v).sort(),["allowRegistration","emailVerificationRequired","initialRegistrationAvailable","product","protocol","status"]);assert.equal(v.product,"harmonia");assert.deepEqual(v.protocol.supportedMajors,[2]);assert.equal(v.initialRegistrationAvailable,true);assert.equal(v.allowRegistration,open);assert.equal(v.emailVerificationRequired,required);
 const first=await h.request("/v1/register",{email:"first@example.invalid",credential:clientCredential});assert.equal(first.status,200,await first.clone().text());const r=await first.json() as any;
 assert.equal(h.store.read(r.accountId)!.verificationRequiredAtRegistration,required);assert.equal(h.mails.length,required?1:0);
 if(required){assert.equal((await h.request("/instance-info").then(r=>r.json()) as any).initialRegistrationAvailable,true);assert.equal((await h.request("/v1/login",{email:"first@example.invalid",credential:clientCredential})).status,401);const p=emailVerification(h.vault.accountLifecycle(), h.mails[0]!);assert.equal((await h.request(`/v1/accounts/${r.accountId}/email-verification/complete`,{accountGeneration:p.accountGeneration,code:p.code})).status,200);assert.equal((await h.request(`/v1/accounts/${r.accountId}/email-verification/complete`,{accountGeneration:p.accountGeneration,code:p.code})).status,401);assert.equal((await h.request("/v1/login",{email:"first@example.invalid",credential:"ee".repeat(32)})).status,401);}
 assert.equal((await h.request("/v1/login",{email:"first@example.invalid",credential:clientCredential})).status,200);assert.equal((await h.request("/instance-info").then(r=>r.json()) as any).initialRegistrationAvailable,false);
 const second=await h.request("/v1/register",{email:"second@example.invalid",credential:clientCredential});assert.equal(second.status,open?200:403);
 assert.equal((await h.request("/instance-info?unknown=1")).status,400);assert.equal((await h.request("/instance-info",{})).status,405);
 const reopened=nodeStore(h.path);try{assert.equal((await reopened.store.registrationAuthority.info()).firstCompleted,true);}finally{reopened.sql.close();}
},{allowRegistration:open,requireEmailVerification:required}));
test("真实NodeTCP closed多个邮箱pending不占首号；并发证明只有赢家激活且reset/删空不重开",async()=>harness(async h=>{
 const rows=await Promise.all(["one","two"].map(async n=>{const r=await h.request("/v1/register",{email:`${n}@example.invalid`,credential:clientCredential});assert.equal(r.status,200);return await r.json() as any;}));
 assert.equal((await h.request("/instance-info").then(r=>r.json()) as any).initialRegistrationAvailable,true);
 const done=await Promise.all(h.mails.map(async m=>{const p=emailVerification(h.vault.accountLifecycle(), m);return h.request(`/v1/accounts/${p.accountId}/email-verification/complete`,{accountGeneration:p.accountGeneration,code:p.code});}));assert.deepEqual(done.map(r=>r.status).sort(),[200,403]);
 const winner=await h.store.registrationAuthority.info(),loser=rows.find(r=>r.accountId!==winner.winnerAccountId)!;
 assert.equal((await h.request("/v1/account-reset/request",{email:h.store.read(loser.accountId)!.email})).status,403);assert.equal(h.store.read(loser.accountId)!.registrationAdmission!.state,"proof-ready");
 h.policy.allowRegistration=true;h.policy.requireEmailVerification=false;const loserEmail=h.store.read(loser.accountId)!.email;await assert.rejects(h.vault.login(loserEmail,"ee".repeat(32)),denies("unauthorized"));assert.equal(h.store.read(loser.accountId)!.registrationAdmission!.state,"proof-ready");await h.vault.login(loserEmail,clientCredential);assert.equal(h.store.read(loser.accountId)!.registrationAdmission!.state,"complete");assert.equal(h.store.read(loser.accountId)!.verificationRequiredAtRegistration,true);assert.equal((await h.store.registrationAuthority.info()).winnerAccountId,winner.winnerAccountId);h.policy.allowRegistration=false;
 const email=h.store.read(winner.winnerAccountId!)!.email;assert.equal((await h.request("/v1/login",{email,credential:clientCredential})).status,200);
 h.advance(31);await h.vault.accountLifecycle().requestProof(email,"reset");const p=await resetProof(h.vault.accountLifecycle(), h.mails.at(-1)!);await h.vault.accountLifecycle().reset(p.accountId,{...p,newCredential:"cd".repeat(32),confirmation:"DELETE_OLD_VAULT"});assert.equal((await h.store.registrationAuthority.info()).firstCompleted,true);
 const raw=new NodeSql(h.path);try{raw.execute("DELETE FROM accounts");}finally{raw.close();}assert.equal((await h.request("/instance-info").then(r=>r.json()) as any).initialRegistrationAvailable,false);assert.equal((await h.request("/v1/register",{email:"third@example.invalid",credential:clientCredential})).status,403);
}));
test("验证开关仅新注册：off旧账号开启后login/配对/boot仍可用；on pending切off仍必须证明",async()=>harness(async h=>{
 h.policy.allowRegistration=true;h.policy.requireEmailVerification=false;
 const r=await h.vault.register("optional@example.invalid",clientCredential);assert.equal(h.store.read(r.accountId)!.verified,false);h.policy.requireEmailVerification=true;h.policy.allowRegistration=false;assert.equal((await h.vault.login("optional@example.invalid",clientCredential)).accountId,r.accountId);
 const a=await fixtureAccount("legacy-account","legacy@example.invalid");a.verified=false;const recovery=recoveryKeys(recoverySeed,a.id);a.trustRoot={rootDeviceId:"admin",rootSigningPublicKey:a.devices.admin!.signingPublicKey,rootReceivingPublicKey:a.devices.admin!.receivingPublicKey,recoveryGeneration:"1",recoverySigningPublicKey:recovery.signingPublicKey,recoveryReceivingPublicKey:recovery.receivingPublicKey,signature:""};a.trustRoot.signature=sign(trustRootPayload(a.id,a.generation,a.trustRoot),recovery.signingSeed);h.store.create(a);
 const login=await h.vault.login(a.email,clientCredential),enrollment=new DAGEnrollmentService(h.store,()=>now);
 const pairing=await enrollment.begin(a.id,login,{certificateVersion:"5",capabilities:["issuer-recovery-dag-v1"],idempotencyKey:"new-legacy-device",deviceId:"new-device",signingPublicKey:b64(ed25519.getPublicKey(Buffer.alloc(32,75))),receivingPublicKey:b64(x25519.getPublicKey(Buffer.alloc(32,76))),approverDeviceId:"admin"});assert.equal(pairing.state,"pending");
 const lifecycle=new LifecycleService(h.store,()=>now),c=lifecycle.bootChallenge(a.id,"admin","1");assert.ok((await lifecycle.bootSession(a.id,"admin","1",c.challengeId,sign(c.signingPayload,seeds.admin!))).token);
 h.policy.allowRegistration=true;const pending=await h.vault.register("required@example.invalid",clientCredential);h.policy.requireEmailVerification=false;await assert.rejects(h.vault.login("required@example.invalid",clientCredential),denies("unauthorized"));assert.equal(h.store.read(pending.accountId)!.verificationRequiredAtRegistration,true);const p=emailVerification(h.vault.accountLifecycle(), h.mails.at(-1)!);await h.vault.accountLifecycle().verifyEmail(p.accountId,p);await h.vault.login("required@example.invalid",clientCredential);
 assert.throws(()=>h.store.transaction(pending.accountId,a=>{a.verificationRequiredAtRegistration=false;}),denies("registration_policy_immutable"));
 h.advance(31);await h.vault.accountLifecycle().requestProof("required@example.invalid","reset");const reset=await resetProof(h.vault.accountLifecycle(), h.mails.at(-1)!);await h.vault.accountLifecycle().reset(reset.accountId,{...reset,newCredential:"cd".repeat(32),confirmation:"DELETE_OLD_VAULT"});assert.equal(h.store.read(reset.accountId)!.verificationRequiredAtRegistration,true);
}));
test("pending超期后同邮箱重新申请，旧证明失效，新申请采用当前策略；正式账号不可替换",async()=>harness(async h=>{
 const first=await h.vault.register("pending@example.invalid",clientCredential),old=emailVerification(h.vault.accountLifecycle(), h.mails[0]!);h.advance(900);h.policy.requireEmailVerification=false;
 const second=await h.vault.register("pending@example.invalid","cd".repeat(32));assert.notEqual(second.accountId,first.accountId);assert.equal(second.accountGeneration,"1");assert.equal(second.verificationRequired,false);await assert.rejects(h.vault.accountLifecycle().verifyEmail(old.accountId,old),denies("registration_expired"));await h.vault.login("pending@example.invalid","cd".repeat(32));h.policy.allowRegistration=true;h.advance(1000);await assert.rejects(h.vault.register("pending@example.invalid",clientCredential),denies("account_exists"));
}));
for(const phase of ["decision","activation"] as const)test(`真实SQLite ${phase}写失败持久proof-ready；重启/正确login恢复，错误密码不激活`,async()=>{
 const dir=mkdtempSync(join(tmpdir(),"harmonia-registration-fault-")),path=join(dir,"synthetic.sqlite"),sql=new NodeSql(path);let armed=false,failActivation=false,failed=false,clock=now;const mails:Email[]=[];
 const wrapped:Sql={rows:(q,p)=>sql.rows(q,p),transaction:f=>sql.transaction(f),execute:(q,p)=>{if(armed&&!failed&&q.startsWith("UPDATE instance_registration SET completed=1")){if(phase==="decision"){failed=true;throw new Error("synthetic decision failure");}failActivation=true;}if(failActivation&&q.startsWith("UPDATE accounts SET data=")){failed=true;failActivation=false;throw new Error("synthetic activation failure");}sql.execute(q,p);}};
 const store=new SqlStore(wrapped,undefined,undefined,()=>clock),life=new AccountLifecycle(store,wasmPassword,()=>clock,{send:async m=>{mails.push(m);}});let reopened:ReturnType<typeof nodeStore>|undefined;
 try{const r=await life.register("fault@example.invalid",clientCredential,{allowRegistration:false,requireEmailVerification:true}),p=emailVerification(life, mails[0]!);armed=true;await assert.rejects(life.verifyEmail(r.accountId,p),/synthetic/);assert.equal(store.read(r.accountId)!.registrationAdmission!.state,"proof-ready");assert.equal((await store.registrationAuthority.info()).firstCompleted,phase==="activation");
 reopened=nodeStore(path,()=>clock);clock+=1000;const vault=new VaultService(reopened.store,{allowRegistration:false,requireEmailVerification:false},()=>clock);await assert.rejects(vault.login("fault@example.invalid","ee".repeat(32)),denies("unauthorized"));assert.equal(reopened.store.read(r.accountId)!.registrationAdmission!.state,"proof-ready");await assert.rejects(new AccountLifecycle(reopened.store,wasmPassword,()=>clock,{send:async()=>{}}).register("fault@example.invalid",clientCredential,{allowRegistration:true,requireEmailVerification:false}),denies("account_exists"));
 await vault.login("fault@example.invalid",clientCredential);assert.equal(reopened.store.read(r.accountId)!.registrationAdmission!.state,"complete");assert.equal((await reopened.store.registrationAuthority.info()).firstCompleted,true);assert.equal((await vault.login("fault@example.invalid",clientCredential)).accountId,r.accountId);
 }finally{reopened?.sql.close();sql.close();rmSync(dir,{recursive:true,force:true});}
});
test("真实SQLite拒绝缺失注册字段的旧账号，读取不补写或接管实例", async () => harness(async h => {
  const account = await fixtureAccount("obsolete-account", "obsolete@example.invalid");
  h.store.create(account);
  const sql = new NodeSql(h.path);
  try {
    for (const field of ["verificationRequiredAtRegistration", "registrationAdmission"]) {
      const malformed = structuredClone(account) as unknown as Record<string, unknown>;
      delete malformed[field];
      const raw = JSON.stringify(malformed);
      sql.execute("UPDATE accounts SET data=? WHERE id=?", [raw, account.id]);
      assert.throws(() => h.store.read(account.id), denies("registration_state_invalid"));
      await assert.rejects(h.vault.login(account.email, clientCredential), denies("registration_state_invalid"));
      assert.equal(sql.rows("SELECT data FROM accounts WHERE id=?", [account.id])[0]!.data, raw);
      assert.equal((await h.store.registrationAuthority.info()).firstCompleted, false);
    }
  } finally { sql.close(); }
}));

test("真实NodeTCP closed无验证并发只激活一个首号，失败候选不能登录",async()=>harness(async h=>{
 const emails=["quick-one@example.invalid","quick-two@example.invalid"],results=await Promise.all(emails.map(email=>h.request("/v1/register",{email,credential:clientCredential})));assert.deepEqual(results.map(r=>r.status).sort(),[200,403]);const accepted=results.findIndex(r=>r.status===200);assert.equal((await h.request("/v1/login",{email:emails[accepted],credential:clientCredential})).status,200);const loser=h.store.byEmail(emails[1-accepted]!);assert.equal((await h.request("/v1/login",{email:emails[1-accepted],credential:clientCredential})).status,loser?403:401);if(loser)assert.equal(h.store.read(loser)!.registrationAdmission!.state,"proof-ready");assert.equal((await h.store.registrationAuthority.info()).firstCompleted,true);
},{allowRegistration:false,requireEmailVerification:false}));
