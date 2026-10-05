import { afterEmailCooldown, httpResetProof, type EmailVerification, verificationCode } from "./email-proof.js";
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync,rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build } from "esbuild";
import { Miniflare } from "miniflare";
import { ed25519,x25519 } from "@noble/curves/ed25519.js";
import { fixtureAccount,clientCredential,seeds,recoveryKeys,recoverySeed } from "./fixtures.js";
import { trustRootPayload } from "../src/trust-root.js";
import type { Email } from "../src/email-transport.js";
import type { SyntheticVault,SyntheticRegistry } from "./worker-harness.js";
type RuntimeResponse=Awaited<ReturnType<Miniflare["dispatchFetch"]>>;
const b64=(v:Uint8Array)=>Buffer.from(v).toString("base64url"),sign=(v:unknown,k:Uint8Array)=>b64(ed25519.sign(new TextEncoder().encode(JSON.stringify(v)),k));
async function harness(run:(h:{mf:Miniflare;post:(p:string,b:unknown)=>Promise<RuntimeResponse>;info:()=>Promise<any>;vault:(id:string)=>Promise<DurableObjectStub<SyntheticVault>>;registry:()=>Promise<DurableObjectStub<SyntheticRegistry>>;set:(allow:boolean,verify:boolean)=>Promise<void>})=>Promise<void>){
 const dir=mkdtempSync(join(tmpdir(),"harmonia-registration-worker-")),built=await build({entryPoints:["test/worker-harness.ts"],absWorkingDir:process.cwd(),bundle:true,write:false,format:"esm",platform:"browser",target:"es2023",external:["cloudflare:workers","node:*"],define:{Buffer:"Buffer"},banner:{js:'import { Buffer } from "node:buffer";'}});
 const options={modules:true as const,script:built.outputFiles[0]!.text,compatibilityDate:"2026-07-30",compatibilityFlags:["nodejs_compat"],durableObjects:{INSTANCES:{className:"SyntheticRegistry",useSQLite:true},REGISTRATION_FIXTURES:{className:"SyntheticRegistry",useSQLite:true},ACCOUNTS:{className:"SyntheticVault",useSQLite:true},FIXTURES:{className:"SyntheticVault",useSQLite:true}},d1Databases:{DIRECTORY:"directory"},durableObjectsPersist:join(dir,"objects"),d1Persist:join(dir,"directory"),bindings:{ALLOW_REGISTRATION:"false",REQUIRE_EMAIL_VERIFICATION:"true",EMAIL_FROM:"noreply@example.invalid"}};
 const mf=new Miniflare(options),post=(p:string,b:unknown)=>afterEmailCooldown(()=>mf.dispatchFetch(`https://selfhost.example.invalid${p}`,{method:"POST",headers: {"Harmonia-Protocol-Major":"2", "content-type":"application/json"},body:JSON.stringify(b)}));
 try{await run({mf,post,info:async()=>{const r=await mf.dispatchFetch("https://selfhost.example.invalid/instance-info",{headers:{"Harmonia-Protocol-Major":"2"}});assert.equal(r.status,200,await r.clone().text());assert.equal(r.headers.get("cache-control"),"no-store");return await r.json();},vault:async id=>(await mf.getDurableObjectNamespace("FIXTURES")).getByName(id) as unknown as DurableObjectStub<SyntheticVault>,registry:async()=>(await mf.getDurableObjectNamespace("REGISTRATION_FIXTURES")).getByName("harmonia-instance-v1") as unknown as DurableObjectStub<SyntheticRegistry>,set:async(allow,verify)=>{await mf.setOptions({...options,bindings:{...options.bindings,ALLOW_REGISTRATION:String(allow),REQUIRE_EMAIL_VERIFICATION:String(verify)}});}});}finally{await mf.dispose();rmSync(dir,{recursive:true,force:true});}
}
const complete=(post:(p:string,b:unknown)=>Promise<RuntimeResponse>,p:EmailVerification)=>post(`/v1/accounts/${p.accountId}/email-verification/complete`,{accountGeneration:p.accountGeneration,code:p.code});
test("真实workerd closed非独占pending/并发首号CAS、冻结verify、终态丢回应login、reset及删空永久关闭",{timeout:180000},async()=>harness(async h=>{
 const i=await h.info();assert.deepEqual(Object.keys(i).sort(),["allowRegistration","emailVerificationRequired","initialRegistrationAvailable","product","protocol","status"]);assert.equal(i.product,"harmonia");assert.deepEqual(i.protocol.supportedMajors,[2]);assert.equal(i.initialRegistrationAvailable,true);
 const accounts=[] as {accountId:string}[];for(const email of ["first@example.invalid","other@example.invalid"]){const r=await h.post("/v1/register",{email,credential:clientCredential});assert.equal(r.status,200,await r.clone().text());accounts.push(await r.json() as {accountId:string});}
 assert.equal((await h.info()).initialRegistrationAvailable,true);await h.set(false,false);assert.equal((await h.info()).emailVerificationRequired,false);
 const proofs=[] as EmailVerification[];for(const a of accounts)proofs.push(verificationCode((await (await h.vault(a.accountId)).mails())[0]!, a.accountId));assert.equal((await h.post("/v1/login",{email:"first@example.invalid",credential:clientCredential})).status,401);
 const finished=await Promise.all(proofs.map(p=>complete(h.post,p)));assert.deepEqual(finished.map(r=>r.status).sort(),[200,403]);const index=finished.findIndex(r=>r.status===200),winner=proofs[index]!,email=index===0?"first@example.invalid":"other@example.invalid";
 assert.equal((await complete(h.post,winner)).status,401);assert.equal((await h.post("/v1/login",{email,credential:"ee".repeat(32)})).status,401);assert.equal((await h.post("/v1/login",{email,credential:clientCredential})).status,200);assert.equal((await h.info()).initialRegistrationAvailable,false);
 assert.equal((await h.post("/v1/account-reset/request",{email:index===0?"other@example.invalid":"first@example.invalid"})).status,403);
 const loserIndex=1-index,loser=proofs[loserIndex]!,loserEmail=index===0?"other@example.invalid":"first@example.invalid";await h.set(true,false);assert.equal((await h.post("/v1/login",{email:loserEmail,credential:"ee".repeat(32)})).status,401);assert.equal((await (await h.vault(loser.accountId)).account(loser.accountId))!.registrationAdmission!.state,"proof-ready");assert.equal((await h.post("/v1/login",{email:loserEmail,credential:clientCredential})).status,200);assert.equal((await (await h.registry()).info()).winnerAccountId,winner.accountId);await h.set(false,false);
 assert.equal((await h.post("/v1/account-reset/request",{email})).status,200);const reset=await httpResetProof(h.post, (await (await h.vault(winner.accountId)).mails()).at(-1)!);assert.equal((await h.post(`/v1/accounts/${winner.accountId}/account-reset/complete`,{accountGeneration:"1",challengeId:"not-a-reset-challenge",token:Buffer.alloc(32, 7).toString("base64url"),newCredential:"cd".repeat(32),confirmation:"DELETE_OLD_VAULT"})).status,401);
 const done=await h.post(`/v1/accounts/${winner.accountId}/account-reset/complete`,{accountGeneration:"1",challengeId:reset.challengeId,token:reset.token,newCredential:"cd".repeat(32),confirmation:"DELETE_OLD_VAULT"});assert.equal(done.status,200,await done.clone().text());assert.equal((await (await h.vault(winner.accountId)).account(winner.accountId))!.verificationRequiredAtRegistration,true);
 await h.set(true,false);const optional=await h.post("/v1/register",{email:"optional@example.invalid",credential:clientCredential});assert.equal(optional.status,200);const optionalId=(await optional.json() as {accountId:string}).accountId;assert.equal((await (await h.vault(optionalId)).account(optionalId))!.verified,false);await h.set(false,true);assert.equal((await h.post("/v1/login",{email:"optional@example.invalid",credential:clientCredential})).status,200);
 for(const a of [...accounts,{accountId:optionalId}])await (await h.vault(a.accountId)).removeAccount(a.accountId);await h.set(false,true);assert.equal((await h.info()).initialRegistrationAvailable,false);assert.equal((await h.post("/v1/register",{email:"new@example.invalid",credential:clientCredential})).status,403);
 const db=await h.mf.getD1Database("DIRECTORY");assert.deepEqual((await db.prepare("PRAGMA table_info(account_directory)").all<{name:string}>()).results.map(r=>r.name),["email","account_id"]);
}));
for(const fault of ["decision","activation"] as const)test(`真实workerd ${fault}持久失败/重启原短码补全，wrongcredential不可激活`,{timeout:120000},async()=>harness(async h=>{
 const r=await h.post("/v1/register",{email:"crash@example.invalid",credential:clientCredential});assert.equal(r.status,200);const id=(await r.json() as {accountId:string}).accountId,p=verificationCode((await (await h.vault(id)).mails())[0]!, id);
 if(fault==="decision")await (await h.registry()).arm();else await (await h.vault(id)).activationFault();const failed=await complete(h.post,p);assert.equal(failed.status,500);assert.equal((await (await h.vault(id)).account(id))!.registrationAdmission!.state,"proof-ready");assert.equal((await h.info()).initialRegistrationAvailable,fault==="decision");
 await h.set(false,false);assert.equal((await h.post("/v1/login",{email:"crash@example.invalid",credential:"ee".repeat(32)})).status,401);assert.equal((await (await h.vault(id)).account(id))!.registrationAdmission!.state,"proof-ready");
 if(fault==="decision")await (await h.registry()).disarm();else await (await h.vault(id)).clearFault();assert.equal((await complete(h.post,p)).status,200);assert.equal((await h.post("/v1/login",{email:"crash@example.invalid",credential:clientCredential})).status,200);
}));
test("真实workerd拒绝缺注册记录的旧账号，孤D1不接管首次注册", { timeout: 120000 }, async () => harness(async h => {
  const account = await fixtureAccount("obsolete-account", "obsolete@example.invalid");
  const malformed = structuredClone(account) as unknown as Record<string, unknown>;
  delete malformed.registrationAdmission;
  assert.equal((await h.post("/test/seed", malformed)).status, 200);
  assert.equal((await h.post("/v1/login", { email: account.email, credential: clientCredential })).status, 400);
  assert.equal((await h.info()).initialRegistrationAvailable, true);
  assert.equal(Object.hasOwn((await (await h.vault(account.id)).account(account.id))!, "registrationAdmission"), false);
}));

test("真实workerd拒绝已移除邮箱验证解析路径和旧字段", {timeout: 120000}, async () => harness(async h => {
  const email = 'code-contract@example.invalid';
  assert.equal((await h.post('/v1/email-verification/resolve', { email, code: '012345' })).status, 404);
  const response = await h.post('/v1/register', { email, credential: clientCredential });
  assert.equal(response.status, 200);
  const { accountId } = await response.json() as { accountId: string };
  const code = verificationCode((await (await h.vault(accountId)).mails())[0]!, accountId);
  assert.equal((await h.post(`/v1/accounts/${accountId}/email-verification/complete`, { accountGeneration: '1', challengeId: 'obsolete', token: code.code })).status, 400);
  assert.equal((await complete(h.post, code)).status, 200);
}));
