import test from "node:test";
import assert from "node:assert/strict";
import { ed25519 } from "@noble/curves/ed25519.js";
import { nodeHarness, workerHarness, setupEnvironments, freshRecovery, recoverChallenge, revoke, seeds, sign, b64, type Harness } from "./recovery-origin-fixtures.js";
import { issuerAuthorityHash } from "../src/issuer-proof.js";
import { verifyIssuerOriginGraph } from "../src/issuer-origin.js";
import { environmentOriginHash, environmentRights } from "../src/environment-origin.js";
import { environmentChangeBytes } from "../src/environments.js";
import { grantBytes } from "../src/protocol.js";
import { grantKey, type SignedGrant } from "../src/model.js";
const path="/recovery-vault?capability=issuer-origin-v1";
function verifySnapshot(h:Harness,data:any,expectedTargets=2):void {
  assert.equal(data.rotationRequired,true);assert.equal(data.originalInitialization.sequence,1);assert.ok(data.issuerEvidence);assert.equal(data.issuerEvidence.targets.length,expectedTargets);assert.deepEqual(data.issuerEvidence.path,[]);
  const graph=verifyIssuerOriginGraph(data.issuerEvidence),initial=new Set(data.originalInitialization.proposal.environments.map((environment:any)=>issuerAuthorityHash(environment.grant)));
  for(const [hash,node] of graph.authorities)if(!node.parentHash)assert.equal(initial.has(hash),true);
  for(const target of data.issuerEvidence.targets){const g=graph.authorities.get(target.authorityHash)!.grant.grant,env=data.environments.find((environment:any)=>environment.environmentId===target.environmentId);assert.equal(g.environmentId,env.environmentId);assert.equal(g.keyVersion,env.keyVersion);}
  for(const origin of data.issuerEvidence.origins)for(const row of [...origin.origin.before,...origin.origin.after])assert.deepEqual(environmentRights(graph.authorities.get(row.grantHash)!.grant),row);
  assert.equal(graph.identities.get("device-C")!.signing,b64(ed25519.getPublicKey(seeds.C!)));
  assert.equal(graph.origins.size,2);assert.equal(data.events.length,2);assert.deepEqual(data.events.map((event:any)=>[event.mutation.mutation.environmentId,event.mutation.mutation.keyVersion]).sort(),[["env-fixture","2"],["environment-Y","1"]]);
  for(const event of data.events)assert.deepEqual(graph.authorities.get(issuerAuthorityHash(event.authorization))!.grant,event.authorization);
  const serialized=JSON.stringify(data.issuerEvidence);for(const field of ["labelPayload","mutations","recoveryEnvelope","SOURCE_X","SOURCE_Y","passwordVerifier","email","tokenHash"])assert.equal(serialized.includes(field),false);
  assert.equal(data.accountId,h.account.id);
}
for(const [runtime,create] of [["Node TCP",nodeHarness],["workerd HTTP",workerHarness]] as const){
  test(`${runtime} fresh恢复核新Y与跨版本X完整历史，原root撤销不阻塞且targets不授管理权`,{timeout:120000},async()=>{
    const h=await create();try {
      const setup=await setupEnvironments(h);await revoke(h,"A");const recovery=await freshRecovery(h);
      const old=await h.send("/recovery-vault","GET",undefined,"R");assert.equal(old.status,200,JSON.stringify(old.data));assert.equal(Object.hasOwn(old.data,"originalInitialization"),false);assert.equal(Object.hasOwn(old.data,"issuerEvidence"),false);
      const result=await h.send(path,"GET",undefined,"R");assert.equal(result.status,200,JSON.stringify(result.data));verifySnapshot(h,result.data);
      assert.equal(result.data.publicDevices.find((device:any)=>device.id==="device-A").revoked,true);assert.equal(result.data.currentGrants.some((grant:SignedGrant)=>grant.grant.subjectDeviceId==="device-A"),false);
      for(const packet of setup.packets)assert.equal(JSON.stringify(result.data.issuerEvidence).includes(packet),false);
      const parent=await h.send("/pull?after=0&capability=issuer-origin-v1","GET",undefined,"R");assert.equal(parent.status,401);
      const enrollment=await h.send("/pairings-v3","POST",{idempotencyKey:"restricted-enrollment",deviceId:"device-D",signingPublicKey:b64(ed25519.getPublicKey(Buffer.alloc(32,4))),receivingPublicKey:b64(Buffer.alloc(32,12)),approverDeviceId:"device-B",certificateVersion:"3",capabilities:["issuer-origin-v1"]},"R");assert.equal(enrollment.status,401);
      assert.equal((await h.send(path,"GET",undefined,"login")).status,403);
      assert.equal((await h.send(path,"GET",undefined,"R","2")).status,401);
      assert.equal((await h.send(path,"GET",undefined,"R","1","another-account")).status,401);
      assert.equal((await h.send("/recovery-vault?capability=issuer-origin-v1&capability=issuer-origin-v1","GET",undefined,"R")).status,400);
      assert.equal(JSON.stringify(result.data).includes(recovery.token),false);
    }finally{await h.close();}
  });
  test(`${runtime} 全部设备撤销且currentGrants空，受限恢复仍从接受历史验证每现存环境`,{timeout:120000},async()=>{
    const h=await create();try {
      await setupEnvironments(h);await revoke(h,"A");await revoke(h,"C");await revoke(h,"B");await freshRecovery(h);
      const response=await h.send(path,"GET",undefined,"R");assert.equal(response.status,200,JSON.stringify(response.data));verifySnapshot(h,response.data);assert.deepEqual(response.data.currentGrants,[]);assert.equal(response.data.publicDevices.every((device:any)=>device.revoked),true);
      assert.equal((await h.send("/boot-challenges","POST",{deviceId:"device-B",accountGeneration:"1"},"login")).status,403);
      const rejected=await h.send("/issuer-evidence?environmentId=environment-Y&capability=issuer-origin-v1","GET",undefined,"B");assert.equal(rejected.status,403);assert.equal(rejected.data.error,"device_untrusted");
    }finally{await h.close();}
  });
  test(`${runtime} currentGrants全部none仍能恢复历史，不把旧targets恢复为当前权限`,{timeout:120000},async()=>{
    const h=await create();try {
      const setup=await setupEnvironments(h);await revoke(h,"A");
      for(const [current,gen,id] of [[setup.writer,"2","none-C"],[setup.newX,"3","none-B-X"],[setup.newY,"2","none-B-Y"]] as const){const g=structuredClone(current.grant);Object.assign(g,{grantGeneration:gen,role:"none",envelope:"",idempotencyKey:id});assert.equal((await h.send("/grants","POST",{grant:g,signature:b64(ed25519.sign(grantBytes(g),seeds.B!))},"B")).status,200);}
      await freshRecovery(h);const response=await h.send(path,"GET",undefined,"R");assert.equal(response.status,200,JSON.stringify(response.data));verifySnapshot(h,response.data);assert.equal(response.data.currentGrants.length,3);assert.equal(response.data.currentGrants.every((signed:SignedGrant)=>signed.grant.role==="none"),true);
      assert.equal((await h.send("/boot-challenges","POST",{deviceId:"device-B",accountGeneration:"1"},"login")).data.error,"no_current_grant");
      const inactive=await h.send("/pull?after=0&capability=issuer-origin-v1","GET",undefined,"B");assert.ok(inactive.data.issuerEvidence);assert.deepEqual(inactive.data.events,[]);assert.equal(inactive.data.grants.every((g:SignedGrant)=>g.grant.role==="none"),true);
    }finally{await h.close();}
  });
  test(`${runtime} 所有现角色已到期不阻塞历史恢复，也不会恢复设备在线授权`,{timeout:120000},async()=>{
    const h=await create();try {
      const setup=await setupEnvironments(h);await revoke(h,"A");const deadline=Math.floor(Date.now()/1000)+2;
      for(const [current,gen,id] of [[setup.writer,"2","expire-C"],[setup.newX,"3","expire-B-X"],[setup.newY,"2","expire-B-Y"]] as const){const g=structuredClone(current.grant);Object.assign(g,{grantGeneration:gen,expiresAt:String(deadline),idempotencyKey:id});assert.equal((await h.send("/grants","POST",{grant:g,signature:b64(ed25519.sign(grantBytes(g),seeds.B!))},"B")).status,200);}
      await new Promise(resolve=>setTimeout(resolve,Math.max(1,deadline*1000-Date.now()+20)));await freshRecovery(h);
      const response=await h.send(path,"GET",undefined,"R");assert.equal(response.status,200,JSON.stringify(response.data));verifySnapshot(h,response.data);assert.equal(response.data.currentGrants.every((signed:SignedGrant)=>Number(signed.grant.expiresAt)<=Math.floor(Date.now()/1000)),true);
      assert.equal((await h.send("/boot-challenges","POST",{deviceId:"device-B",accountGeneration:"1"},"login")).data.error,"no_current_grant");
      const refresh=await h.send("/pull?after=0&scope=authorizations&capability=issuer-origin-v1","GET",undefined,"B");assert.equal(refresh.status,200);assert.ok(refresh.data.issuerEvidence);assert.deepEqual(refresh.data.events,[]);
    }finally{await h.close();}
  });
}
test("Node 恢复缺来源/历史/双签身份、伪genesis、无效写签或内层change不匹配均拒且不返回部分数据",async()=>{
  const h=await nodeHarness();try {
    await setupEnvironments(h);await revoke(h,"A");await freshRecovery(h);const original=h.read();
    const attacks:[string,(a:ReturnType<Harness["read"]>)=>void][]=[
      ["issuer_origin_unaccepted",a=>{delete a.environmentHistory![0]!.origin;}],
      ["issuer_authority_unaccepted",a=>{const originalB=a.grantHistory!.find(event=>event.grant.grant.environmentId==="env-fixture"&&event.grant.grant.subjectDeviceId==="device-B"&&event.grant.grant.keyVersion==="1")!;a.grantHistory=a.grantHistory!.filter(event=>issuerAuthorityHash(event.grant)!==issuerAuthorityHash(originalB.grant));}],
      ["issuer_archive_mismatch",a=>{delete a.deviceEnrollments!["device-C"];}],
      ["issuer_environment_evidence_required",a=>{const grant=a.grants[grantKey("environment-Y","device-B")]!,row=a.grantHistory!.find(event=>issuerAuthorityHash(event.grant)===issuerAuthorityHash(grant))!;row.authorization=null;delete row.originHash;}],
      ["issuer_origin_unaccepted",a=>{const event=a.environmentHistory![0]!;event.change.change.labelPayload=b64(Buffer.alloc(40,111));event.change.signature=b64(ed25519.sign(environmentChangeBytes(event.change.change),seeds.B!));}],
      ["signature_invalid",a=>{a.events.find(event=>event.mutation.mutation.environmentId==="environment-Y")!.mutation.mutation.payload=b64(Buffer.alloc(40,112));}],
      ["issuer_environment_evidence_required",a=>{const g=structuredClone(a.vaultInitializations!["original-chain-initialization"]!.proposal.environments[0]!.grant.grant);Object.assign(g,{environmentId:"forged-genesis",idempotencyKey:"forged-new-root"});const grant={grant:g,signature:b64(ed25519.sign(grantBytes(g),seeds.A!))};a.environments["forged-genesis"]={id:"forged-genesis",keyVersion:"1",recoveryKeyVersion:"1",recoveryGeneration:"1",recoveryEnvelope:b64(Buffer.alloc(80,113))};a.grants[grantKey("forged-genesis","device-A")]=grant;a.grantHistory!.unshift({sequence:1,grant,authorization:null});}]
    ];
    for(const [code,attack] of attacks){h.change(a=>attack(a));const denied=await h.send(path,"GET",undefined,"R");assert.equal(denied.status,403,JSON.stringify(denied.data));assert.equal(denied.data.error,code);assert.deepEqual(Object.keys(denied.data),["error"]);h.change(a=>{Object.assign(a,structuredClone(original));});}
    const restored=await h.send(path,"GET",undefined,"R");assert.equal(restored.status,200,JSON.stringify(restored.data));verifySnapshot(h,restored.data);
  }finally{await h.close();}
});
test("Node SQLite恢复nonce完成与graph读取UPDATE失败整笔回滚，旧代际立即拒",async()=>{
  const h=await nodeHarness();try {
    await setupEnvironments(h);await revoke(h,"A");const proof=await recoverChallenge(h),before=JSON.stringify(h.read()),restore=h.failNextCommit!();
    try{const failure=await h.send("/recovery-sessions","POST",{accountGeneration:"1",challengeId:proof.challenge.challengeId,signature:proof.signature},"login");assert.equal(failure.status,500);}finally{restore();}
    assert.equal(JSON.stringify(h.read()),before);
    const complete=await h.send("/recovery-sessions","POST",{accountGeneration:"1",challengeId:proof.challenge.challengeId,signature:proof.signature},"login");assert.equal(complete.status,200,JSON.stringify(complete.data));h.setToken("R",complete.data.token);
    assert.equal((await h.send("/recovery-sessions","POST",{accountGeneration:"1",challengeId:proof.challenge.challengeId,signature:proof.signature},"login")).status,403);
    const persisted=JSON.stringify(h.read()),undo=h.failNextCommit!();try{assert.equal((await h.send(path,"GET",undefined,"R")).status,500);}finally{undo();}assert.equal(JSON.stringify(h.read()),persisted);
    const success=await h.send(path,"GET",undefined,"R");assert.equal(success.status,200);verifySnapshot(h,success.data);
    h.change(a=>{a.generation="2";a.devices={};a.environments={};a.grants={};a.events=[];a.sessions=[];a.recoverySigningPublicKey=null;a.recoveryReceivingPublicKey=null;delete a.trustRoot;a.vaultInitializations={};});
    assert.equal((await h.send(path,"GET",undefined,"R")).data.error,"generation_stale");
  }finally{await h.close();}
});
