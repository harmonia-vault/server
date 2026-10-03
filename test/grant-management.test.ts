import test from "node:test";
import assert from "node:assert/strict";
import { ed25519 } from "@noble/curves/ed25519.js";
import { grantKey, type Grant, type SignedGrant } from "../src/model.js";
import { grantBytes, mutationBytes } from "../src/protocol.js";
import { tokenHash } from "../src/service.js";
import { deviceRevocationBytes } from "../src/environments.js";
import { environmentRights } from "../src/environment-origin.js";
import { issuerAuthorityHash } from "../src/issuer-proof.js";
import { verifyIssuerOriginGraph } from "../src/issuer-origin.js";
import type { ManagementControl } from "../src/grant-management.js";
import { b64, seeds, sign, vector, resign, nodeHarness, workerHarness, setupEnvironments, type Harness } from "./recovery-origin-fixtures.js";
const controlPath = "/grant-management?environmentId=env-fixture&capability=issuer-origin-v1";
const signedGrant = (grant: Grant): SignedGrant => ({grant,signature:b64(ed25519.sign(grantBytes(grant), seeds[grant.issuerDeviceId.slice(-1)]!))});
const receipt = (signed:SignedGrant) => tokenHash(b64(grantBytes(signed.grant))+"."+signed.signature);
const row = (c:ManagementControl,id:string) => c.subjects.find(subject=>subject.deviceId===id)!;
async function control(h:Harness):Promise<ManagementControl>{const response=await h.send(controlPath,"GET");assert.equal(response.status,200,JSON.stringify(response.data));return response.data;}
async function rotateX(h:Harness, c:ManagementControl):Promise<number>{
  const active=c.subjects.map(subject=>subject.currentGrant).filter((signed):signed is SignedGrant=>!!signed&&signed.grant.role!=="none"&&signed.grant.keyVersion===c.keyVersion&&(signed.grant.expiresAt==="0"||BigInt(signed.grant.expiresAt)>BigInt(Math.floor(Date.now()/1000)))).sort((a,b)=>a.grant.subjectDeviceId<b.grant.subjectDeviceId?-1:1);
  const actor=row(c,"device-B").currentGrant!,keyVersion=String(BigInt(c.keyVersion)+1n),grants=active.map(signed=>signedGrant({...signed.grant,issuerDeviceId:"device-B",keyVersion,grantGeneration:String(BigInt(signed.grant.grantGeneration)+1n),idempotencyKey:`management-rotate-${signed.grant.subjectDeviceId}`}));
  const mutation={accountId:c.accountId,accountGeneration:"1",deviceId:"device-B",environmentId:"env-fixture",keyVersion,grantGeneration:grants.find(g=>g.grant.subjectDeviceId==="device-B")!.grant.grantGeneration,operation:"put" as const,idempotencyKey:"management-reencrypt",name:"SOURCE_X",payload:b64(Buffer.alloc(40,114))};
  const packet=structuredClone(vector.rotation);Object.assign(packet.change,{previousKeyVersion:c.keyVersion,keyVersion,authorityKeyVersion:c.keyVersion,authorityGrantGeneration:actor.grant.grantGeneration,expectedSequence:String(c.sequence),idempotencyKey:"management-rotate-X",grants,mutations:[{mutation,signature:b64(ed25519.sign(mutationBytes(mutation),seeds.B!))}],labelPayload:""});
  Object.assign(packet.origin.origin,{previousKeyVersion:c.keyVersion,keyVersion,authorityKeyVersion:c.keyVersion,authorityGrantGeneration:actor.grant.grantGeneration,authorityHash:issuerAuthorityHash(actor),expectedSequence:String(c.sequence),idempotencyKey:packet.change.idempotencyKey,before:active.map(environmentRights),after:grants.map(environmentRights)});resign(packet);
  const response=await h.send("/environment-changes-v2","POST",packet);assert.equal(response.status,200,JSON.stringify(response.data));return response.data.sequence;
}
for(const [runtime,create] of [["Node真实TCP",nodeHarness],["本地workerd SQLiteDO",workerHarness]] as const){
  test(`${runtime} 独立授权管理包含未授环境身份、none/过期/旧KV和最高代际，不泄数据`,{timeout:120000},async()=>{
    const h=await create();try{
      const setup=await setupEnvironments(h),initial=await control(h);assert.deepEqual(Object.keys(initial).sort(),["accountGeneration","accountId","environmentId","issuerEvidence","keyVersion","sequence","subjects"]);assert.equal(initial.keyVersion,"2");assert.equal(row(initial,"device-C").highestGrantGeneration,"0");assert.equal(row(initial,"device-C").currentGrant,null);
      const graph=verifyIssuerOriginGraph(initial.issuerEvidence);assert.equal(graph.identities.get("device-C")!.signing,row(initial,"device-C").signingPublicKey);assert.equal(initial.issuerEvidence.targets.length,1);assert.equal(initial.issuerEvidence.targets[0]!.authorityHash,issuerAuthorityHash(row(initial,"device-B").currentGrant!));
      for(const value of setup.packets)assert.equal(JSON.stringify(initial).includes(value),false);
      const original={...setup.newX.grant,subjectDeviceId:"device-C",subjectSigningPublicKey:row(initial,"device-C").signingPublicKey,subjectReceivingPublicKey:row(initial,"device-C").receivingPublicKey,expiresAt:String(Math.floor(Date.now()/1000)+3600)};
      for(const [generation,role] of [["1","ro"],["2","rw"],["3","admin"],["4","none"]] as const){const packet=signedGrant({...original,grantGeneration:generation,role,envelope:role==="none"?"":b64(Buffer.alloc(80,115)),idempotencyKey:`management-C-${generation}`});const response=await h.send("/grants","POST",packet);assert.equal(response.status,200,JSON.stringify(response.data));const c=await control(h);assert.equal(row(c,"device-C").highestGrantGeneration,generation);assert.equal(row(c,"device-C").currentGrant!.grant.role,role);assert.equal(c.issuerEvidence.authorities.some(a=>a.grant.grant.role==="none"),false);assert.equal((await h.send(`/grant-status?idempotencyKey=${packet.grant.idempotencyKey}`,"GET")).data.contentHash,await receipt(packet));}
      const deadline=Math.floor(Date.now()/1000)+2,expired=signedGrant({...original,grantGeneration:"5",role:"ro",expiresAt:String(deadline),idempotencyKey:"management-expiry-C",envelope:b64(Buffer.alloc(80,116))});assert.equal((await h.send("/grants","POST",expired)).status,200);await new Promise(resolve=>setTimeout(resolve,Math.max(1,deadline*1000-Date.now()+20)));
      const afterExpiry=await control(h);assert.equal(row(afterExpiry,"device-C").highestGrantGeneration,"5");assert.equal(row(afterExpiry,"device-C").currentGrant!.grant.expiresAt,String(deadline));const active=await h.send("/issuer-evidence?environmentId=env-fixture&capability=issuer-origin-v1","GET");assert.equal(active.status,200);assert.equal(active.data.grants.some((g:SignedGrant)=>g.grant.subjectDeviceId==="device-C"),false);
      await rotateX(h,afterExpiry);const old=await control(h);assert.equal(old.keyVersion,"3");assert.equal(row(old,"device-C").currentGrant!.grant.keyVersion,"2");assert.equal(row(old,"device-C").highestGrantGeneration,"5");
      const restored=signedGrant({...original,keyVersion:"3",grantGeneration:"6",role:"rw",idempotencyKey:"management-restored-C",envelope:b64(Buffer.alloc(80,117))});assert.equal((await h.send("/grants","POST",restored)).status,200);assert.equal(row(await control(h),"device-C").highestGrantGeneration,"6");
    }finally{await h.close();}
  });
  test(`${runtime} 本人原授权收据降权后仍精确可查，错会话/旧代际/跨账号与伪幂等拒绝`,{timeout:120000},async()=>{
    const h=await create();try{
      const setup=await setupEnvironments(h),packet=signedGrant({...setup.writer.grant,grantGeneration:"2",role:"ro",idempotencyKey:"management-lost-ack"});const result=await h.send("/grants","POST",packet);assert.equal(result.status,200,JSON.stringify(result.data));const expected={idempotencyKey:packet.grant.idempotencyKey,accepted:true,sequence:result.data.sequence,contentHash:await receipt(packet)};
      assert.deepEqual((await h.send(`/grant-status?idempotencyKey=${packet.grant.idempotencyKey}`,"GET")).data,expected);assert.deepEqual((await h.send(`/grant-status?idempotencyKey=${packet.grant.idempotencyKey}`,"GET",undefined,"C")).data,{idempotencyKey:packet.grant.idempotencyKey,accepted:false});
      const conflict=signedGrant({...packet.grant,role:"rw"});assert.equal((await h.send("/grants","POST",conflict)).status,409);assert.deepEqual((await h.send(`/grant-status?idempotencyKey=${packet.grant.idempotencyKey}`,"GET")).data,expected);
      const downgrade=signedGrant({...setup.newX.grant,issuerDeviceId:"device-A",grantGeneration:"3",role:"ro",idempotencyKey:"management-downgrade-B"});assert.equal((await h.send("/grants","POST",downgrade,"A")).status,200);assert.equal((await h.send(controlPath,"GET")).status,403);assert.deepEqual((await h.send(`/grant-status?idempotencyKey=${packet.grant.idempotencyKey}`,"GET")).data,expected);
      for(const path of["/grant-status","/grant-status?idempotencyKey=","/grant-status?idempotencyKey=management-lost-ack&idempotencyKey=management-lost-ack","/grant-status?idempotencyKey=management-lost-ack&deviceId=device-B",controlPath+"&environmentId=env-fixture",controlPath+"&extra=directory"]){assert.equal((await h.send(path,"GET")).status,400);}
      assert.equal((await h.send(`/grant-status?idempotencyKey=${packet.grant.idempotencyKey}`,"GET",undefined,"login")).status,401);assert.equal((await h.send(`/grant-status?idempotencyKey=${packet.grant.idempotencyKey}`,"GET",undefined,"B","2")).status,401);assert.equal((await h.send(`/grant-status?idempotencyKey=${packet.grant.idempotencyKey}`,"GET",undefined,"B","1","other-account")).status,401);
    }finally{await h.close();}
  });
  test(`${runtime} 全局撤销精确收据通过新boot会话查原包，过期/重绑token不重签旧操作`,{timeout:120000},async()=>{
    const h=await create();try{
      const setup=await setupEnvironments(h),key="management-revoke-C",path=`/device-revocation-status?idempotencyKey=${key}`;assert.deepEqual((await h.send(path,"GET")).data,{idempotencyKey:key,accepted:false});
      const challenge=await h.send("/device-revocations","POST",{subjectDeviceId:"device-C",idempotencyKey:key});assert.equal(challenge.status,200);assert.deepEqual((await h.send(path,"GET")).data,{idempotencyKey:key,accepted:false});assert.equal((await h.send(`/device-revocations/${key}`,"GET")).data.state,"pending");const signature=b64(ed25519.sign(deviceRevocationBytes(challenge.data),seeds.B!)),packet={revocation:challenge.data,signature};
      const response=await h.send("/device-revocations/complete","POST",packet);assert.equal(response.status,200);const expected={idempotencyKey:key,accepted:true,sequence:response.data.sequence,contentHash:await tokenHash(b64(deviceRevocationBytes(challenge.data))+"."+signature)};assert.deepEqual((await h.send(path,"GET")).data,expected);assert.equal((await h.send(`/device-revocations/${key}`,"GET")).data.state,"complete");assert.equal(row(await control(h),"device-C"),undefined);
      assert.equal((await h.send(path,"GET",undefined,"C")).status>=400,true);assert.equal((await h.send(controlPath,"GET",undefined,"C")).status>=400,true);
      h.setToken("B",b64(Buffer.alloc(32,118)));assert.equal((await h.send(path,"GET")).status,401);
      const boot=await h.send("/boot-challenges","POST",{deviceId:"device-B",accountGeneration:"1"},"login");assert.equal(boot.status,200);const fields=["harmonia/device-boot/v1",h.account.id,"1","device-B",setup.newX.grant.subjectSigningPublicKey,setup.newX.grant.subjectReceivingPublicKey,boot.data.challengeId,boot.data.nonce,String(boot.data.expiresAt)];assert.deepEqual(boot.data.signingPayload,fields);const renewed=await h.send("/boot-sessions","POST",{deviceId:"device-B",accountGeneration:"1",challengeId:boot.data.challengeId,signature:sign(fields,seeds.B!)},"login");assert.equal(renewed.status,200);h.setToken("B",renewed.data.token);assert.deepEqual((await h.send(path,"GET")).data,expected);assert.equal((await h.send("/device-revocations/complete","POST",packet)).data.error,"binding_invalid");
      const downgrade=signedGrant({...setup.newX.grant,issuerDeviceId:"device-A",grantGeneration:"3",role:"ro",idempotencyKey:"management-post-revoke-downgrade"});assert.equal((await h.send("/grants","POST",downgrade,"A")).status,200);assert.deepEqual((await h.send(path,"GET")).data,expected);assert.equal((await h.send(controlPath,"GET")).status,403);
      assert.deepEqual(Object.keys(expected).sort(),["accepted","contentHash","idempotencyKey","sequence"]);assert.equal(JSON.stringify(expected).includes(signature),false);assert.equal(JSON.stringify(expected).includes(challenge.data.sessionHash),false);
    }finally{await h.close();}
  });
}
test("Node管理缺档案/历史/最高GG或签名替换拒绝，不从目录和当前selfgrant补造",async()=>{
  const h=await nodeHarness();try{await setupEnvironments(h);const original=h.read();const attacks=[
    (a:ReturnType<Harness["read"]>)=>{delete a.deviceEnrollments!["device-C"];},
    (a:ReturnType<Harness["read"]>)=>{a.devices["device-C"]!.receivingPublicKey=b64(Buffer.alloc(32,119));},
    (a:ReturnType<Harness["read"]>)=>{a.grantHistory=a.grantHistory!.filter(event=>event.grant.grant.subjectDeviceId!=="device-B");},
    (a:ReturnType<Harness["read"]>)=>{a.grants[grantKey("env-fixture","device-B")]=a.vaultInitializations!["original-chain-initialization"]!.proposal.environments[0]!.grant;},
    (a:ReturnType<Harness["read"]>)=>{a.vaultInitializations={};}
  ];for(const attack of attacks){h.change(attack);const response=await h.send(controlPath,"GET");assert.equal(response.status>=400,true,JSON.stringify(response.data));assert.deepEqual(Object.keys(response.data),["error"]);h.change(a=>Object.assign(a,structuredClone(original)));}assert.equal((await h.send(controlPath,"GET")).status,200);
  }finally{await h.close();}
});
test("Node真实SQLite grant提交与管理读事务失败原子回滚，未知收据不把失败当接受",async()=>{
  const h=await nodeHarness();try{const setup=await setupEnvironments(h),packet=signedGrant({...setup.writer.grant,grantGeneration:"2",role:"ro",idempotencyKey:"management-sql-failure"}),before=JSON.stringify(h.read()),restore=h.failNextCommit!();try{assert.equal((await h.send("/grants","POST",packet)).status,500);}finally{restore();}assert.equal(JSON.stringify(h.read()),before);assert.deepEqual((await h.send(`/grant-status?idempotencyKey=${packet.grant.idempotencyKey}`,"GET")).data,{idempotencyKey:packet.grant.idempotencyKey,accepted:false});assert.equal((await h.send("/grants","POST",packet)).status,200);const accepted=JSON.stringify(h.read()),undo=h.failNextCommit!();try{assert.equal((await h.send(controlPath,"GET")).status,500);}finally{undo();}assert.equal(JSON.stringify(h.read()),accepted);assert.equal((await h.send(controlPath,"GET")).status,200);
  }finally{await h.close();}
});

test("Node none记录独立验签，最高历史不能倒退；当前Admin到期后管理拒绝而本人旧回执仍可查",async()=>{
  const h=await nodeHarness();try{
    const setup=await setupEnvironments(h),none=signedGrant({...setup.writer.grant,grantGeneration:"2",role:"none",envelope:"",idempotencyKey:"management-none-source"});assert.equal((await h.send("/grants","POST",none)).status,200);const path="/grant-management?environmentId=environment-Y&capability=issuer-origin-v1";assert.equal((await h.send(path,"GET")).status,200);const original=h.read();
    h.change(a=>{const current=a.grants[grantKey("environment-Y","device-C")]!;current.signature=b64(Buffer.alloc(64,120));a.grantHistory!.find(event=>event.grant.grant.idempotencyKey===none.grant.idempotencyKey)!.grant.signature=current.signature;});const invalid=await h.send(path,"GET");assert.equal(invalid.status,403);assert.equal(invalid.data.error,"signature_invalid");h.change(a=>Object.assign(a,structuredClone(original)));
    h.change(a=>{a.grants[grantKey("environment-Y","device-C")]=structuredClone(setup.writer);});assert.equal((await h.send(path,"GET")).data.error,"issuer_authority_unaccepted");h.change(a=>Object.assign(a,structuredClone(original)));
    const deadline=Math.floor(Date.now()/1000)+2,g=signedGrant({...setup.newX.grant,issuerDeviceId:"device-A",grantGeneration:"3",expiresAt:String(deadline),idempotencyKey:"management-admin-expiry"});assert.equal((await h.send("/grants","POST",g,"A")).status,200);await new Promise(resolve=>setTimeout(resolve,Math.max(1,deadline*1000-Date.now()+20)));const expired=await h.send(controlPath,"GET");assert.equal(expired.status,403);assert.equal(expired.data.error,"environment_forbidden");assert.equal((await h.send(`/grant-status?idempotencyKey=${none.grant.idempotencyKey}`,"GET")).data.contentHash,await receipt(none));
  }finally{await h.close();}
});
