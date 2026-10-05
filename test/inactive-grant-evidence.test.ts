import test from "node:test";
import assert from "node:assert/strict";
import { ed25519 } from "@noble/curves/ed25519.js";
import { grantBytes } from "../src/protocol.js";
import { grantKey } from "../src/model.js";
import { verifyGraph } from "./recovery-origin-fixtures.js";
import { issuerAuthorityHash } from "../src/issuer-proof.js";
import { nodeHarness, workerHarness, seeds, b64 } from "./recovery-origin-fixtures.js";
for(const [runtime,create] of [["Node TCP",nodeHarness],["workerd HTTP",workerHarness]] as const) test(`${runtime} 原A批准C被B撤销，零当前可读权限仍返回B冻结签权与双签身份`,async()=>{
  const h=await create(true);try{
    assert.equal(h.account.dagDeviceEnrollments!["device-C"]!.context.approverDeviceId,"device-A");const prior=h.account.grants[grantKey("env-fixture","device-C")]!,admin=h.account.grants[grantKey("env-fixture","device-B")]!,grant={...prior.grant,issuerDeviceId:"device-B",grantGeneration:"2",role:"none" as const,envelope:"",expiresAt:String(Math.floor(Date.now()/1000)+3600),idempotencyKey:"B-revokes-A-reader"},signature=b64(ed25519.sign(grantBytes(grant),seeds.B!));assert.equal((await h.send("/grants","POST",{grant,signature})).status,200);
    for(const scope of["","&scope=authorizations"]){const pull=await h.send(`/pull?after=0&capability=issuer-recovery-dag-v1${scope}`,"GET",undefined,"C");assert.equal(pull.status,200,JSON.stringify(pull.data));assert.deepEqual(pull.data.events,[]);assert.deepEqual(pull.data.environmentEvents,[]);assert.equal(pull.data.grants[0].grant.role,"none");const graph=verifyGraph(pull.data.issuerEvidence);assert.equal(graph.identities.get("device-B")!.signing,admin.grant.subjectSigningPublicKey);assert.equal(graph.authorities.has(issuerAuthorityHash(admin)),true);assert.equal(pull.data.issuerEvidence.source.view.targets[0].authorityHash,issuerAuthorityHash(admin));assert.equal(pull.data.issuerEvidence.source.view.authorities.some((node:{grant:typeof prior})=>node.grant.grant.role==="none"),false);assert.equal(ed25519.verify(Buffer.from(signature,"base64url"),grantBytes(grant),Buffer.from(graph.identities.get("device-B")!.signing,"base64url")),true);}
    const old=await h.send("/pull?after=0","GET",undefined,"C");assert.equal(old.status,400);
    if(runtime==="Node TCP"){h.change(a=>{delete a.dagDeviceEnrollments!["device-B"];});const denied=await h.send("/pull?after=0&capability=issuer-recovery-dag-v1","GET",undefined,"C");assert.equal(denied.status,403);assert.equal(denied.data.error,"issuer_archive_mismatch");assert.deepEqual(Object.keys(denied.data),["error"]);}
  }finally{await h.close();}
});
