import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { nodeStore } from "../src/node-store.js";
import { route } from "../src/http.js";
import { Fault } from "../src/model.js";
import { tokenHash } from "../src/service.js";
import { auth, mutation, seed } from "./fixtures.js";
const id="synthetic-account";
async function context(run:(c:ReturnType<typeof nodeStore>,vault:Awaited<ReturnType<typeof seed>>)=>Promise<void>):Promise<void>{const dir=mkdtempSync(join(tmpdir(),"harmonia-status-")),c=nodeStore(join(dir,"vault.sqlite"));try{await run(c,await seed(c.store));}finally{c.sql.close();rmSync(dir,{recursive:true,force:true});}}
test("本人写入收据仅含接受序号与原签包hash，丢响应与删除历史后仍可查询而不新增授权",async()=>context(async({store},vault)=>{
 assert.deepEqual(await vault.mutationStatus(id,auth(),"write-1"),{idempotencyKey:"write-1",accepted:false});
 await vault.mutate(id,auth(),mutation());const content=store.read(id)!.idempotency["mutation/writer/write-1"]!.content;
 const expected={idempotencyKey:"write-1",accepted:true,sequence:4,contentHash:await tokenHash(content)};
 assert.deepEqual(await vault.mutationStatus(id,auth(),"write-1"),expected);assert.deepEqual(await vault.mutationStatus(id,auth("reader"),"write-1"),{idempotencyKey:"write-1",accepted:false});
 store.transaction(id,a=>{a.events=[];a.environments={};a.grants={};});assert.deepEqual(await vault.mutationStatus(id,auth(),"write-1"),expected);assert.equal(store.read(id)!.sequence,4);
}));
test("撤销设备、错误会话与旧代际不得查历史收据，查询不会恢复grant或泄露其他账号",async()=>context(async({store},vault)=>{
 await vault.mutate(id,auth(),mutation());await assert.rejects(vault.mutationStatus(id,{...auth(),token:auth("reader").token},"write-1"),e=>e instanceof Fault&&e.code==="device_proof_required");
 const login=await vault.login("synthetic@example.invalid","ab".repeat(32));await assert.rejects(vault.mutationStatus(id,{...auth(),token:login.token},"write-1"),e=>e instanceof Fault&&e.code==="device_proof_required");
 store.transaction(id,a=>{a.devices.writer!.revoked=true;});await assert.rejects(vault.mutationStatus(id,auth(),"write-1"),e=>e instanceof Fault&&e.code==="device_untrusted");
 store.transaction(id,a=>{a.generation="2";delete a.trustRoot;});await assert.rejects(vault.mutationStatus(id,auth(),"write-1"),e=>e instanceof Fault&&e.code==="generation_stale");
}));
test("HTTP写入收据查询只接受单个幂等键，响应no-store且无名称/密文/凭据",async()=>context(async(_,vault)=>{
 await vault.mutate(id,auth(),mutation());const request=(query:string)=>new Request(`https://selfhost.example.invalid/v1/accounts/${id}/mutation-status${query}`,{headers: {"Harmonia-Protocol-Major":"2", authorization:`Bearer ${auth().token}`,"x-harmonia-device-id":"writer","x-harmonia-account-generation":"1"}});
 const response=await route(request("?idempotencyKey=write-1"),vault);assert.equal(response.status,200);assert.equal(response.headers.get("cache-control"),"no-store");const body=await response.json() as Record<string,unknown>;assert.deepEqual(Object.keys(body).sort(),["accepted","contentHash","idempotencyKey","sequence"]);
 for(const query of["","?idempotencyKey=write-1&idempotencyKey=write-1","?idempotencyKey=write-1&deviceId=admin","?idempotencyKey="])assert.equal((await route(request(query),vault)).status,400);
}));
