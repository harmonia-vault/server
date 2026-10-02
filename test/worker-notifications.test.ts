import WebSocket from "ws";
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build } from "esbuild";
import { Miniflare } from "miniflare";
import { ed25519 } from "@noble/curves/ed25519.js";
import { environmentChangeBytes, type EnvironmentChange } from "../src/environments.js";
import { fixtureAccount, grant, mutation, seeds, signGrant, tokenFor } from "./fixtures.js";
import { tokenHash } from "../src/service.js";
const id="synthetic-account",headers=(device="reader")=>({"content-type":"application/json",authorization:`Bearer ${tokenFor(device)}`,"x-harmonia-device-id":device,"x-harmonia-account-generation":"1"});
class Inbox {values:string[]=[];closed?:number;private pending:((s:string)=>void)[]=[];private closes:((n:number)=>void)[]=[];
 constructor(readonly socket:WebSocket){
 // 固定 ws 8.22.0 的成熟 Receiver 解析真实 close 帧；Miniflare 代理 FIN 延迟不能冒充未发送关闭帧。
 socket.on("open",()=>{(socket as unknown as {_receiver:{on(event:"conclude",listener:(code:number)=>void):void}})._receiver.on("conclude",code=>{this.closed=code;for(const p of this.closes)p(code);});});
 socket.on("message",data=>{const p=this.pending.shift();if(p)p(String(data));else this.values.push(String(data));});socket.on("close",code=>{if(this.closed===undefined)this.closed=code;for(const p of this.closes)p(this.closed);});}
 next():Promise<string>{const s=this.values.shift();return s===undefined?Promise.race([new Promise<string>(r=>this.pending.push(r)),new Promise<string>((_,r)=>setTimeout(()=>r(new Error("message timeout")),5000))]):Promise.resolve(s);}
 closeCode(label="unknown"):Promise<number>{return this.closed!==undefined?Promise.resolve(this.closed):Promise.race([new Promise<number>(r=>this.closes.push(r)),new Promise<number>((_,r)=>setTimeout(()=>r(new Error(`close timeout: ${label}`)),5000))]);}
}
test("真实workerd休眠API通知验证单次票据、逐次撤销/到期关闭帧、代际、隔离与持久补拉",{timeout:25000},async()=>{
 const dir=mkdtempSync(join(tmpdir(),"harmonia-worker-notifications-"));let mf:Miniflare|undefined;const sockets:WebSocket[]=[];
 try{
  const bundle=await build({entryPoints:["test/worker-harness.ts"],absWorkingDir:process.cwd(),bundle:true,write:false,format:"esm",platform:"browser",target:"es2023",external:["cloudflare:workers","node:*"],banner:{js:'import { Buffer } from "node:buffer";'}});
  mf=new Miniflare({modules:true,script:bundle.outputFiles[0]!.text,compatibilityDate:"2026-07-30",compatibilityFlags:["nodejs_compat"],durableObjects:{ACCOUNTS:{className:"SyntheticVault",useSQLite:true},FIXTURES:{className:"SyntheticVault",useSQLite:true}},d1Databases:{DIRECTORY:"directory"},durableObjectsPersist:join(dir,"objects"),d1Persist:join(dir,"directory")});
  const account=await fixtureAccount(),passwordOnly=Buffer.alloc(32,55).toString("base64url");account.sessions.push({tokenHash:await tokenHash(passwordOnly),generation:"1",kind:"login",expiresAt:Math.floor(Date.now()/1000)+3600});
  await mf.dispatchFetch("https://selfhost.example.invalid/test/seed",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(account)});
  const call=(path:string,value:unknown,device="reader",extra:Record<string,string>={})=>mf!.dispatchFetch(`https://selfhost.example.invalid/v1/accounts/${id}/${path}`,{method:"POST",headers:{...headers(device),...extra},body:JSON.stringify(value)});
  const issue=async(device="reader")=>{const res=await call("notification-tickets",{},device);assert.equal(res.status,200,await res.clone().text());return(await res.json() as{ticket:string}).ticket;};
  const endpoint=(await mf.ready).toString().replace("http:","ws:").replace(/\/$/,"");
  const upgrade=(value:string,device="reader",accountId=id,query=""):Promise<{status:number;inbox:Inbox}>=>new Promise((resolve,reject)=>{
    const socket=new WebSocket(`${endpoint}/v1/accounts/${accountId}/notifications${query}`,{headers:{...headers(device),authorization:`Bearer ${value}`}}),inbox=new Inbox(socket);
    socket.on("error",()=>{});socket.on("open",()=>{sockets.push(socket);resolve({status:101,inbox});});socket.on("unexpected-response",(_,res)=>{res.resume();socket.terminate();resolve({status:res.statusCode!,inbox});});
  });
  const connect=async(device="reader")=>{const value=await issue(device),res=await upgrade(value,device);assert.equal(res.status,101);return{inbox:res.inbox,ticket:value};};
  assert.equal((await call("notification-tickets",{},"reader",{authorization:`Bearer ${passwordOnly}`})).status,403);assert.equal((await call("notification-tickets",{},"stranger")).status,403);
  const t=await issue();assert.equal((await upgrade(t,"reader","other-account")).status,401);assert.equal((await upgrade(t,"reader",id,"?ticket=forbidden")).status,400);
  const res=await upgrade(t);assert.equal(res.status,101);const reader=res.inbox;assert.deepEqual(JSON.parse(await reader.next()),{accountId:id,accountGeneration:"1",sequence:0});assert.equal((await upgrade(t)).status,401);
  assert.equal((await call("mutations",mutation(),"writer")).status,200);assert.deepEqual(JSON.parse(await reader.next()),{accountId:id,accountGeneration:"1",sequence:1});
  reader.socket.close();await reader.closeCode("client disconnect");assert.equal((await call("mutations",mutation("writer",{idempotencyKey:"disconnected-value",name:"SECOND_KEY"}),"writer")).status,200);
  const {inbox:reconnected}=await connect();assert.equal(JSON.parse(await reconnected.next()).sequence,2);const pull=await mf.dispatchFetch(`https://selfhost.example.invalid/v1/accounts/${id}/pull?after=0`,{headers:headers()});assert.equal((await pull.json() as{events:unknown[]}).events.length,2);
  const receipt=await mf.dispatchFetch(`https://selfhost.example.invalid/v1/accounts/${id}/mutation-status?idempotencyKey=write-1`,{headers:headers("writer")});assert.equal(receipt.status,200);assert.equal((await receipt.json() as{accepted:boolean}).accepted,true);
  const deadline=Math.floor(Date.now()/1000)+2;assert.equal((await call("grants",signGrant(grant("reader",{grantGeneration:"2",expiresAt:String(deadline),idempotencyKey:"expire-reader"})),"admin")).status,200);await reconnected.next();const probe=await (await mf.dispatchFetch(`https://selfhost.example.invalid/test/notification-probe/${id}`)).json() as{scheduledAlarm:number|null};assert.equal(probe.scheduledAlarm,deadline*1000);assert.equal(await reconnected.closeCode("expiry alarm").catch(async error=>{const state=await(await mf!.dispatchFetch(`https://selfhost.example.invalid/test/notification-probe/${id}`)).json();throw new Error(`${error.message}: ${JSON.stringify(state)} client=${JSON.stringify({readyState:reconnected.socket.readyState,received:(reconnected.socket as unknown as {_closeFrameReceived:boolean})._closeFrameReceived,sent:(reconnected.socket as unknown as {_closeFrameSent:boolean})._closeFrameSent})}`);}),4003);
  assert.equal((await call("notification-tickets",{},"reader")).status,403);
  const {inbox:writer}=await connect("writer");await writer.next();assert.equal((await call("grants",signGrant(grant("writer",{grantGeneration:"2",role:"none",envelope:"",idempotencyKey:"revoke-writer"})),"admin")).status,200);assert.equal(await writer.closeCode("grant revocation"),4003);assert.deepEqual(writer.values,[]);
  const {inbox:admin}=await connect("admin");await admin.next();const reset=await mf.dispatchFetch(`https://selfhost.example.invalid/test/reset-generation/${id}`,{method:"POST"});assert.equal(reset.status,200);assert.equal(await admin.closeCode("generation change"),4003);
 }finally{for(const s of sockets){try{s.terminate();}catch{}}await mf?.dispose();rmSync(dir,{recursive:true,force:true});}
});
test("真实workerd外围缓冲使用1MB环境专用上限，双大密文HTTP轮换成功且其他入口不放宽",{timeout:20000},async()=>{
 const dir=mkdtempSync(join(tmpdir(),"harmonia-worker-large-http-"));let mf:Miniflare|undefined;
 try{
  const bundle=await build({entryPoints:["test/worker-harness.ts"],absWorkingDir:process.cwd(),bundle:true,write:false,format:"esm",platform:"browser",target:"es2023",external:["cloudflare:workers","node:*"],banner:{js:'import { Buffer } from "node:buffer";'}});
  mf=new Miniflare({modules:true,script:bundle.outputFiles[0]!.text,compatibilityDate:"2026-07-30",compatibilityFlags:["nodejs_compat"],durableObjects:{ACCOUNTS:{className:"SyntheticVault",useSQLite:true},FIXTURES:{className:"SyntheticVault",useSQLite:true}},d1Databases:{DIRECTORY:"directory"}});
  await mf.dispatchFetch("https://selfhost.example.invalid/test/seed",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(await fixtureAccount())});
  const call=(path:string,value:unknown,device="writer")=>mf!.dispatchFetch(`https://selfhost.example.invalid/v1/accounts/${id}/${path}`,{method:"POST",headers:headers(device),body:JSON.stringify(value)});
  const packet=Buffer.alloc(40040,7).toString("base64url");for(const name of["SYNTHETIC_KEY","SECOND_KEY"])assert.equal((await call("mutations",mutation("writer",{name,payload:packet,idempotencyKey:`worker-${name}`}))).status,200);
  const change:EnvironmentChange={accountId:id,accountGeneration:"1",deviceId:"admin",environmentId:"dev",operation:"rotate",authorityEnvironmentId:"dev",authorityKeyVersion:"1",authorityGrantGeneration:"1",previousKeyVersion:"1",keyVersion:"2",expectedSequence:"2",idempotencyKey:"worker-big-rotate",labelPayload:"",recoveryGeneration:"1",recoveryEnvelope:Buffer.alloc(80,8).toString("base64url"),grants:["admin","reader","writer"].map(d=>signGrant(grant(d,{keyVersion:"2",grantGeneration:"2",idempotencyKey:`worker-grant-${d}`}))),mutations:["SYNTHETIC_KEY","SECOND_KEY"].map(name=>mutation("admin",{name,keyVersion:"2",grantGeneration:"2",idempotencyKey:`worker-rotate-${name}`,payload:packet}))};
  const signed={change,signature:Buffer.from(ed25519.sign(environmentChangeBytes(change),seeds.admin!)).toString("base64url")};assert.ok(Buffer.byteLength(JSON.stringify(signed))>100000);const rotate=await call("environment-changes",signed,"admin");assert.equal(rotate.status,200,await rotate.text());
  for(const[path,padding]of[["environment-changes",1000001],["mutations",100001]] as const)assert.equal((await call(path,{padding:"x".repeat(padding)},"admin")).status,413);
 }finally{await mf?.dispose();rmSync(dir,{recursive:true,force:true});}
});
