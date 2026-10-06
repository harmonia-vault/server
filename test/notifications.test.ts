import {withEnvironmentOrigin} from "./fixtures.js";
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";
import WebSocket from "ws";
import { nodeStore } from "../src/node-store.js";
import { nodeServer } from "../src/node-runtime.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { environmentChangeBytes, type EnvironmentChange } from "../src/environments.js";
import { NotificationAuthority, type SequenceHint } from "../src/notifications.js";
import { Fault, grantKey } from "../src/model.js";
import { VaultService, tokenHash } from "../src/service.js";
import { auth, fixtureAccount, grant, mutation, now, seed, signGrant, tokenFor, seeds } from "./fixtures.js";
const id = "synthetic-account", denies = (code: string) => (e: unknown) => e instanceof Fault && e.code === code;
async function context(run: (c: ReturnType<typeof nodeStore>, vault: VaultService) => Promise<void>, clock: () => number = () => now): Promise<void> {
 const dir = mkdtempSync(join(tmpdir(), "harmonia-notifications-")), c = nodeStore(join(dir,"vault.sqlite"), clock);
 try { await run(c, await seed(c.store)); } finally { c.sql.close(); rmSync(dir,{recursive:true,force:true}); }
}
test("通知票据仅限当前受信持钥会话与可读授权，哈希持久化且不改变权威序号", async()=>context(async({store},vault)=>{
 const notifications = new NotificationAuthority(store,()=>now), ticket = await notifications.issue(id,auth("reader"));
 assert.equal(ticket.expiresAt,now+30); assert.equal(ticket.sequence,3); assert.equal(store.read(id)!.sequence,3);
 assert.equal(JSON.stringify(store.read(id)).includes(ticket.ticket),false); assert.equal(store.read(id)!.notificationTickets![0]!.ticketHash,await tokenHash(ticket.ticket));
 const login=await vault.login("synthetic@example.invalid","ab".repeat(32));
 await assert.rejects(notifications.issue(id,{...auth("reader"),token:login.token}),denies("device_proof_required"));
 await assert.rejects(notifications.issue(id,auth("stranger")),denies("environment_forbidden"));
 await assert.rejects(notifications.issue(id,{...auth("reader"),accountGeneration:"2"}),denies("generation_stale"));
 await assert.rejects(notifications.issue(id,{...auth("reader"),token:tokenFor("writer")}),denies("device_proof_required"));
 store.transaction(id,a=>{a.sessions.find(s=>s.deviceId==="reader")!.kind="recovery";});
 await assert.rejects(notifications.issue(id,auth("reader")),denies("unauthorized"));
}));
test("票据绑定账号设备代际，短时单次原子消费，重放与并发只接受一次",async()=>context(async({store})=>{
 const n=new NotificationAuthority(store,()=>now), ticket=await n.issue(id,auth("reader")), request={...auth("reader"),token:ticket.ticket};
 await assert.rejects(n.consume(id,{...request,deviceId:"writer"}),denies("notification_ticket_invalid"));
 const other=await fixtureAccount("other-account","other@example.invalid"); store.create(other);
 await assert.rejects(n.consume("other-account",request),denies("notification_ticket_invalid"));
 await assert.rejects(n.consume(id,{...request,accountGeneration:"2"}),denies("generation_stale"));
 const attempts=await Promise.allSettled([n.consume(id,request),n.consume(id,request)]); assert.equal(attempts.filter(r=>r.status==="fulfilled").length,1);
 await assert.rejects(n.consume(id,request),denies("notification_ticket_invalid"));
}));
test("票据消费和每次发送均重查撤销/会话/期限/代际，消息精确只有序号提示",async()=>context(async({store},vault)=>{
 let clock=now; const n=new NotificationAuthority(store,()=>clock), ticket=await n.issue(id,auth("reader")); clock=now+30;
 await assert.rejects(n.consume(id,{...auth("reader"),token:ticket.ticket}),denies("notification_ticket_invalid")); clock=now;
 const fresh=await n.issue(id,auth("reader")), state=await n.consume(id,{...auth("reader"),token:fresh.ticket});
 const sent:SequenceHint[]=[],closed:number[]=[];const peer={send:(s:string)=>sent.push(JSON.parse(s) as SequenceHint),close:(code:number)=>closed.push(code)};
 const first=n.deliver(state,peer)!; assert.deepEqual(sent,[{accountId:id,accountGeneration:"1",sequence:3}]);
 await vault.mutate(id,auth(),mutation()); const next=n.deliver(first.state,peer)!; assert.deepEqual(Object.keys(sent[1]!).sort(),["accountGeneration","accountId","sequence"]); assert.equal(sent[1]!.sequence,4);
 store.transaction(id,a=>{a.grants[grantKey("dev","reader")]=signGrant(grant("reader",{role:"none",envelope:""}));});
 assert.equal(n.deliver(next.state,peer),undefined); assert.deepEqual(closed,[4003]); assert.equal(sent.length,2);
 const writerTicket=await n.issue(id,auth()), writerState=await n.consume(id,{...auth(),token:writerTicket.ticket});
 store.transaction(id,a=>{a.sessions.find(s=>s.deviceId==="writer")!.expiresAt=now;}); assert.equal(n.deliver(writerState,peer),undefined);
 store.transaction(id,a=>{a.generation="2";delete a.trustRoot;}); assert.equal(n.deliver(writerState,peer),undefined);
}));
test("成功COMMIT才提示；失败SQL回滚和幂等重试不发新序号",async()=>context(async({store,sql},vault)=>{
 const observed:string[]=[]; const stop=store.onCommit(id=>observed.push(id));
 sql.execute("CREATE TRIGGER fail_notify BEFORE UPDATE ON accounts BEGIN SELECT RAISE(FAIL,'synthetic failure'); END");
 await assert.rejects(vault.mutate(id,auth(),mutation())); assert.deepEqual(observed,[]); assert.equal(store.read(id)!.sequence,3);
 sql.execute("DROP TRIGGER fail_notify"); await vault.mutate(id,auth(),mutation()); assert.deepEqual(observed,[id]);
 await vault.mutate(id,auth(),mutation()); assert.deepEqual(observed,[id]); stop();
}));
class Inbox { values:string[]=[]; close?:{code:number;reason:string}; private pending:{resolve:(s:string)=>void;reject:(e:Error)=>void;timer:ReturnType<typeof setTimeout>}[]=[];
 constructor(readonly socket:WebSocket){socket.on("message",data=>{const s=data.toString(), p=this.pending.shift();if(p){clearTimeout(p.timer);p.resolve(s);}else this.values.push(s);});socket.on("close",(code,reason)=>{this.close={code,reason:reason.toString()};for(const p of this.pending){clearTimeout(p.timer);p.reject(new Error("closed"));}this.pending=[];});}
 next():Promise<string>{const value=this.values.shift();if(value!==undefined)return Promise.resolve(value);return new Promise((resolve,reject)=>{const item={resolve,reject,timer:setTimeout(()=>{this.pending=this.pending.filter(p=>p!==item);reject(new Error("message timeout"));},4000)};this.pending.push(item);});}
}
async function live(run:(c:ReturnType<typeof nodeStore>,vault:VaultService,url:string)=>Promise<void>):Promise<void>{
 const dir=mkdtempSync(join(tmpdir(),"harmonia-live-ws-")),c=nodeStore(join(dir,"vault.sqlite"));c.store.create(await fixtureAccount());
 const vault=new VaultService(c.store,{allowRegistration:false,requireEmailVerification:true}),runtime=nodeServer(vault);
 runtime.server.listen(0,"127.0.0.1");await once(runtime.server,"listening"); const address=runtime.server.address(); assert.ok(address&&typeof address!=="string");
 try{await run(c,vault,`http://127.0.0.1:${address.port}`);}finally{runtime.closeNotifications();runtime.server.closeAllConnections();await new Promise<void>(resolve=>runtime.server.close(()=>resolve()));c.sql.close();rmSync(dir,{recursive:true,force:true});}
}
const headers=(device="reader")=>({"Harmonia-Protocol-Major":"2",authorization:`Bearer ${tokenFor(device)}`,"x-harmonia-device-id":device,"x-harmonia-account-generation":"1","content-type":"application/json"});
async function connect(base:string,ticket:string,device="reader",query=""):Promise<Inbox>{const ws=new WebSocket(`${base.replace("http:","ws:")}/v1/accounts/${id}/notifications${query}`,{headers:{...headers(device),authorization:`Bearer ${ticket}`}});const inbox=new Inbox(ws);await once(ws,"open");return inbox;}
async function ticket(base:string,device="reader"):Promise<string>{const res=await fetch(`${base}/v1/accounts/${id}/notification-tickets`,{method:"POST",headers:headers(device),body:"{}"});assert.equal(res.status,200);return (await res.json() as{ticket:string}).ticket;}
async function rejected(base:string,value:string,device="reader",query=""):Promise<number>{return new Promise((resolve,reject)=>{const ws=new WebSocket(`${base.replace("http:","ws:")}/v1/accounts/${id}/notifications${query}`,{headers:{...headers(device),authorization:`Bearer ${value}`}});ws.on("unexpected-response",(_,res)=>{res.resume();resolve(res.statusCode!);ws.terminate();});ws.on("error",()=>{});ws.on("open",()=>{ws.close();reject(new Error("unexpected upgrade"));});});}
test("真实Node WebSocket只提示已持久序号，断线重连后按pull补漏，票据不接受URL或重放",{timeout:15000},async()=>live(async({store},vault,base)=>{
 const raw=await ticket(base), inbox=await connect(base,raw);assert.equal(JSON.parse(await inbox.next()).sequence,3);
 assert.equal(await rejected(base,raw),401);assert.equal(await rejected(base,await ticket(base),"reader","?token=forbidden"),400);
 await vault.mutate(id,auth(),mutation());assert.deepEqual(JSON.parse(await inbox.next()),{accountId:id,accountGeneration:"1",sequence:4});
 inbox.socket.close();await once(inbox.socket,"close"); await vault.mutate(id,auth(),mutation("writer",{idempotencyKey:"offline-2",name:"SECOND_KEY"}));
 const reconnect=await connect(base,await ticket(base));assert.equal(JSON.parse(await reconnect.next()).sequence,5);
 const pull=await fetch(`${base}/v1/accounts/${id}/pull?after=0&capability=issuer-recovery-dag-v1`,{headers:headers()});assert.equal((await pull.json() as{events:unknown[]}).events.length,2);reconnect.socket.close();await once(reconnect.socket,"close");
}));
test("真实Node连接在授权撤销后立即关闭，后续写入不泄露通知；期限主动关闭不等下一次写",{timeout:15000},async()=>live(async({store},vault,base)=>{
 const inbox=await connect(base,await ticket(base));await inbox.next();const closed=once(inbox.socket,"close");
 await vault.changeGrant(id,auth("admin"),signGrant(grant("reader",{grantGeneration:"2",role:"none",envelope:"",idempotencyKey:"revoke-notification"})));assert.equal((await closed)[0],4003);
 await vault.mutate(id,auth(),mutation());assert.deepEqual(inbox.values,[]);
 const deadline=Math.floor(Date.now()/1000)+2;store.transaction(id,a=>{a.grants[grantKey("dev","writer")]=signGrant(grant("writer",{expiresAt:String(deadline)}));});
 const expiring=await connect(base,await ticket(base,"writer"),"writer");await expiring.next();assert.equal((await once(expiring.socket,"close"))[0],4003);
}));

test("真实Node TCP使用环境1MB专用限制，双大密文>100k可轮换，普通与超限请求受控413",{timeout:15000},async()=>live(async({store},vault,base)=>{
 const packet=Buffer.alloc(40040,7).toString("base64url");
 for(const name of ["SYNTHETIC_KEY","SECOND_KEY"])await vault.mutate(id,auth(),mutation("writer",{name,payload:packet,idempotencyKey:`tcp-${name}`}));
 const change:EnvironmentChange={accountId:id,accountGeneration:"1",deviceId:"admin",environmentId:"dev",operation:"rotate",authorityEnvironmentId:"dev",authorityKeyVersion:"1",authorityGrantGeneration:"1",previousKeyVersion:"1",keyVersion:"2",expectedSequence:"5",idempotencyKey:"tcp-big-rotate",labelPayload:"",recoveryGeneration:"1",recoveryEnvelope:Buffer.alloc(80,8).toString("base64url"),grants:["admin","reader","writer"].map(d=>signGrant(grant(d,{keyVersion:"2",grantGeneration:"2",idempotencyKey:`tcp-grant-${d}`}))),mutations:["SYNTHETIC_KEY","SECOND_KEY"].map(name=>mutation("admin",{name,keyVersion:"2",grantGeneration:"2",idempotencyKey:`tcp-rotate-${name}`,payload:packet}))};
 const signed=withEnvironmentOrigin(store.read(id)!,{change,signature:Buffer.from(ed25519.sign(environmentChangeBytes(change),seeds.admin!)).toString("base64url")}),body=JSON.stringify(signed);assert.ok(Buffer.byteLength(body)>100000);
 const response=await fetch(`${base}/v1/accounts/${id}/environment-changes-v4`,{method:"POST",headers:headers("admin"),body});assert.equal(response.status,200,await response.text());
 for(const [path,data] of[["environment-changes-v4",JSON.stringify({...signed,padding:"x".repeat(1000000)})],["mutations",JSON.stringify({padding:"x".repeat(100001)})]] as const){
  const res=await fetch(`${base}/v1/accounts/${id}/${path}`,{method:"POST",headers:headers("admin"),body:data});assert.equal(res.status,413);assert.deepEqual(await res.json(),{error:"body_too_large"});
 }
 const oversizedWithoutMajor=await fetch(`${base}/v1/accounts/${id}/mutations`,{method:"POST",body:"x".repeat(100001)});
 assert.equal(oversizedWithoutMajor.status,413);assert.equal(oversizedWithoutMajor.headers.get("Harmonia-Protocol-Major"),"2");

}));

test("待用票据有界且到期清理；发票后撤销/授权到期不得完成握手",async()=>{
 let clock=now;await context(async({store})=>{
 const n=new NotificationAuthority(store,()=>clock);
 for(let i=0;i<4;i++)await n.issue(id,auth("reader"));await assert.rejects(n.issue(id,auth("reader")),denies("notification_capacity_reached"));
 clock=now+31;assert.equal((await n.issue(id,auth("reader"))).expiresAt,clock+30);assert.equal(store.read(id)!.notificationTickets!.length,1);
 const writer=await n.issue(id,auth());store.transaction(id,a=>{a.devices.writer!.revoked=true;});await assert.rejects(n.consume(id,{...auth(),token:writer.ticket}),denies("device_untrusted"));
 const reader=await n.issue(id,auth("reader"));store.transaction(id,a=>{a.grants[grantKey("dev","reader")]=signGrant(grant("reader",{expiresAt:String(clock)}));});await assert.rejects(n.consume(id,{...auth("reader"),token:reader.ticket}),denies("environment_forbidden"));
 },()=>clock);
});
