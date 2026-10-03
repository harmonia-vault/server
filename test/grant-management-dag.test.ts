import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,mkdtempSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {once} from 'node:events';
import {ed25519} from '@noble/curves/ed25519.js';
import {build} from 'esbuild';
import {Miniflare} from 'miniflare';
import {nodeHarness,b64,sign,seeds} from './recovery-origin-fixtures.js';
import {recoveryKeys} from './fixtures.js';
import {nodeStore} from '../src/node-store.js';
import {nodeServer} from '../src/node-runtime.js';
import {VaultService} from '../src/service.js';
import {grantBytes} from '../src/protocol.js';
import {trustRootPayload} from '../src/trust-root.js';
import {recoveryManifestHash,recoveryEnvelopesHash,recoveryRootHash} from '../src/recovery-authority-wire.js';
import {transitionBytesV2,type RecoveryTransitionCommandV2} from '../src/recovery-dag-wire.js';
import type {SignedGrant} from '../src/model.js';

const capability='issuer-recovery-dag-v1';
const template=JSON.parse(readFileSync(new URL('./vectors/recovery-authority-v1.json',import.meta.url),'utf8'));
// 本层只验真实HTTP/SQLite事务与来源投影；封套/密文为合成字节，真HPKE/PAKE由Go联合测试承担。
async function harness(kind:'node'|'worker') {
 const initial=await nodeHarness(true),account=structuredClone(initial.read());await initial.close();
 const dir=mkdtempSync(join(tmpdir(),'harmonia-env-dag-'));
 const tokens=new Map([['A',b64(Buffer.alloc(32,65))],['B',b64(Buffer.alloc(32,62))],['C',b64(Buffer.alloc(32,63))],['login',b64(Buffer.alloc(32,61))]]);
 const db=kind==='node'?nodeStore(join(dir,'account.sqlite')):undefined;
 let mf:Miniflare|undefined,server:ReturnType<typeof nodeServer>|undefined,base='';
 if(db){db.store.create(account);server=nodeServer(new VaultService(db.store,{allowRegistration:false,requireEmailVerification:true}));server.server.listen(0,'127.0.0.1');await once(server.server,'listening');base=`http://127.0.0.1:${(server.server.address() as {port:number}).port}`;}
 else {
  const bundle=await build({entryPoints:['test/worker-harness.ts'],absWorkingDir:process.cwd(),bundle:true,write:false,format:'esm',platform:'browser',target:'es2023',external:['cloudflare:workers','node:*'],banner:{js:'import {Buffer} from "node:buffer";'}});
  mf=new Miniflare({modules:true,script:bundle.outputFiles[0]!.text,compatibilityDate:'2026-07-30',compatibilityFlags:['nodejs_compat'],durableObjects:{INSTANCES:{className:'InstanceRegistry',useSQLite:true},ACCOUNTS:{className:'SyntheticVault',useSQLite:true},FIXTURES:{className:'SyntheticVault',useSQLite:true}},d1Databases:{DIRECTORY:'directory'},durableObjectsPersist:join(dir,'objects'),d1Persist:join(dir,'directory')});
  await mf.dispatchFetch('https://synthetic.invalid/test/seed',{method:'POST',body:JSON.stringify(account)});base='https://synthetic.invalid';
 }
 const send=async(path:string,method='GET',body?:unknown,who='A',major='2')=>{
  const init={method,headers:{'content-type':'application/json',authorization:'Bearer '+tokens.get(who),'x-harmonia-account-generation':'1',...(who==='A'||who==='B'||who==='C'?{'x-harmonia-device-id':'device-'+who}:{}),...(major?{'Harmonia-Protocol-Major':major}:{})},...(body===undefined?{}:{body:JSON.stringify(body)})};
  const response=mf?await mf.dispatchFetch(base+'/v1/accounts/'+account.id+path,init):await fetch(base+'/v1/accounts/'+account.id+path,init);
  return {status:response.status,major:response.headers.get('Harmonia-Protocol-Major'),data:await response.json() as any};
 };
 const close=async()=>{await mf?.dispose();if(server){server.closeNotifications();server.server.close();await once(server.server,'close');}db?.sql.close();rmSync(dir,{recursive:true,force:true});};
 return {send,close,account,tokens,db};
}
type H=Awaited<ReturnType<typeof harness>>;
async function enterDAG(h:H){
 const old=recoveryKeys(Buffer.alloc(32,88),h.account.id,'1'),fresh=recoveryKeys(Buffer.alloc(32,71),h.account.id,'2');
 const challenge=await h.send('/recovery-challenges','POST',{accountGeneration:'1'},'login');assert.equal(challenge.status,200);
 const session=await h.send('/recovery-sessions','POST',{accountGeneration:'1',challengeId:challenge.data.challengeId,signature:sign(challenge.data.signingPayload,old.signingSeed)},'login');assert.equal(session.status,200);h.tokens.set('R',session.data.token);
 const c=(await h.send('/recovery-authority-challenges-v2?capability='+capability,'POST',{operationId:'env-dag-transition',authorizationKind:'old-recovery',chainMode:'continuous'},'R')).data;
 const s=structuredClone(template.oldRecoveryTransition.submission),t=s.transition;
 s.environmentManifest=c.environmentManifest;s.authoritySet=[];s.issuerEvidence=null;s.legacyState=null;s.envelopes=c.environmentManifest.map((e:any)=>({...e,envelope:b64(Buffer.alloc(80,71))}));
 const root=c.dependencyBundle.initialization.proposal.device;
 s.newTrustRoot={rootDeviceId:root.id,rootSigningPublicKey:root.signingPublicKey,rootReceivingPublicKey:root.receivingPublicKey,recoveryGeneration:'2',recoverySigningPublicKey:fresh.signingPublicKey,recoveryReceivingPublicKey:fresh.receivingPublicKey,signature:''};s.newTrustRoot.signature=sign(trustRootPayload(h.account.id,'1',s.newTrustRoot),fresh.signingSeed);
 Object.assign(t,{accountId:h.account.id,accountGeneration:'1',operationId:c.operationId,challengeId:c.challengeId,nonce:c.nonce,expiresAt:String(c.expiresAt),sessionHash:c.sessionHash,expectedSequence:c.expectedSequence,previousTransitionHash:c.previousTransitionHash,oldRecoveryGeneration:'1',oldRecoverySigningPublicKey:old.signingPublicKey,oldRecoveryReceivingPublicKey:old.receivingPublicKey,newRecoveryGeneration:'2',newRecoverySigningPublicKey:fresh.signingPublicKey,newRecoveryReceivingPublicKey:fresh.receivingPublicKey,authorizationKind:'old-recovery',authorizerDeviceId:'',environmentManifestHash:recoveryManifestHash(s.environmentManifest),authoritySetHash:'',issuerEvidenceHash:'',envelopesHash:recoveryEnvelopesHash(s.envelopes),newTrustRootHash:recoveryRootHash(h.account.id,'1',s.newTrustRoot),chainMode:'continuous',legacyStateHash:''});
 s.authorizationSignature=b64(ed25519.sign(transitionBytesV2(t),old.signingSeed));s.newRecoverySignature=b64(ed25519.sign(transitionBytesV2(t),fresh.signingSeed));
 const command:RecoveryTransitionCommandV2={submission:s,dependencyBundle:c.dependencyBundle};const accepted=await h.send('/recovery-authority-transitions-v2?capability='+capability,'POST',command,'R');assert.equal(accepted.status,200,JSON.stringify(accepted.data));
}

const managementPath='/grant-management?environmentId=env-fixture&capability='+capability;
async function management(h:H){const r=await h.send(managementPath);assert.equal(r.status,200,JSON.stringify(r.data));assert.equal(r.major,'2');assert.equal(r.data.issuerEvidence.profile,'harmonia/issuer-proof/v4');return r.data;}
function update(c:any,target:string,role:'ro'|'rw'|'admin'|'none',id:string,expiresAt='0'):SignedGrant {
 const actor=c.subjects.find((s:any)=>s.deviceId==='device-A').currentGrant.grant;
 const row=c.subjects.find((s:any)=>s.deviceId===target);
 const g={...actor,subjectDeviceId:target,subjectSigningPublicKey:row.signingPublicKey,subjectReceivingPublicKey:row.receivingPublicKey,keyVersion:c.keyVersion,grantGeneration:String(BigInt(row.highestGrantGeneration)+1n),role,expiresAt,idempotencyKey:id,envelope:role==='none'?'':b64(Buffer.alloc(80,125))};
 return {grant:g,signature:b64(ed25519.sign(grantBytes(g),seeds.A!))};
}
for(const backend of ['node','worker'] as const)test(`${backend} P4每环境授权/期限/none/最高代际与原收据`,{timeout:30000},async()=>{
 const h=await harness(backend);try{
  await enterDAG(h);
  assert.equal((await h.send(managementPath,'GET',undefined,'A','1')).status,426);
  for(const old of ['issuer-origin-v1','issuer-recovery-v1']) assert.equal((await h.send('/grant-management?environmentId=env-fixture&capability='+old)).status,426);
  let c=await management(h);assert.equal(c.issuerEvidence.source.view.targets.length,1);
  let previous=BigInt(c.subjects.find((s:any)=>s.deviceId==='device-C').highestGrantGeneration);
  for(const role of ['ro','rw','admin','none'] as const){
   const packet=update(c,'device-C',role,'dag-management-'+role,role==='none'?'0':String(Math.floor(Date.now()/1000)+600));
   const accepted=await h.send('/grants','POST',packet);assert.equal(accepted.status,200,JSON.stringify(accepted.data));
   const hash=await import('../src/service.js').then(m=>m.tokenHash(b64(grantBytes(packet.grant))+'.'+packet.signature));
   const receipt=await h.send('/grant-status?idempotencyKey='+packet.grant.idempotencyKey);assert.equal(receipt.data.sequence,accepted.data.sequence);assert.equal(receipt.data.contentHash,hash);
   c=await management(h);const row=c.subjects.find((s:any)=>s.deviceId==='device-C');assert.equal(row.currentGrant.grant.role,role);assert.equal(BigInt(row.highestGrantGeneration),++previous);
   assert.equal(c.issuerEvidence.source.view.authorities.some((n:any)=>n.grant.grant.role==='none'),false);
   const changed:SignedGrant={...packet,grant:{...packet.grant,role:role==='ro'?'rw':'ro',envelope:b64(Buffer.alloc(80,126))}};changed.signature=b64(ed25519.sign(grantBytes(changed.grant),seeds.A!));assert.equal((await h.send('/grants','POST',changed)).status,409);
  }
  const restored=update(c,'device-C','ro','dag-management-restore');assert.equal((await h.send('/grants','POST',restored)).status,200);const after=await management(h);assert.equal(after.subjects.find((s:any)=>s.deviceId==='device-C').highestGrantGeneration,String(previous+1n));
  const stale=update(c,'device-C','rw','dag-management-stale');assert.equal((await h.send('/grants','POST',stale)).status,409);assert.deepEqual((await h.send('/grant-status?idempotencyKey=dag-management-stale')).data,{idempotencyKey:'dag-management-stale',accepted:false});
  const own=update(after,'device-A','admin','dag-management-expire-actor',String(Math.floor(Date.now()/1000)+2));assert.equal((await h.send('/grants','POST',own)).status,200);
  const temporary=await management(h),beyond=update(temporary,'device-C','admin','dag-management-expiry-escalation');assert.equal((await h.send('/grants','POST',beyond)).status,403);
  await new Promise(resolve=>setTimeout(resolve,Math.max(1,Number(own.grant.expiresAt)*1000-Date.now()+20)));
  assert.equal((await h.send(managementPath)).status,403);assert.equal((await h.send('/grants','POST',beyond)).status,403);
  const receipt=await h.send('/grant-status?idempotencyKey=dag-management-restore');assert.equal(receipt.status,200);assert.equal(receipt.data.accepted,true);
 }finally{await h.close();}
});
test('P4授权写/控制缺目标归档均failclosed，保留unknown原收据',async()=>{
 const h=await harness('node');try{
  await enterDAG(h);const c=await management(h),packet=update(c,'device-C','rw','dag-management-bad-archive');
  await h.db!.store.transaction(h.account.id,a=>{delete (a as any).deviceEnrollments['device-C'];});
  assert.equal((await h.send(managementPath)).status,403);assert.equal((await h.send('/grants','POST',packet)).status,403);
  assert.deepEqual((await h.send('/grant-status?idempotencyKey='+packet.grant.idempotencyKey)).data,{idempotencyKey:packet.grant.idempotencyKey,accepted:false});
 }finally{await h.close();}
});
