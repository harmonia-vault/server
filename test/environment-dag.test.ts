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
import {environmentChangeBytes,type EnvironmentChange,type SignedEnvironmentChangeV2} from '../src/environments.js';
import {environmentChangeHash,environmentOriginBytes,environmentRights} from '../src/environment-origin.js';
import {issuerAuthorityHash} from '../src/issuer-proof.js';
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
function grant(h:H,environmentId:string,keyVersion:string,previous:SignedGrant,id:string):SignedGrant {
 const g={...previous.grant,environmentId,keyVersion,grantGeneration:previous.grant.environmentId===environmentId?String(BigInt(previous.grant.grantGeneration)+1n):'1',issuerDeviceId:'device-A',idempotencyKey:id,envelope:b64(Buffer.alloc(80,99))};
 return {grant:g,signature:b64(ed25519.sign(grantBytes(g),seeds.A!))};
}
function packet(h:H,control:any,id:string,env:string,op:'create'|'rotate',mutations:any[]=[]):SignedEnvironmentChangeV2 {
 const own=control.grants.find((g:SignedGrant)=>g.grant.subjectDeviceId==='device-A') as SignedGrant;
 const previous=op==='create'?'0':own.grant.keyVersion,keyVersion=String(BigInt(previous)+1n),before=op==='create'?[]:control.grants;
 const grants=(op==='create'?[own]:before).map((g:SignedGrant,i:number)=>grant(h,env,keyVersion,g,id+'-g-'+i));
 const c:EnvironmentChange={accountId:h.account.id,accountGeneration:'1',deviceId:'device-A',environmentId:env,operation:op,authorityEnvironmentId:own.grant.environmentId,authorityKeyVersion:own.grant.keyVersion,authorityGrantGeneration:own.grant.grantGeneration,previousKeyVersion:previous,keyVersion,expectedSequence:String(control.sequence),idempotencyKey:id,labelPayload:b64(Buffer.alloc(40,43)),recoveryGeneration:control.issuerEvidence.source.view.trustRoot.recoveryGeneration,recoveryEnvelope:b64(Buffer.alloc(80,80)),grants,mutations};
 const signature=b64(ed25519.sign(environmentChangeBytes(c),seeds.A!));
 const origin={accountId:c.accountId,accountGeneration:c.accountGeneration,actorDeviceId:c.deviceId,environmentId:env,operation:op,authorityEnvironmentId:c.authorityEnvironmentId,authorityKeyVersion:c.authorityKeyVersion,authorityGrantGeneration:c.authorityGrantGeneration,previousKeyVersion:previous,keyVersion,expectedSequence:c.expectedSequence,idempotencyKey:id,changeHash:environmentChangeHash(environmentChangeBytes(c),signature),authorityHash:issuerAuthorityHash(own),before:before.map(environmentRights).sort((a:any,b:any)=>a.subjectDeviceId<b.subjectDeviceId?-1:1),after:grants.map(environmentRights).sort((a:any,b:any)=>a.subjectDeviceId<b.subjectDeviceId?-1:1)};
 return {change:c,signature,origin:{origin,signature:b64(ed25519.sign(environmentOriginBytes(origin),seeds.A!))}};
}
async function control(h:H,env:string){const r=await h.send('/issuer-evidence?environmentId='+env+'&capability='+capability);assert.equal(r.status,200,JSON.stringify(r.data));assert.equal(r.major,'2');assert.equal(r.data.issuerEvidence.profile,'harmonia/issuer-proof/v4');return r.data;}
for(const backend of ['node','worker'] as const)test(`${backend}真实HTTP/SQLite：P4环境CRUD与完整接收者轮换、major2和原包收据`,{timeout:30000},async()=>{
 const h=await harness(backend);try{
  await enterDAG(h);
  const initial=await control(h,'env-fixture'),created=packet(h,initial,'p4-create','env-p4','create');
  assert.equal((await h.send('/environment-changes-v4','POST',created,'A','1')).status,426);
  assert.equal((await h.send('/environment-changes-v4?extra=1','POST',created)).status,400);
  const accepted=await h.send('/environment-changes-v4','POST',created);assert.equal(accepted.status,200,JSON.stringify(accepted.data));assert.equal(accepted.data.sequence,initial.sequence+1);
  for(const version of ['2','3','4']){const status=await h.send('/environment-changes-v'+version+'/p4-create');assert.equal(status.status,200);assert.equal(status.data.sequence,accepted.data.sequence);assert.match(status.data.contentHash,/^[a-f0-9]{64}$/);}
  const replay=await h.send('/environment-changes-v2','POST',created);assert.equal(replay.status,200);assert.equal(replay.data.sequence,accepted.data.sequence);assert.equal(replay.data.replayed,true);
  const conflicting=structuredClone(created);conflicting.change.labelPayload=b64(Buffer.alloc(40,51));conflicting.signature=b64(ed25519.sign(environmentChangeBytes(conflicting.change),seeds.A!));assert.equal((await h.send('/environment-changes-v4','POST',conflicting)).status,409);
  for(const cap of ['issuer-origin-v1','issuer-recovery-v1'])assert.equal((await h.send('/issuer-evidence?environmentId=env-p4&capability='+cap)).status,426);
  const z=await control(h,'env-p4');
  const own=z.grants[0] as SignedGrant,b=Object.values(h.account.grants).find(g=>g.grant.subjectDeviceId==='device-B')!;
  const reader={...own.grant,subjectDeviceId:b.grant.subjectDeviceId,subjectSigningPublicKey:b.grant.subjectSigningPublicKey,subjectReceivingPublicKey:b.grant.subjectReceivingPublicKey,grantGeneration:'1',role:'ro' as const,expiresAt:String(Math.floor(Date.now()/1000)+600),idempotencyKey:'p4-reader',envelope:b64(Buffer.alloc(80,61))};
  assert.equal((await h.send('/grants','POST',{grant:reader,signature:b64(ed25519.sign(grantBytes(reader),seeds.A!))})).status,200);
  const before=await control(h,'env-p4');assert.equal(before.grants.length,2);
  const renamed={...created.change,operation:'rename' as const,authorityEnvironmentId:'env-p4',authorityKeyVersion:'1',authorityGrantGeneration:'1',previousKeyVersion:'1',keyVersion:'1',expectedSequence:String(before.sequence),idempotencyKey:'p4-rename',grants:[],mutations:[],recoveryEnvelope:'',labelPayload:b64(Buffer.alloc(40,52))};
  assert.equal((await h.send('/environment-changes','POST',{change:renamed,signature:b64(ed25519.sign(environmentChangeBytes(renamed),seeds.A!))})).status,200);
  const fresh=await control(h,'env-p4'),rotated=packet(h,fresh,'p4-rotate','env-p4','rotate');
  assert.equal((await h.send('/environment-changes-v3','POST',rotated)).status,426);
  assert.equal((await h.send('/environment-changes','POST',{change:rotated.change,signature:rotated.signature})).status,426);
  const incomplete=packet(h,{...fresh,grants:fresh.grants.filter((g:SignedGrant)=>g.grant.subjectDeviceId==='device-A')},'p4-rotate-incomplete','env-p4','rotate');
  const missing=await h.send('/environment-changes-v4','POST',incomplete);assert.equal(missing.status,409);assert.equal(missing.data.error,'device_envelope_set_incomplete');
  const stale=packet(h,{...fresh,sequence:fresh.sequence-1},'p4-rotate-stale','env-p4','rotate');assert.equal((await h.send('/environment-changes-v4','POST',stale)).status,409);
  assert.deepEqual((await h.send('/environment-changes-v4/p4-rotate-incomplete')).data,{state:'unknown'});
  const rr=await h.send('/environment-changes-v4','POST',rotated);assert.equal(rr.status,200,JSON.stringify(rr.data));
  const after=await control(h,'env-p4');assert.equal(after.grants.length,2);assert.equal(after.grants.find((g:SignedGrant)=>g.grant.subjectDeviceId==='device-B').grant.expiresAt,reader.expiresAt);
  assert.ok(after.grants.every((g:SignedGrant)=>g.grant.keyVersion==='2'&&g.grant.grantGeneration==='2'));
  const deleted={...renamed,operation:'delete' as const,authorityKeyVersion:'2',authorityGrantGeneration:'2',previousKeyVersion:'2',keyVersion:'2',expectedSequence:String(after.sequence),idempotencyKey:'p4-delete',labelPayload:''};
  assert.equal((await h.send('/environment-changes','POST',{change:deleted,signature:b64(ed25519.sign(environmentChangeBytes(deleted),seeds.A!))})).status,200);
  const tombstone=await h.send('/pull?after=0&scope=authorizations&capability='+capability,'GET',undefined,'B');assert.equal(tombstone.status,200,JSON.stringify(tombstone.data));assert.deepEqual(tombstone.data.events,[]);assert.ok(tombstone.data.environmentEvents.some((e:any)=>e.change.change.idempotencyKey==='p4-delete'));
 }finally{await h.close();}
});

test('旧已接受V2包进入DAG后仍仅返回原收据；新旧路由/当前降权不能变成新写',async()=>{
 const h=await harness('node');try{
  const old=await h.send('/issuer-evidence?environmentId=env-fixture&capability=issuer-origin-v1');assert.equal(old.status,200);
  old.data.issuerEvidence={source:{view:{trustRoot:old.data.issuerEvidence.trustRoot}}};
  const original=packet(h,old.data,'pre-dag-original','env-pre-dag','create');
  const accepted=await h.send('/environment-changes-v2','POST',original);assert.equal(accepted.status,200,JSON.stringify(accepted.data));
  const receipt=await h.send('/environment-changes-v2/pre-dag-original');
  await enterDAG(h);
  const replay=await h.send('/environment-changes-v4','POST',original);assert.equal(replay.status,200,JSON.stringify(replay.data));assert.equal(replay.data.sequence,accepted.data.sequence);assert.equal(replay.data.replayed,true);
  const migrated=await h.send('/environment-changes-v4/pre-dag-original');assert.deepEqual(migrated.data,receipt.data);
  const current=await control(h,'env-fixture'),pending=packet(h,current,'after-dag-stale','env-after-dag-stale','create');
  const g={...current.grants.find((g:SignedGrant)=>g.grant.subjectDeviceId==='device-A').grant,grantGeneration:'2',role:'ro' as const,idempotencyKey:'actor-demote'};
  const downgrade=await h.send('/grants','POST',{grant:g,signature:b64(ed25519.sign(grantBytes(g),seeds.A!))});assert.equal(downgrade.status,200);
  assert.equal((await h.send('/environment-changes-v4','POST',pending)).status,403);
  assert.equal((await h.send('/environment-changes-v4','POST',original)).status,403);
  assert.deepEqual((await h.send('/environment-changes-v4/after-dag-stale')).data,{state:'unknown'});
  assert.deepEqual((await h.send('/environment-changes-v4/pre-dag-original')).data,receipt.data);
 }finally{await h.close();}
});
