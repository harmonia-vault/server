import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { build } from 'esbuild';
import { Miniflare } from 'miniflare';
import { ed25519,x25519 } from '@noble/curves/ed25519.js';
import { nodeStore } from '../src/node-store.js';
import { nodeServer } from '../src/node-runtime.js';
import { VaultService } from '../src/service.js';
import { nodeHarness,sign,b64,seeds } from './recovery-origin-fixtures.js';
import { recoveryKeys } from './fixtures.js';
import { issuerAuthorityHash } from '../src/issuer-proof.js';
import { trustRootPayload } from '../src/trust-root.js';
import { grantBytes } from '../src/protocol.js';
import { recoveryManifestHash,recoveryAdminHash,recoveryEnvelopesHash,recoveryRootHash } from '../src/recovery-authority-wire.js';
import { recoveredRightsHash,recoveredGrantsHash,recoveredEnvelopesHash } from '../src/recovered-device-wire.js';
import { sourceHash,transitionBytesV2,recoveredEnrollmentBytesV2,transitionHashV2,recoveredDeviceHashV2,type RecoveryTransitionCommandV2,type RecoveredDeviceCommandV2 } from '../src/recovery-dag-wire.js';
import { verifiedAccountDAG, buildIssuerRecoveryDAGEvidence, type RecoveryDAGAccount } from '../src/recovery-dag-account.js';
import { enrollmentV5Fields, type EnrollmentApprovalV5 } from '../src/issuer-dag.js';
import { canonical, pairingProfile, transcriptHash } from '../src/enrollment-wire.js';
import { relayFields } from '../src/enrollment.js';
const cap='capability=issuer-recovery-dag-v1';
const vector=JSON.parse(readFileSync(new URL('./vectors/recovery-dag-v1.json',import.meta.url),'utf8'));
async function harness(){
 const old=await nodeHarness();const account=structuredClone(old.read());await old.close();
 const dir=mkdtempSync(join(tmpdir(),'harmonia-dag-http-')),db=nodeStore(join(dir,'account.sqlite'));db.store.create(account);
 const server=nodeServer(new VaultService(db.store,{allowRegistration:true,requireEmailVerification:false}));server.server.listen(0,'127.0.0.1');await once(server.server,'listening');const address=server.server.address();assert.ok(address&&typeof address!=='string');
 const base=`http://127.0.0.1:${address.port}/v1/accounts/${account.id}`,tokens=new Map<string,string>([['login',b64(Buffer.alloc(32,61))],['A',b64(Buffer.alloc(32,65))]]);
 const send=async(path:string,method='GET',body?:unknown,who='R',major:string|undefined='2')=>{
  const response=await fetch(base+path,{method,headers:{'content-type':'application/json',authorization:'Bearer '+tokens.get(who),'x-harmonia-account-generation':'1',...(who==='A'||who.startsWith('recovered-')?{'x-harmonia-device-id':who==='A'?'device-A':who}:{}),...(major?{'Harmonia-Protocol-Major':major}:{})},...(body===undefined?{}:{body:JSON.stringify(body)})});return {status:response.status,major:response.headers.get('Harmonia-Protocol-Major'),data:await response.json() as any};
 };
 const session=async(seed:Uint8Array,generation:string)=>{
  const c=await send('/recovery-challenges','POST',{accountGeneration:'1'},'login');assert.equal(c.status,200);const k=recoveryKeys(seed,account.id,generation);
  assert.deepEqual(c.data.signingPayload,['harmonia/recovery-proof/v1',account.id,'1',generation,c.data.challengeId,c.data.nonce,String(c.data.expiresAt)]);
  const r=await send('/recovery-sessions','POST',{accountGeneration:'1',challengeId:c.data.challengeId,signature:sign(c.data.signingPayload,k.signingSeed)},'login');assert.equal(r.status,200,JSON.stringify(r.data));tokens.set('R',r.data.token);return r;
 };
 return {account,db,tokens,send,session,read:()=>db.store.read(account.id) as RecoveryDAGAccount,close:async()=>{server.closeNotifications();server.server.close();await once(server.server,'close');db.sql.close();rmSync(dir,{recursive:true,force:true});}};
}
type Harness=Awaited<ReturnType<typeof harness>>;
function transition(h:Harness,c:any,id:string,oldSeed:Uint8Array,newSeed:Uint8Array):RecoveryTransitionCommandV2{
 const submission=structuredClone(vector.proof.records.find((r: any) => r.kind === 'transition-v2').record.submission),t=submission.transition,newGeneration=String(BigInt(c.oldRecoveryGeneration)+1n),k=recoveryKeys(newSeed,h.account.id,newGeneration),old=recoveryKeys(oldSeed,h.account.id,c.oldRecoveryGeneration),root=c.dependencyBundle.initialization.proposal.device;
 assert.equal(c.oldRecoverySigningPublicKey,old.signingPublicKey);assert.equal(c.oldRecoveryReceivingPublicKey,old.receivingPublicKey);
 submission.environmentManifest=c.environmentManifest;submission.authoritySet=c.authoritySet;submission.issuerEvidence=c.issuerEvidence;
 submission.envelopes=c.environmentManifest.map((e:any)=>({...e,envelope:b64(Buffer.alloc(80,41))}));
 submission.newTrustRoot={rootDeviceId:root.id,rootSigningPublicKey:root.signingPublicKey,rootReceivingPublicKey:root.receivingPublicKey,recoveryGeneration:newGeneration,recoverySigningPublicKey:k.signingPublicKey,recoveryReceivingPublicKey:k.receivingPublicKey,signature:''};submission.newTrustRoot.signature=sign(trustRootPayload(h.account.id,'1',submission.newTrustRoot),k.signingSeed);
 Object.assign(t,{accountId:h.account.id,accountGeneration:'1',operationId:id,challengeId:c.challengeId,nonce:c.nonce,expiresAt:String(c.expiresAt),sessionHash:c.sessionHash,expectedSequence:c.expectedSequence,previousTransitionHash:c.previousTransitionHash,oldRecoveryGeneration:c.oldRecoveryGeneration,oldRecoverySigningPublicKey:c.oldRecoverySigningPublicKey,oldRecoveryReceivingPublicKey:c.oldRecoveryReceivingPublicKey,newRecoveryGeneration:newGeneration,newRecoverySigningPublicKey:k.signingPublicKey,newRecoveryReceivingPublicKey:k.receivingPublicKey,authorizationKind:c.authorizationKind,authorizerDeviceId:c.authorizerDeviceId,environmentManifestHash:recoveryManifestHash(submission.environmentManifest),authoritySetHash:c.authorizationKind==='old-recovery'?'':recoveryAdminHash(submission.authoritySet),issuerEvidenceHash:c.issuerEvidence?sourceHash(c.issuerEvidence):'',envelopesHash:recoveryEnvelopesHash(submission.envelopes),newTrustRootHash:recoveryRootHash(h.account.id,'1',submission.newTrustRoot)});
 submission.authorizationSignature=b64(ed25519.sign(transitionBytesV2(t),old.signingSeed));submission.newRecoverySignature=b64(ed25519.sign(transitionBytesV2(t),k.signingSeed));return {submission,dependencyBundle:c.dependencyBundle};
}
async function recover(h:Harness,id:string,recoverySeed:Uint8Array,edSeed:Uint8Array,xSeed:Uint8Array){
 const pub=b64(ed25519.getPublicKey(edSeed)),recv=b64(x25519.getPublicKey(xSeed));const c=await h.send(`/recovered-device-challenges-v2?${cap}`,'POST',{operationId:'operation-'+id,deviceId:id,deviceSigningPublicKey:pub,deviceReceivingPublicKey:recv});assert.equal(c.status,200,JSON.stringify(c.data));
 const source=c.data.issuerEvidence,view=source.view;
 const s=structuredClone(vector.proof.records.find((r: any) => r.kind === 'recovered-v2').record.submission);s.certificateVersion='5';s.capabilities=['issuer-recovery-dag-v1'];s.issuerEvidence=source;
 s.selectedRights=view.targets.map((t:any)=>{const g=view.authorities.find((n:any)=>{return issuerAuthorityHash(n.grant)===t.authorityHash;}).grant.grant;return {environmentId:g.environmentId,keyVersion:g.keyVersion,role:'admin',expiresAt:'0'};}).sort((a:any,b:any)=>a.environmentId<b.environmentId?-1:1);
 s.envelopes=s.selectedRights.map((r:any)=>({environmentId:r.environmentId,keyVersion:r.keyVersion,envelope:b64(Buffer.alloc(80,43))}));s.grants=s.selectedRights.map((r:any,i:number)=>{const grant={accountId:h.account.id,accountGeneration:'1',issuerDeviceId:id,subjectDeviceId:id,subjectSigningPublicKey:pub,subjectReceivingPublicKey:recv,environmentId:r.environmentId,keyVersion:r.keyVersion,grantGeneration:'1',role:r.role,expiresAt:r.expiresAt,idempotencyKey:id+'-grant-'+i,envelope:s.envelopes[i].envelope};return {grant,signature:b64(ed25519.sign(grantBytes(grant),edSeed))};});
 Object.assign(s.enrollment,{accountId:h.account.id,accountGeneration:'1',recoveryGeneration:c.data.recoveryGeneration,recoveryTransitionHash:c.data.recoveryTransitionHash,operationId:'operation-'+id,challengeId:c.data.challengeId,nonce:c.data.nonce,expiresAt:String(c.data.expiresAt),restrictedSessionHash:c.data.restrictedSessionHash,expectedSequence:c.data.expectedSequence,deviceId:id,deviceSigningPublicKey:pub,deviceReceivingPublicKey:recv,selectedRightsHash:recoveredRightsHash(s.selectedRights),grantsHash:recoveredGrantsHash(s.grants),issuerEvidenceHash:sourceHash(source),envelopesHash:recoveredEnvelopesHash(s.envelopes)});
 const k=recoveryKeys(recoverySeed,h.account.id,s.enrollment.recoveryGeneration);s.recoverySignature=b64(ed25519.sign(recoveredEnrollmentBytesV2(s.enrollment),k.signingSeed));s.deviceSignature=b64(ed25519.sign(recoveredEnrollmentBytesV2(s.enrollment),edSeed));const command:RecoveredDeviceCommandV2={submission:s,dependencyBundle:c.data.dependencyBundle};
 const r=await h.send(`/recovered-devices-v2?${cap}`,'POST',command);assert.equal(r.status,200,JSON.stringify(r.data));assert.equal(r.data.contentHash,recoveredDeviceHashV2(s));
 const boot=await h.send('/boot-challenges','POST',{deviceId:id,accountGeneration:'1'},'login');assert.equal(boot.status,200);const token=await h.send('/boot-sessions','POST',{deviceId:id,accountGeneration:'1',challengeId:boot.data.challengeId,signature:sign(boot.data.signingPayload,edSeed)},'login');assert.equal(token.status,200);h.tokens.set(id,token.data.token);return command;
}
test('NodeTCP+SQLite：major2实际两次恢复与显式B/C登记，原根/历史与原ID接受顺序持续保留',async()=>{
 const h=await harness();try{
  const old=Buffer.alloc(32,66),next=Buffer.alloc(32,71),last=Buffer.alloc(32,74);await h.session(old,'1');
  let c=await h.send(`/recovery-authority-challenges-v2?${cap}`,'POST',{operationId:'first-dag',authorizationKind:'old-recovery'});assert.equal(c.status,200,JSON.stringify(c.data));
  const first=transition(h,c.data,'first-dag',old,next);let r=await h.send(`/recovery-authority-transitions-v2?${cap}`,'POST',first);assert.equal(r.status,200,JSON.stringify(r.data));assert.equal(r.major,'2');assert.equal(r.data.sequence,11);
  await recover(h,'recovered-DAG-B',next,Buffer.alloc(32,72),Buffer.alloc(32,73));await h.session(next,'2');
  c=await h.send(`/recovery-authority-challenges-v2?${cap}`,'POST',{operationId:'second-dag',authorizationKind:'old-recovery'});assert.equal(c.status,200,JSON.stringify(c.data));const second=transition(h,c.data,'second-dag',next,last);
  r=await h.send(`/recovery-authority-transitions-v2?${cap}`,'POST',second);assert.equal(r.status,200,JSON.stringify(r.data));assert.equal(r.data.sequence,13);
  await recover(h,'recovered-DAG-C',last,Buffer.alloc(32,75),Buffer.alloc(32,76));
  const pull=await h.send(`/pull?after=0&${cap}`,'GET',undefined,'recovered-DAG-C');assert.equal(pull.status,200,JSON.stringify(pull.data));assert.equal(pull.data.issuerEvidence.profile,'harmonia/issuer-proof/v4');assert.equal(pull.data.issuerEvidence.records.length,4);
  assert.equal(verifiedAccountDAG(h.read()).head.generation,'3');assert.equal(h.read().trustRoot!.rootDeviceId,h.account.trustRoot!.rootDeviceId);
  const thirdChallenge=await h.send(`/recovery-authority-challenges-v2?${cap}`,'POST',{operationId:'third-admin-dag',authorizationKind:'all-environments-admin'},'recovered-DAG-C');assert.equal(thirdChallenge.status,200,JSON.stringify(thirdChallenge.data));
  const third=transition(h,thirdChallenge.data,'third-admin-dag',last,Buffer.alloc(32,77));third.submission.authorizationSignature=b64(ed25519.sign(transitionBytesV2(third.submission.transition),Buffer.alloc(32,75)));
  const thirdAccepted=await h.send(`/recovery-authority-transitions-v2?${cap}`,'POST',third,'recovered-DAG-C');assert.equal(thirdAccepted.status,200,JSON.stringify(thirdAccepted.data));assert.equal(verifiedAccountDAG(h.read()).head.generation,'4');
  await h.session(Buffer.alloc(32,77),'4');
  const obsolete=await h.send('/recovery-challenges','POST',{accountGeneration:'1'},'login');assert.equal(obsolete.status,200);const oldKeys=recoveryKeys(last,h.account.id,'3');assert.equal((await h.send('/recovery-sessions','POST',{accountGeneration:'1',challengeId:obsolete.data.challengeId,signature:sign(obsolete.data.signingPayload,oldKeys.signingSeed)},'login')).status,403);

  assert.equal((await h.send('/recovery-authority-challenges?capability=issuer-recovery-v1','POST',{operationId:'legacy-bypass',authorizationKind:'old-recovery'})).status,404);
  assert.equal((await h.send('/pull?after=0&capability=issuer-recovery-v1','GET',undefined,'recovered-DAG-C')).status,400);
  assert.equal((await h.send(`/recovered-devices-v2?${cap}`,'POST',{},'R','')).status,426);
 }finally{await h.close();}
});
test('NodeTCP：接受后丢响应只查原ID/hash，原包重试无新序号，不同body/nonce或跨旧route冲突',async()=>{
 const h=await harness();try{
  await h.session(Buffer.alloc(32,66),'1');const c=await h.send(`/recovery-authority-challenges-v2?${cap}`,'POST',{operationId:'unknown-original',authorizationKind:'old-recovery'});assert.equal(c.status,200,JSON.stringify(c.data));const p=transition(h,c.data,'unknown-original',Buffer.alloc(32,66),Buffer.alloc(32,71));
  const accepted=await h.send(`/recovery-authority-transitions-v2?${cap}`,'POST',p);assert.equal(accepted.status,200,JSON.stringify(accepted.data));
  const receipt=await h.send(`/recovery-authority-transitions-v2/unknown-original?${cap}`);assert.equal(receipt.data.contentHash,transitionHashV2(p.submission));assert.equal(receipt.data.sequence,accepted.data.sequence);
  const retry=await h.send(`/recovery-authority-transitions-v2?${cap}`,'POST',p);assert.equal(retry.data.replayed,true);assert.equal(retry.data.sequence,accepted.data.sequence);
  const changed=structuredClone(p);changed.submission.transition.nonce=b64(Buffer.alloc(32,99));assert.equal((await h.send(`/recovery-authority-transitions-v2?${cap}`,'POST',changed)).status,409);
  assert.equal((await h.send('/recovery-authority-transitions?capability=issuer-recovery-v1','POST',p.submission)).status,404);
  assert.equal(h.read().sequence,accepted.data.sequence);
 }finally{await h.close();}
});
test('真实SQLite提交失败不切恢复代际/公钥/任何封套，原nonce包恢复后仍可唯一接受',async()=>{
 const h=await harness();try{
  await h.session(Buffer.alloc(32,66),'1');const c=await h.send(`/recovery-authority-challenges-v2?${cap}`,'POST',{operationId:'atomic-fail',authorizationKind:'old-recovery'});assert.equal(c.status,200,JSON.stringify(c.data));const p=transition(h,c.data,'atomic-fail',Buffer.alloc(32,66),Buffer.alloc(32,71));const before=structuredClone(h.read());
  const original=h.db.sql.execute.bind(h.db.sql);let failed=false;h.db.sql.execute=(query,params)=>{if(!failed&&query.startsWith('UPDATE accounts')){failed=true;throw Error('synthetic SQLite commit fault');}original(query,params);};
  assert.equal((await h.send(`/recovery-authority-transitions-v2?${cap}`,'POST',p)).status,500);h.db.sql.execute=original;
  const after=h.read();assert.equal(after.recoveryGeneration,before.recoveryGeneration);assert.equal(after.recoverySigningPublicKey,before.recoverySigningPublicKey);assert.deepEqual(after.environments,before.environments);assert.equal(after.sequence,before.sequence);
  const retry=await h.send(`/recovery-authority-transitions-v2?${cap}`,'POST',p);assert.equal(retry.status,200,JSON.stringify(retry.data));assert.equal(retry.data.replayed,false);assert.equal(retry.data.sequence,before.sequence+1);
 }finally{await h.close();}
});

test('证书5独立HTTP中继/两签接受后可Boot+Proof4读；同原ID重查且旧profile不接受',async()=>{
 const h=await harness();try{
  await h.session(Buffer.alloc(32,66),'1');const ch=await h.send(`/recovery-authority-challenges-v2?${cap}`,'POST',{operationId:'v5-rotate',authorizationKind:'old-recovery'});const t=transition(h,ch.data,'v5-rotate',Buffer.alloc(32,66),Buffer.alloc(32,71));assert.equal((await h.send(`/recovery-authority-transitions-v2?${cap}`,'POST',t)).status,200);
  await recover(h,'recovered-DAG-B',Buffer.alloc(32,71),Buffer.alloc(32,72),Buffer.alloc(32,73));
  const ed=Buffer.alloc(32,90),x=Buffer.alloc(32,91),id='recovered-paired-v5',key='pair-v5-original',proposal={idempotencyKey:key,deviceId:id,signingPublicKey:b64(ed25519.getPublicKey(ed)),receivingPublicKey:b64(x25519.getPublicKey(x)),approverDeviceId:'recovered-DAG-B',certificateVersion:'5',capabilities:['issuer-recovery-dag-v1']};
  const begun=await h.send('/pairings-v5','POST',proposal,'login');assert.equal(begun.status,200,JSON.stringify(begun.data));assert.equal((await h.send('/pairings-v5','POST',proposal,'login','')).status,426);
  const context=begun.data.context;
  for(const kind of ['message','confirmation'] as const)for(const side of ['initiator','approver'] as const){const payload=b64(Buffer.alloc(32,kind==='message'?(side==='initiator'?101:102):(side==='initiator'?103:104))),signature=sign(relayFields({context},{side,kind,payload}),side==='initiator'?ed:Buffer.alloc(32,72));const r=await h.send(`/pairings-v5/${key}/relay`,'POST',{side,kind,payload,signature},side==='initiator'?'login':'recovered-DAG-B');assert.equal(r.status,200,JSON.stringify(r.data));}
  const status=await h.send(`/pairings-v5/${key}`,'GET',undefined,'recovered-DAG-B');const s=status.data,hash=transcriptHash(s),a=h.read(),authority=Object.values(a.grants).filter(g=>g.grant.subjectDeviceId==='recovered-DAG-B');const proof=buildIssuerRecoveryDAGEvidence(a,'recovered-DAG-B',authority)!;
  const grants=authority.map((s,i)=>{const grant={...s.grant,issuerDeviceId:'recovered-DAG-B',subjectDeviceId:id,subjectSigningPublicKey:proposal.signingPublicKey,subjectReceivingPublicKey:proposal.receivingPublicKey,grantGeneration:'1',role:'ro' as const,idempotencyKey:key+'-'+i,envelope:b64(Buffer.alloc(80,94))};return {grant,signature:b64(ed25519.sign(grantBytes(grant),Buffer.alloc(32,72)))};});
  const certificate:EnrollmentApprovalV5={certificateVersion:'5',capabilities:['issuer-recovery-dag-v1'],context,pairingProfile,transcriptHash:hash,grants,issuerProof:proof,approverSignature:''};certificate.approverSignature=sign(enrollmentV5Fields(certificate),Buffer.alloc(32,72));
  const approved=await h.send(`/pairings-v5/${key}/approve`,'POST',{certificateVersion:'5',capabilities:['issuer-recovery-dag-v1'],grants,transcriptHash:hash,issuerProof:proof,signature:certificate.approverSignature},'recovered-DAG-B');assert.equal(approved.status,200,JSON.stringify(approved.data));
  const signature=b64(ed25519.sign(canonical(enrollmentV5Fields(certificate)),ed)),accepted=await h.send(`/pairings-v5/${key}/complete`,'POST',{signature},'login');assert.equal(accepted.status,200,JSON.stringify(accepted.data));assert.equal(accepted.data.sequence,13);
  const retry=await h.send(`/pairings-v5/${key}/complete`,'POST',{signature},'login');assert.equal(retry.data.replayed,true);assert.equal(retry.data.sequence,13);assert.equal((await h.send(`/pairings-v5/${key}`,'GET',undefined,'login')).data.approval.initiatorSignature,signature);
  assert.equal((await h.send(`/pairings-v4/${key}`,'GET',undefined,'login')).status,404);
  const boot=await h.send('/boot-challenges','POST',{deviceId:id,accountGeneration:'1'},'login');const bound=await h.send('/boot-sessions','POST',{deviceId:id,accountGeneration:'1',challengeId:boot.data.challengeId,signature:sign(boot.data.signingPayload,ed)},'login');assert.equal(bound.status,200);h.tokens.set(id,bound.data.token);
  const pull=await h.send(`/pull?after=0&${cap}`,'GET',undefined,id);assert.equal(pull.status,200,JSON.stringify(pull.data));assert.equal(pull.data.issuerEvidence.profile,'harmonia/issuer-proof/v4');assert.equal(pull.data.issuerEvidence.source.view.path.at(-1).enrollment.certificateVersion,'5');assert.equal(h.read().sequence,13);
 }finally{await h.close();}
});

test('所有旧设备已撤销/全部current none且无变量事件：恢复仍取已接受grantHistory来源',async()=>{
 const h=await harness();try{
  h.db.store.transaction(h.account.id,raw=>{const a=raw as RecoveryDAGAccount;
   for(const [key,old] of Object.entries(a.grants)){const grant={...old.grant,issuerDeviceId:'device-A',role:'none' as const,grantGeneration:String(BigInt(old.grant.grantGeneration)+1n),envelope:'',idempotencyKey:'none-'+old.grant.subjectDeviceId};const signed={grant,signature:b64(ed25519.sign(grantBytes(grant),seeds.A!))};a.grantHistory!.push({sequence:++a.sequence,grant:signed,authorization:structuredClone(h.account.grants['env-fixture/device-A']!)});a.grants[key]=signed;}
   for(const d of Object.values(a.devices))d.revoked=true;a.sessions=a.sessions.filter(s=>!s.deviceId);assert.equal(a.events.length,0);
  });
  await h.session(Buffer.alloc(32,66),'1');const vault=await h.send(`/recovery-vault-v2?${cap}`);assert.equal(vault.status,200,JSON.stringify(vault.data));assert.equal(vault.data.events.length,0);assert.ok(vault.data.currentGrants.every((g:any)=>g.grant.role==='none'));
  const c=await h.send(`/recovery-authority-challenges-v2?${cap}`,'POST',{operationId:'after-all-lost',authorizationKind:'old-recovery'});assert.equal(c.status,200);const p=transition(h,c.data,'after-all-lost',Buffer.alloc(32,66),Buffer.alloc(32,71));assert.equal((await h.send(`/recovery-authority-transitions-v2?${cap}`,'POST',p)).status,200);
  await recover(h,'recovered-after-all-lost',Buffer.alloc(32,71),Buffer.alloc(32,72),Buffer.alloc(32,73));assert.equal((await h.send(`/pull?after=0&${cap}`,'GET',undefined,'recovered-after-all-lost')).status,200);
  const collision={operationId:'cross-kind',deviceId:'cross-kind-device',deviceSigningPublicKey:b64(ed25519.getPublicKey(Buffer.alloc(32,95))),deviceReceivingPublicKey:b64(x25519.getPublicKey(Buffer.alloc(32,96)))};
  assert.equal((await h.send(`/recovered-device-challenges-v2?${cap}`,'POST',collision)).status,200);
  assert.equal((await h.send(`/recovery-authority-challenges-v2?${cap}`,'POST',{operationId:'cross-kind',authorizationKind:'old-recovery'})).status,409);
  assert.equal((await h.send(`/recovery-authority-challenges-v2?${cap}`,'POST',{operationId:'reverse-kind',authorizationKind:'old-recovery'})).status,200);
  assert.equal((await h.send(`/recovered-device-challenges-v2?${cap}`,'POST',{...collision,operationId:'reverse-kind'})).status,409);
 }finally{await h.close();}
});

test('真实workerd：discovery/edge失败/DO事务均回显major2，旧入口不绕DAG状态', {timeout:30000}, async()=>{
 const h=await harness(),dir=mkdtempSync(join(tmpdir(),'harmonia-dag-worker-'));let mf:Miniflare|undefined;
 try{
  const bundle=await build({entryPoints:['test/worker-harness.ts'],absWorkingDir:process.cwd(),bundle:true,write:false,format:'esm',platform:'browser',target:'es2023',external:['cloudflare:workers','node:*'],define:{Buffer:'Buffer'},banner:{js:'import {Buffer} from "node:buffer";'}});
  mf=new Miniflare({modules:true,script:bundle.outputFiles[0]!.text,compatibilityDate:'2026-07-30',compatibilityFlags:['nodejs_compat'],durableObjects:{INSTANCES:{className:'InstanceRegistry',useSQLite:true},ACCOUNTS:{className:'SyntheticVault',useSQLite:true},FIXTURES:{className:'SyntheticVault',useSQLite:true}},d1Databases:{DIRECTORY:'directory'},durableObjectsPersist:join(dir,'objects'),d1Persist:join(dir,'directory')});
  await mf.dispatchFetch('https://synthetic.invalid/test/seed',{method:'POST',body:JSON.stringify(h.account)});
  const discovery=await mf.dispatchFetch('https://synthetic.invalid/protocol-info',{headers:{'Harmonia-Protocol-Major':'2'}});assert.equal(discovery.status,200);assert.equal(discovery.headers.get('Harmonia-Protocol-Major'),'2');assert.deepEqual((await discovery.json() as any).supportedProtocolMajors,[2]);
  const edgeError=await mf.dispatchFetch('https://synthetic.invalid/not-a-route',{headers:{'Harmonia-Protocol-Major':'2'}});assert.equal(edgeError.status,404);assert.equal(edgeError.headers.get('Harmonia-Protocol-Major'),'2');
  const send:Harness['send']=async(path,method='GET',body,who='R',major='2')=>{const response=await mf!.dispatchFetch(`https://synthetic.invalid/v1/accounts/${h.account.id}${path}`,{method,headers:{'content-type':'application/json',authorization:'Bearer '+h.tokens.get(who),'x-harmonia-account-generation':'1',...(major?{'Harmonia-Protocol-Major':major}:{})},...(body===undefined?{}:{body:JSON.stringify(body)})});return {status:response.status,major:response.headers.get('Harmonia-Protocol-Major'),data:await response.json() as any};};
  const c=await send('/recovery-challenges','POST',{accountGeneration:'1'},'login'),k=recoveryKeys(Buffer.alloc(32,66),h.account.id,'1');assert.equal(c.major,'2');const r=await send('/recovery-sessions','POST',{accountGeneration:'1',challengeId:c.data.challengeId,signature:sign(c.data.signingPayload,k.signingSeed)},'login');assert.equal(r.status,200);assert.equal(r.major,'2');h.tokens.set('R',r.data.token);
  const ch=await send(`/recovery-authority-challenges-v2?${cap}`,'POST',{operationId:'worker-dag',authorizationKind:'old-recovery'});assert.equal(ch.status,200,JSON.stringify(ch.data));const p=transition(h,ch.data,'worker-dag',Buffer.alloc(32,66),Buffer.alloc(32,71));const accepted=await send(`/recovery-authority-transitions-v2?${cap}`,'POST',p);assert.equal(accepted.status,200,JSON.stringify(accepted.data));assert.equal(accepted.major,'2');assert.equal((await send('/recovery-authority-challenges?capability=issuer-recovery-v1','POST',{operationId:'legacy-worker',authorizationKind:'old-recovery'})).status,404);
 }finally{await mf?.dispose();await h.close();rmSync(dir,{recursive:true,force:true});}
});
