import { Fault, grantKey, type Session } from './model.js';
import { bytes, generation, identifier } from './protocol.js';
import { canonical, exact, own, hash } from './enrollment-wire.js';
import { device, next, permission, randomToken, sameAccount, session, tokenHash } from './service.js';
import type { Store } from './store.js';
import type { RecoveryAuth } from './lifecycle-wire.js';
import { recoveryManifestHash, type RecoveryAdminAuthority, type RecoveryEnvironmentVersion } from './recovery-authority-wire.js';
import { issuerAuthorityHash } from './issuer-proof.js';
import { accountDAGBundle, accountDAGPin, verifiedAccountDAG, buildIssuerRecoveryDAGEvidence, acceptedSourceDAG, type RecoveryDAGAccount } from './recovery-dag-account.js';
import { verifyRecoveryDependencyBundle } from './recovery-dag.js';
import { initializationDAGRow, recordRow, recordRows, sourceHash, transitionHashV2, recoveredDeviceHashV2, transitionReferencesV2, recoveredReferencesV2, type RecoveryDependencyBundle, type RecoverySource, type RecoveryTransitionCommandV2, type RecoveredDeviceCommandV2, type RecoveryDAGRecord } from './recovery-dag-wire.js';
import { recoveryEnvelopeEvidence } from './recovery-envelope-evidence.js';
export interface DAGAuthorityChallenge {
 operationId:string;challengeId:string;nonce:string;expiresAt:number;sessionHash:string;accountGeneration:string;
 authorizationKind:'old-recovery'|'all-environments-admin';chainMode:'continuous';authorizerDeviceId:string;expectedSequence:string;
 previousTransitionHash:string;oldRecoveryGeneration:string;oldRecoverySigningPublicKey:string;oldRecoveryReceivingPublicKey:string;
 environmentManifest:RecoveryEnvironmentVersion[];authoritySet:RecoveryAdminAuthority[];issuerEvidence:RecoverySource|null;
 dependencyBundle:RecoveryDependencyBundle;
}
export interface DAGRecoveredChallenge {
 operationId:string;challengeId:string;nonce:string;expiresAt:number;restrictedSessionHash:string;accountGeneration:string;
 expectedSequence:string;recoveryGeneration:string;recoveryTransitionHash:string;deviceId:string;deviceSigningPublicKey:string;deviceReceivingPublicKey:string;
 issuerEvidence:RecoverySource;dependencyBundle:RecoveryDependencyBundle;
}
type AuthoritySession=Session&{recoveryAuthorityHead?:string};
const ttl=120;
const manifest=(a:RecoveryDAGAccount):RecoveryEnvironmentVersion[]=>Object.values(a.environments).map(e=>({environmentId:e.id,keyVersion:e.keyVersion})).sort((a,b)=>a.environmentId<b.environmentId?-1:1);
const bundleContent=(b:RecoveryDependencyBundle):string=>JSON.stringify([initializationDAGRow(b.initialization),recordRows(b.records)]);
const same=(a:unknown,b:unknown):boolean=>JSON.stringify(a)===JSON.stringify(b);
const operation=(r:RecoveryDAGRecord):string=>r.kind.startsWith('transition')?(r as Extract<RecoveryDAGRecord,{kind:'transition-v1'|'transition-v2'}>).record.submission.transition.operationId:(r as Extract<RecoveryDAGRecord,{kind:'recovered-v1'|'recovered-v2'}>).record.submission.enrollment.operationId;
function current(a:RecoveryDAGAccount,auth:RecoveryAuth,h:string,now:number):AuthoritySession {
 sameAccount(a,auth.accountGeneration);const s=session(a,h,now,true) as AuthoritySession;
 if(s.kind==='recovery'){if(s.recoveryGeneration!==a.recoveryGeneration)throw new Fault(403,'recovery_session_stale');}
 else{if(!auth.deviceId||s.deviceId!==auth.deviceId)throw new Fault(403,'device_proof_required');device(a,auth.deviceId);}
 return s;
}
function allAdmin(a:RecoveryDAGAccount,id:string,now:number):void {
 const ids=Object.keys(a.environments);if(!ids.length||ids.some(e=>permission(a,id,e,now).role!=='admin'))throw new Fault(403,'all_environment_admin_required');
}
function novel(a:RecoveryDAGAccount,pubs:string[]):void {
 const d=verifiedAccountDAG(a);if(pubs[0]===pubs[1]||pubs.some(k=>d.head.seenKeys.has(k)||Object.values(a.devices).some(v=>v.signingPublicKey===k||v.receivingPublicKey===k)))throw new Fault(403,'key_purpose_invalid');
}
function recoveryTargets(a:RecoveryDAGAccount,grants:import('./model.js').SignedGrant[]):import('./model.js').SignedGrant[]{
 return manifest(a).map(e=>{const g=grants.find(g=>g.grant.environmentId===e.environmentId&&g.grant.keyVersion===e.keyVersion);if(!g)throw new Fault(403,'issuer_authority_unaccepted');return g;});
}
/** 恢复来源是已接受签历史，不是当前活设备的权限；全部设备撤销也不能丢失vault来源。 */
function recoverySources(a:RecoveryDAGAccount):import('./model.js').SignedGrant[]{
 const rows=[...Object.values(a.grants),...(a.grantHistory??[]).map(e=>e.grant)],seen=new Set<string>();
 return rows.filter(g=>{const id=g.grant.environmentId;if(g.grant.role==='none'||a.environments[id]?.keyVersion!==g.grant.keyVersion)return false;const h=issuerAuthorityHash(g);if(seen.has(h))return false;seen.add(h);return true;});
}
function priorOperation(a:RecoveryDAGAccount,id:string):RecoveryDAGRecord|undefined {return accountDAGBundle(a).records.find(r=>operation(r)===id);}
function oldChallengeConflict(a:RecoveryDAGAccount,id:string,kind:'transition'|'recovered'):void {
 if(kind==='transition'?own(a.recoveredDAGChallenges,id):own(a.recoveryDAGChallenges,id))throw new Fault(409,'idempotency_conflict');
 if(own(a.recoveryAuthorityChallenges,id)||own(a.recoveredDeviceChallenges,id)||own(a.recoveryRotations,id))throw new Fault(409,'idempotency_conflict');
}
function challengeView(c:DAGAuthorityChallenge|DAGRecoveredChallenge):Record<string,unknown>{return structuredClone(c) as unknown as Record<string,unknown>;}
/** 唯一账号事务内核对live权限、完整已接受历史、一次nonce后才原子切换。 */
export class RecoveryDAGService {
 constructor(readonly store:Store,private readonly clock:()=>number=()=>Math.floor(Date.now()/1000)){}
 private async authorized<T>(id:string,auth:RecoveryAuth,fn:(a:RecoveryDAGAccount,s:AuthoritySession,h:string,now:number)=>T):Promise<T>{
  identifier(id);generation(auth.accountGeneration);bytes(auth.token,32);if(auth.deviceId)identifier(auth.deviceId);const h=await tokenHash(auth.token);
  return this.store.transaction(id,account=>{const a=account as RecoveryDAGAccount,now=this.clock(),s=current(a,auth,h,now);return fn(a,s,h,now);});
 }
 async challenge(id:string,auth:RecoveryAuth,input:{operationId:string;authorizationKind:DAGAuthorityChallenge['authorizationKind'];chainMode:'continuous'}):Promise<Record<string,unknown>>{
  exact(input,['operationId','authorizationKind','chainMode']);identifier(input.operationId);if(!['old-recovery','all-environments-admin'].includes(input.authorizationKind)||input.chainMode!=='continuous')throw new Fault(400,'fields_invalid');
  return this.authorized(id,auth,(a,s,h,now)=>{
   const dag=verifiedAccountDAG(a);if(input.authorizationKind==='old-recovery'){if(s.kind!=='recovery')throw new Fault(403,'device_proof_required');}
   else{if(s.kind!=='login'||!auth.deviceId)throw new Fault(403,'device_proof_required');allAdmin(a,auth.deviceId,now);}
   const prior=own(a.recoveryDAGChallenges,input.operationId);if(prior){if(prior.sessionHash!==h||prior.authorizationKind!==input.authorizationKind)throw new Fault(409,'idempotency_conflict');return challengeView(prior);}
   if(priorOperation(a,input.operationId))throw new Fault(409,'idempotency_conflict');oldChallengeConflict(a,input.operationId,'transition');
   a.recoveryDAGChallenges??={};if(Object.keys(a.recoveryDAGChallenges).length>=128)throw new Fault(503,'account_capacity_reached');
   const environments=manifest(a);recoveryManifestHash(environments);let authoritySet:RecoveryAdminAuthority[]=[],issuerEvidence:RecoverySource|null=null;
   if(input.authorizationKind==='all-environments-admin'){
    const grants=environments.map(e=>a.grants[grantKey(e.environmentId,auth.deviceId!)]!);
    authoritySet=grants.map(s=>({environmentId:s.grant.environmentId,keyVersion:s.grant.keyVersion,grantGeneration:s.grant.grantGeneration,expiresAt:s.grant.expiresAt,authorityHash:issuerAuthorityHash(s)}));
    issuerEvidence=buildIssuerRecoveryDAGEvidence(a,auth.deviceId!,grants)!.source;
   }
   const c:DAGAuthorityChallenge={...input,challengeId:crypto.randomUUID(),nonce:randomToken(),expiresAt:now+ttl,sessionHash:h,accountGeneration:a.generation,authorizerDeviceId:input.authorizationKind==='all-environments-admin'?auth.deviceId!:'',expectedSequence:String(a.sequence),previousTransitionHash:dag.head.head,oldRecoveryGeneration:a.recoveryGeneration,oldRecoverySigningPublicKey:a.recoverySigningPublicKey!,oldRecoveryReceivingPublicKey:a.recoveryReceivingPublicKey!,environmentManifest:environments,authoritySet,issuerEvidence,dependencyBundle:accountDAGBundle(a)};
   a.recoveryDAGChallenges[input.operationId]=c;return challengeView(c);
  });
 }
 async transition(id:string,auth:RecoveryAuth,command:RecoveryTransitionCommandV2):Promise<Record<string,unknown>>{
  exact(command,['submission','dependencyBundle']);transitionReferencesV2(command.submission);const s=command.submission,t=s.transition,contentHash=transitionHashV2(s);
  return this.authorized(id,auth,(a,actor,h,now)=>{
   const c=own(a.recoveryDAGChallenges,t.operationId),prior=priorOperation(a,t.operationId);
   if(prior){if(prior.kind!=='transition-v2'||recordRow(prior)[1]!==contentHash||!c||c.sessionHash!==h||bundleContent(command.dependencyBundle)!==bundleContent(c.dependencyBundle))throw new Fault(409,'idempotency_conflict');return {sequence:prior.record.sequence,replayed:true,transitionHash:contentHash,contentHash};}
   const dag=verifiedAccountDAG(a);
   if(!c||c.sessionHash!==h||c.accountGeneration!==a.generation||c.expiresAt<=now||c.challengeId!==t.challengeId||c.nonce!==t.nonce||String(c.expiresAt)!==t.expiresAt||t.sessionHash!==h||t.accountId!==a.id||t.accountGeneration!==a.generation)throw new Fault(403,'challenge_invalid');
   if(t.authorizationKind!==c.authorizationKind||t.chainMode!=='continuous'||t.authorizerDeviceId!==c.authorizerDeviceId||t.expectedSequence!==c.expectedSequence||t.expectedSequence!==String(a.sequence)||t.previousTransitionHash!==c.previousTransitionHash||t.previousTransitionHash!==dag.head.head||t.oldRecoveryGeneration!==a.recoveryGeneration||t.oldRecoverySigningPublicKey!==a.recoverySigningPublicKey||t.oldRecoveryReceivingPublicKey!==a.recoveryReceivingPublicKey||!same(manifest(a),c.environmentManifest)||!same(s.environmentManifest,c.environmentManifest)||!same(s.authoritySet,c.authoritySet)||bundleContent(command.dependencyBundle)!==bundleContent(c.dependencyBundle)||bundleContent(command.dependencyBundle)!==bundleContent(accountDAGBundle(a))||s.legacyState!==null||(s.issuerEvidence===null)!==(c.issuerEvidence===null)||(s.issuerEvidence&&sourceHash(s.issuerEvidence)!==sourceHash(c.issuerEvidence!)))throw new Fault(409,'recovery_context_changed');
   if(t.authorizationKind==='old-recovery'){if(actor.kind!=='recovery')throw new Fault(403,'device_proof_required');}
   else{if(actor.kind!=='login'||auth.deviceId!==t.authorizerDeviceId)throw new Fault(403,'device_proof_required');allAdmin(a,auth.deviceId,now);acceptedSourceDAG(a,s.issuerEvidence!);for(const row of s.authoritySet)if(issuerAuthorityHash(a.grants[grantKey(row.environmentId,auth.deviceId)]!)!==row.authorityHash)throw new Fault(403,'issuer_authority_changed');}
   novel(a,[t.newRecoverySigningPublicKey,t.newRecoveryReceivingPublicKey]);
   const accepted:Extract<RecoveryDAGRecord,{kind:'transition-v2'}>={kind:'transition-v2',record:{submission:structuredClone(s),sequence:a.sequence+1}};
   verifyRecoveryDependencyBundle(accountDAGPin(a),{initialization:command.dependencyBundle.initialization,records:[...command.dependencyBundle.records,accepted]});
   a.recoveryGeneration=t.newRecoveryGeneration;a.recoverySigningPublicKey=t.newRecoverySigningPublicKey;a.recoveryReceivingPublicKey=t.newRecoveryReceivingPublicKey;a.trustRoot=structuredClone(s.newTrustRoot);
   for(const row of s.envelopes){const e=a.environments[row.environmentId]!;e.recoveryEnvelope=row.envelope;e.recoveryGeneration=a.recoveryGeneration;e.recoveryKeyVersion=e.keyVersion;}
   a.sessions=a.sessions.filter(other=>other.kind!=='recovery'||other.tokenHash===h);
   if(actor.kind==='recovery'){actor.recoveryGeneration=a.recoveryGeneration;actor.rotationRequired=false;actor.recoveryAuthorityHead=contentHash;}
   const sequence=next(a);a.recoveryDAGHistory??=[];a.recoveryDAGHistory.push(accepted);
   // 已接受原包永久消费该operation/nonce；仅完全相同原包可走immutable receipt分支。
   return {sequence,replayed:false,transitionHash:contentHash,contentHash};
  });
 }
 async transitionStatus(id:string,auth:RecoveryAuth,operationId:string):Promise<Record<string,unknown>>{
  identifier(operationId);return this.authorized(id,auth,(a,s)=>{const r=priorOperation(a,operationId);if(!r)return {operationId,accepted:false};if(r.kind!=='transition-v2')throw new Fault(409,'idempotency_conflict');if(s.kind==='login'&&r.record.submission.transition.authorizerDeviceId!==auth.deviceId)throw new Fault(403,'operation_forbidden');const contentHash=transitionHashV2(r.record.submission);return {operationId,accepted:true,sequence:r.record.sequence,contentHash,transitionHash:contentHash};});
 }
 async recoveredChallenge(id:string,auth:RecoveryAuth,input:{operationId:string;deviceId:string;deviceSigningPublicKey:string;deviceReceivingPublicKey:string}):Promise<Record<string,unknown>>{
  exact(input,['operationId','deviceId','deviceSigningPublicKey','deviceReceivingPublicKey']);identifier(input.operationId);identifier(input.deviceId);bytes(input.deviceSigningPublicKey,32);bytes(input.deviceReceivingPublicKey,32);
  return this.authorized(id,auth,(a,s,h,now)=>{
   const dag=verifiedAccountDAG(a);if(s.kind!=='recovery'||s.rotationRequired!==false||s.recoveryAuthorityHead!==dag.head.head)throw new Fault(403,'recovery_rotation_required');
   const prior=own(a.recoveredDAGChallenges,input.operationId);if(prior){if(prior.restrictedSessionHash!==h||prior.deviceId!==input.deviceId||prior.deviceSigningPublicKey!==input.deviceSigningPublicKey||prior.deviceReceivingPublicKey!==input.deviceReceivingPublicKey)throw new Fault(409,'idempotency_conflict');return challengeView(prior);}
   if(priorOperation(a,input.operationId))throw new Fault(409,'idempotency_conflict');oldChallengeConflict(a,input.operationId,'recovered');if(own(a.devices,input.deviceId))throw new Fault(409,'device_exists');novel(a,[input.deviceSigningPublicKey,input.deviceReceivingPublicKey]);
   a.recoveredDAGChallenges??={};if(Object.keys(a.recoveredDAGChallenges).length>=128)throw new Fault(503,'account_capacity_reached');
   const grants=recoverySources(a),proof=buildIssuerRecoveryDAGEvidence(a,a.trustRoot!.rootDeviceId,grants,recoveryTargets(a,grants));if(!proof)throw new Fault(403,'issuer_authority_unaccepted');
   const c:DAGRecoveredChallenge={...input,challengeId:crypto.randomUUID(),nonce:randomToken(),expiresAt:now+ttl,restrictedSessionHash:h,accountGeneration:a.generation,expectedSequence:String(a.sequence),recoveryGeneration:a.recoveryGeneration,recoveryTransitionHash:dag.head.head,issuerEvidence:proof.source,dependencyBundle:accountDAGBundle(a)};
   a.recoveredDAGChallenges[input.operationId]=c;return challengeView(c);
  });
 }
 async recoverDevice(id:string,auth:RecoveryAuth,command:RecoveredDeviceCommandV2):Promise<Record<string,unknown>>{
  exact(command,['submission','dependencyBundle']);recoveredReferencesV2(command.submission);const s=command.submission,e=s.enrollment,contentHash=recoveredDeviceHashV2(s);
  return this.authorized(id,auth,(a,actor,h,now)=>{
   if(actor.kind!=='recovery'||actor.rotationRequired!==false)throw new Fault(403,'recovery_rotation_required');const prior=priorOperation(a,e.operationId),c=own(a.recoveredDAGChallenges,e.operationId);
   if(prior){if(prior.kind!=='recovered-v2'||recordRow(prior)[1]!==contentHash||!c||c.restrictedSessionHash!==h||bundleContent(command.dependencyBundle)!==bundleContent(c.dependencyBundle))throw new Fault(409,'idempotency_conflict');return {sequence:prior.record.sequence,replayed:true,recoveryEnrollmentHash:contentHash,contentHash};}
   const dag=verifiedAccountDAG(a);
   if(!c||c.accountGeneration!==a.generation||c.restrictedSessionHash!==h||e.restrictedSessionHash!==h||c.expiresAt<=now||e.challengeId!==c.challengeId||e.nonce!==c.nonce||e.expiresAt!==String(c.expiresAt)||e.accountId!==a.id||e.accountGeneration!==a.generation||e.expectedSequence!==c.expectedSequence||e.expectedSequence!==String(a.sequence)||e.recoveryGeneration!==c.recoveryGeneration||e.recoveryGeneration!==a.recoveryGeneration||e.recoveryTransitionHash!==c.recoveryTransitionHash||e.recoveryTransitionHash!==dag.head.head||actor.recoveryAuthorityHead!==dag.head.head||e.deviceId!==c.deviceId||e.deviceSigningPublicKey!==c.deviceSigningPublicKey||e.deviceReceivingPublicKey!==c.deviceReceivingPublicKey||sourceHash(s.issuerEvidence)!==sourceHash(c.issuerEvidence)||bundleContent(command.dependencyBundle)!==bundleContent(c.dependencyBundle)||bundleContent(command.dependencyBundle)!==bundleContent(accountDAGBundle(a)))throw new Fault(403,'challenge_invalid');
   if(own(a.devices,e.deviceId))throw new Fault(409,'device_exists');novel(a,[e.deviceSigningPublicKey,e.deviceReceivingPublicKey]);acceptedSourceDAG(a,s.issuerEvidence);
   for(const row of s.selectedRights){if(a.environments[row.environmentId]?.keyVersion!==row.keyVersion)throw new Fault(409,'key_version_stale');if(row.expiresAt!=='0'&&BigInt(row.expiresAt)<=BigInt(now))throw new Fault(400,'grant_already_expired');}
   const accepted:Extract<RecoveryDAGRecord,{kind:'recovered-v2'}>={kind:'recovered-v2',record:{submission:structuredClone(s),sequence:a.sequence+1}};
   verifyRecoveryDependencyBundle(accountDAGPin(a),{initialization:command.dependencyBundle.initialization,records:[...command.dependencyBundle.records,accepted]});
   if(Object.keys(a.devices).length>=256)throw new Fault(503,'account_capacity_reached');
   a.devices[e.deviceId]={id:e.deviceId,signingPublicKey:e.deviceSigningPublicKey,receivingPublicKey:e.deviceReceivingPublicKey,revoked:false};const sequence=next(a);a.recoveryDAGHistory??=[];a.recoveryDAGHistory.push(accepted);a.grantHistory??=[];
   for(const signed of s.grants){a.grants[grantKey(signed.grant.environmentId,e.deviceId)]=structuredClone(signed);a.grantHistory.push({sequence,grant:structuredClone(signed),authorization:null,recoveryEnrollmentHash:contentHash});}
   return {sequence,replayed:false,recoveryEnrollmentHash:contentHash,contentHash};
  });
 }
 async recoveredStatus(id:string,auth:RecoveryAuth,operationId:string):Promise<Record<string,unknown>>{
  identifier(operationId);return this.authorized(id,auth,(a,s)=>{const r=priorOperation(a,operationId);if(!r)return {operationId,accepted:false};if(r.kind!=='recovered-v2')throw new Fault(409,'idempotency_conflict');if(s.kind==='login'&&s.deviceId!==r.record.submission.enrollment.deviceId)throw new Fault(403,'operation_forbidden');const contentHash=recoveredDeviceHashV2(r.record.submission);return {operationId,accepted:true,sequence:r.record.sequence,contentHash,recoveryEnrollmentHash:contentHash};});
 }
 async vault(id:string,auth:RecoveryAuth):Promise<Record<string,unknown>>{
  return this.authorized(id,auth,(a,s,_,now)=>{
   if(s.kind!=='recovery')allAdmin(a,auth.deviceId!,now);const bundle=accountDAGBundle(a),dag=verifiedAccountDAG(a),sources=recoverySources(a);
   for(const event of a.events)if(a.environments[event.mutation.mutation.environmentId]?.keyVersion===event.mutation.mutation.keyVersion&&!sources.some(g=>issuerAuthorityHash(g)===issuerAuthorityHash(event.authorization)))sources.push(event.authorization);
   const evidence=buildIssuerRecoveryDAGEvidence(a,a.trustRoot!.rootDeviceId,sources,recoveryTargets(a,sources));
   return structuredClone({accountId:a.id,accountGeneration:a.generation,recoveryGeneration:a.recoveryGeneration,recoverySigningPublicKey:a.recoverySigningPublicKey,recoveryReceivingPublicKey:a.recoveryReceivingPublicKey,rotationRequired:s.kind==='recovery'?s.rotationRequired:false,sequence:a.sequence,dependencyBundle:bundle,issuerEvidence:evidence,trustRoot:a.trustRoot,publicDevices:Object.values(a.devices),currentGrants:Object.values(a.grants),grantHistory:a.grantHistory??[],environments:Object.values(a.environments).map(e=>({environmentId:e.id,keyVersion:e.keyVersion,envelope:e.recoveryEnvelope})),events:a.events.filter(event=>event.mutation.mutation.keyVersion===a.environments[event.mutation.mutation.environmentId]?.keyVersion),envelopeEvidence:recoveryEnvelopeEvidence(a),recoveryHeadHash:dag.head.head});
  });
 }
}
