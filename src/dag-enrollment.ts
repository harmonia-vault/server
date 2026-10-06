import { Fault, grantKey, type Auth, type SignedGrant } from './model.js';
import type { Store } from './store.js';
import { bytes, generation, identifier, verify } from './protocol.js';
import { device, next, permission, randomToken, sameAccount, session, tokenHash } from './service.js';
import { canonical, exact, own, pairingProfile, transcriptHash, type PairingContext } from './enrollment-wire.js';
import { approvalStillValid, relayFields, type LoginAuth, type Relay } from './enrollment.js';
import { registrationVerificationRequired } from './registration.js';
import { recoveryDAGCapability, type IssuerRecoveryDAG } from './recovery-dag-wire.js';
import { accountDAGPin, verifiedAccountDAG, verifyAcceptedDAGEvidence, type RecoveryDAGAccount } from './recovery-dag-account.js';
import { enrollmentV5Fields, verifyEnrollmentV5, type EnrollmentApprovalV5 } from './issuer-dag.js';
import { issuerAuthorityHash } from './issuer-proof.js';

/** 独立证书5状态；旧PairingRecord/parser不接收新DAG包。 */
export interface DAGPairingRecord {
  idempotencyKey:string; initiatorSessionHash:string; context:PairingContext;
  certificateVersion:'5'; messages:Partial<Record<'initiator'|'approver',string>>;
  confirmations:Partial<Record<'initiator'|'approver',string>>;
  approval?:EnrollmentApprovalV5; sequence?:number;
}
export interface DAGPairingProposal {
  idempotencyKey:string;deviceId:string;signingPublicKey:string;receivingPublicKey:string;approverDeviceId:string;
  certificateVersion:'5';capabilities:string[];
}
export interface DAGApprovalRequest {
  certificateVersion:'5';capabilities:string[];grants:SignedGrant[];transcriptHash:string;issuerProof:IssuerRecoveryDAG;signature:string;
}
function negotiated(value:{certificateVersion:string;capabilities:string[]}):void {
  if(value.certificateVersion!=='5'||JSON.stringify(value.capabilities)!==JSON.stringify([recoveryDAGCapability]))throw new Fault(400,'recovery_dag_capability_required');
}
function view(r:DAGPairingRecord):Record<string,unknown>{return structuredClone({state:r.sequence?'complete':r.approval?'approved':'pending',idempotencyKey:r.idempotencyKey,certificateVersion:'5',capabilities:[recoveryDAGCapability],pairingProfile,context:r.context,messages:r.messages,confirmations:r.confirmations,approval:r.approval??null,sequence:r.sequence??null});}
function manager(a:RecoveryDAGAccount,auth:Auth,hash:string,now:number):void {
  const s=session(a,hash,now);device(a,auth.deviceId);
  if(s.deviceId!==auth.deviceId)throw new Fault(403,'device_proof_required');
  if(!Object.keys(a.environments).some(id=>{try{return permission(a,auth.deviceId,id,now).role==='admin';}catch{return false;}}))throw new Fault(403,'admin_required');
}
export function stillCurrent(a:RecoveryDAGAccount,r:DAGPairingRecord,c:EnrollmentApprovalV5,now:number):void {
  approvalStillValid(a,r,c.grants,now);
  const proof=verifyAcceptedDAGEvidence(a,c.issuerProof),source=c.issuerProof.source;
  const targets=source.view.targets;
  if(targets.length!==c.grants.length)throw new Fault(403,'issuer_authority_changed');
  for(const g of c.grants){
    const target=targets.find(t=>t.environmentId===g.grant.environmentId);
    const current=a.grants[grantKey(g.grant.environmentId,r.context.approverDeviceId)];
    const parent=target&&proof.graph.authorities.get(target.authorityHash)?.grant;
    if(!current||!parent||issuerAuthorityHash(current)!==target!.authorityHash||issuerAuthorityHash(parent)!==target!.authorityHash)throw new Fault(403,'issuer_authority_changed');
  }
  verifyEnrollmentV5(accountDAGPin(a),c,{context:r.context,transcriptHash:transcriptHash(r)},false);
}
export class DAGEnrollmentService {
  constructor(readonly store:Store,private readonly clock=()=>Math.floor(Date.now()/1000)){}
  private async authorized<T>(id:string,auth:LoginAuth,fn:(a:RecoveryDAGAccount,now:number,hash:string)=>T):Promise<T>{
    identifier(id);generation(auth.accountGeneration);bytes(auth.token,32);const hash=await tokenHash(auth.token);
    return this.store.transaction(id,raw=>{const a=raw as RecoveryDAGAccount,now=this.clock();sameAccount(a,auth.accountGeneration);session(a,hash,now);if(registrationVerificationRequired(a)&&!a.verified)throw new Fault(403,'email_verification_required');return fn(a,now,hash);});
  }
  async begin(id:string,auth:LoginAuth,p:DAGPairingProposal):Promise<Record<string,unknown>>{
    exact(p,['idempotencyKey','deviceId','signingPublicKey','receivingPublicKey','approverDeviceId','certificateVersion','capabilities']);negotiated(p);
    for(const value of [p.idempotencyKey,p.deviceId,p.approverDeviceId])identifier(value);
    bytes(p.signingPublicKey,32);bytes(p.receivingPublicKey,32);
    if(p.deviceId===p.approverDeviceId||p.signingPublicKey===p.receivingPublicKey)throw new Fault(400,'pairing_identity_invalid');
    return this.authorized(id,auth,(a,now,hash)=>{
      if(!a.trustRoot)throw new Fault(409,'trust_root_required');device(a,p.approverDeviceId);
      if(!Object.keys(a.environments).some(e=>{try{return permission(a,p.approverDeviceId,e,now).role==='admin';}catch{return false;}}))throw new Fault(403,'admin_required');
      const approver=own(a.devices,p.approverDeviceId)!;
      const prior=own(a.dagPairingSessions,p.idempotencyKey);
      if(prior){const c=prior.context;if(prior.initiatorSessionHash!==hash||c.initiatorDeviceId!==p.deviceId||c.initiatorSigningPublicKey!==p.signingPublicKey||c.initiatorReceivingPublicKey!==p.receivingPublicKey||c.approverDeviceId!==p.approverDeviceId)throw new Fault(409,'idempotency_conflict');return view(prior);}
      if(a.usedPairingIds?.includes(p.idempotencyKey))throw new Fault(403,'challenge_invalid');
      if(own(a.devices,p.deviceId))throw new Fault(409,'device_id_exists');
      const keys=Object.values(a.devices).flatMap(d=>[d.signingPublicKey,d.receivingPublicKey]);
      if([p.signingPublicKey,p.receivingPublicKey].some(k=>keys.includes(k)||verifiedAccountDAG(a).head.seenKeys.has(k)))throw new Fault(400,'pairing_identity_invalid');
      a.dagPairingSessions??={};
      // 已用原ID不会因短挑战到期重新生成nonce；容量有界并明确拒绝。
      if(Object.keys(a.devices).length>=64||(a.usedPairingIds?.length??0)>=64)throw new Fault(429,'pairing_capacity_reached');
      const r:DAGPairingRecord={idempotencyKey:p.idempotencyKey,initiatorSessionHash:hash,certificateVersion:'5',context:{accountId:id,accountGeneration:a.generation,purpose:'enroll-device',sessionId:crypto.randomUUID(),challengeNonce:randomToken(),expiresAt:String(now+120),initiatorDeviceId:p.deviceId,initiatorSigningPublicKey:p.signingPublicKey,initiatorReceivingPublicKey:p.receivingPublicKey,approverDeviceId:p.approverDeviceId,approverSigningPublicKey:approver.signingPublicKey,approverReceivingPublicKey:approver.receivingPublicKey},messages:{},confirmations:{}};
      a.usedPairingIds??=[];a.usedPairingIds.push(p.idempotencyKey);
      a.dagPairingSessions[p.idempotencyKey]=r;return view(r);
    });
  }
  private async pairing<T>(id:string,auth:LoginAuth&{deviceId?:string},key:string,fn:(a:RecoveryDAGAccount,r:DAGPairingRecord,side:'initiator'|'approver',now:number)=>T):Promise<T>{
    identifier(key);if(auth.deviceId)identifier(auth.deviceId);
    return this.authorized(id,auth,(a,now,hash)=>{const r=own(a.dagPairingSessions,key);if(!r||r.context.accountGeneration!==a.generation)throw new Fault(404,'pairing_not_found');let side:'initiator'|'approver';if(hash===r.initiatorSessionHash)side='initiator';else if(auth.deviceId===r.context.approverDeviceId){manager(a,auth as Auth,hash,now);side='approver';}else throw new Fault(403,'pairing_forbidden');if(!r.sequence&&Number(r.context.expiresAt)<=now)throw new Fault(403,'challenge_invalid');return fn(a,r,side,now);});
  }
  async status(id:string,auth:LoginAuth&{deviceId?:string},key:string):Promise<Record<string,unknown>>{return this.pairing(id,auth,key,(_,r)=>view(r));}
  async relay(id:string,auth:LoginAuth&{deviceId?:string},key:string,value:Relay):Promise<Record<string,unknown>>{
    exact(value,['side','kind','payload','signature']);if(!['initiator','approver'].includes(value.side)||!['message','confirmation'].includes(value.kind))throw new Fault(400,'relay_invalid');bytes(value.payload,32);bytes(value.signature,64);
    return this.pairing(id,auth,key,(_,r,side)=>{if(r.sequence||r.approval||side!==value.side)throw new Fault(403,'pairing_step_invalid');if(value.kind==='confirmation'&&(!r.messages.initiator||!r.messages.approver))throw new Fault(409,'pairing_messages_required');verify(side==='initiator'?r.context.initiatorSigningPublicKey:r.context.approverSigningPublicKey,canonical(relayFields(r,value)),value.signature);const target=value.kind==='message'?r.messages:r.confirmations;const old=target[side];if(old&&old!==value.payload)throw new Fault(409,'relay_already_consumed');if(value.kind==='message'&&value.payload===r.messages[side==='initiator'?'approver':'initiator'])throw new Fault(400,'pairing_reflection');target[side]=value.payload;return view(r);});
  }
  async approve(id:string,auth:Auth,key:string,value:DAGApprovalRequest):Promise<Record<string,unknown>>{
    exact(value,['certificateVersion','capabilities','grants','transcriptHash','issuerProof','signature']);negotiated(value);
    return this.pairing(id,auth,key,(a,r,side,now)=>{if(side!=='approver'||r.sequence)throw new Fault(403,'admin_required');if(value.transcriptHash!==transcriptHash(r))throw new Fault(403,'pairing_transcript_mismatch');const c:EnrollmentApprovalV5={certificateVersion:'5',capabilities:[recoveryDAGCapability],context:structuredClone(r.context),pairingProfile,transcriptHash:value.transcriptHash,grants:structuredClone(value.grants),issuerProof:structuredClone(value.issuerProof),approverSignature:value.signature};enrollmentV5Fields(c);stillCurrent(a,r,c,now);if(r.approval&&(JSON.stringify(enrollmentV5Fields(r.approval))!==JSON.stringify(enrollmentV5Fields(c))||r.approval.approverSignature!==c.approverSignature))throw new Fault(409,'approval_already_consumed');r.approval=c;return view(r);});
  }
  async complete(id:string,auth:LoginAuth,key:string,signature:string):Promise<Record<string,unknown>>{
    bytes(signature,64);return this.pairing(id,auth,key,(a,r,side,now)=>{if(side!=='initiator'||!r.approval)throw new Fault(403,'approval_required');const c=r.approval;if(r.sequence){if(c.initiatorSignature!==signature)throw new Fault(409,'idempotency_conflict');device(a,r.context.initiatorDeviceId);return {...view(r),replayed:true};}if(own(a.devices,r.context.initiatorDeviceId))throw new Fault(409,'device_id_exists');stillCurrent(a,r,c,now);const complete={...c,initiatorSignature:signature};verifyEnrollmentV5(accountDAGPin(a),complete,{context:r.context,transcriptHash:transcriptHash(r)});c.initiatorSignature=signature;const x=r.context;a.devices[x.initiatorDeviceId]={id:x.initiatorDeviceId,signingPublicKey:x.initiatorSigningPublicKey,receivingPublicKey:x.initiatorReceivingPublicKey,revoked:false};for(const g of c.grants)a.grants[grantKey(g.grant.environmentId,x.initiatorDeviceId)]=structuredClone(g);a.dagDeviceEnrollments??={};a.dagDeviceEnrollments[x.initiatorDeviceId]=structuredClone(c);r.sequence=next(a);a.grantHistory??=[];for(const g of c.grants)a.grantHistory.push({sequence:r.sequence,grant:structuredClone(g),authorization:structuredClone(a.grants[grantKey(g.grant.environmentId,x.approverDeviceId)]!)});return {...view(r),replayed:false};});
  }
}
