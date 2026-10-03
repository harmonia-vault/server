import { Fault, type Account, type SignedGrant } from "./model.js";
import { environmentChangeBytes, type SignedEnvironmentChange } from "./environments.js";
import { environmentChangeHash, environmentOriginBytes, type SignedEnvironmentOrigin } from "./environment-origin.js";
import { bytes, grantBytes, verify } from "./protocol.js";
import { canonical, envelopeHash, rotationPayload, type RotationProposal } from "./lifecycle-wire.js";
import { trustRootHash } from "./trust-root.js";
import { issuerAuthorityHash } from "./issuer-proof.js";
export const recoveryEnvelopeCapability = "recovery-envelope-v1";
export interface RecoveryEnvelopeRotationProof {
  accountId:string;accountGeneration:string;sessionHash:string;recoveryGeneration:string;challengeId:string;nonce:string;expiresAt:string;
  newRecoveryGeneration:string;newRecoverySigningPublicKey:string;newRecoveryReceivingPublicKey:string;envelopesHash:string;trustRootHash:string;
}
export interface RecoveryEnvelopeEvidence {
  profile:"harmonia/recovery-envelope-evidence/v1";
  environmentChanges:{sequence:number;change:SignedEnvironmentChange;origin:SignedEnvironmentOrigin|null;authorization:SignedGrant}[];
  recoveryRotations:{sequence:number;proposal:RotationProposal;proof:RecoveryEnvelopeRotationProof;signature:string}[];
}
/** 同账号事务内投影完整已签封套承诺；不是以HPKE成功或空环境证明来源。 */
export function recoveryEnvelopeEvidence(account:Account):RecoveryEnvelopeEvidence{
  const environmentChanges=(account.environmentHistory??[]).filter(event=>{
    const c=event.change.change;return(c.operation==="create"||c.operation==="rotate")&&account.environments[c.environmentId]?.keyVersion===c.keyVersion;
  }).map(event=>{
    const c=event.change.change,g=event.authorization.grant,actor=account.devices[c.deviceId],issuer=account.devices[g.issuerDeviceId];
    if(c.accountId!==account.id||c.accountGeneration!==account.generation||g.accountId!==account.id||g.accountGeneration!==account.generation||g.subjectDeviceId!==c.deviceId||g.role!=="admin"||g.environmentId!==c.authorityEnvironmentId||g.keyVersion!==c.authorityKeyVersion||g.grantGeneration!==c.authorityGrantGeneration||!actor||!issuer||g.subjectSigningPublicKey!==actor.signingPublicKey||g.subjectReceivingPublicKey!==actor.receivingPublicKey||event.sequence!==Number(BigInt(c.expectedSequence)+1n)||event.sequence>account.sequence)throw new Fault(403,"binding_invalid");
    verify(issuer.signingPublicKey,grantBytes(g),event.authorization.signature);const encoded=environmentChangeBytes(c);verify(actor.signingPublicKey,encoded,event.change.signature);
    if(event.origin){const o=event.origin.origin;const bindings=[[o.accountId,c.accountId],[o.accountGeneration,c.accountGeneration],[o.actorDeviceId,c.deviceId],[o.environmentId,c.environmentId],[o.operation,c.operation],[o.authorityEnvironmentId,c.authorityEnvironmentId],[o.authorityKeyVersion,c.authorityKeyVersion],[o.authorityGrantGeneration,c.authorityGrantGeneration],[o.previousKeyVersion,c.previousKeyVersion],[o.keyVersion,c.keyVersion],[o.expectedSequence,c.expectedSequence],[o.idempotencyKey,c.idempotencyKey]];if(bindings.some(([a,b])=>a!==b)||o.authorityHash!==issuerAuthorityHash(event.authorization)||o.changeHash!==environmentChangeHash(encoded,event.change.signature))throw new Fault(403,"issuer_origin_unaccepted");verify(actor.signingPublicKey,environmentOriginBytes(o),event.origin.signature);}
    return{sequence:event.sequence,change:{change:structuredClone(c),signature:event.change.signature},origin:event.origin?structuredClone(event.origin):null,authorization:structuredClone(event.authorization)};
  }).sort((a,b)=>a.sequence-b.sequence);
  const recoveryRotations=Object.values(account.recoveryRotations??{}).filter(r=>r.state==="complete"&&r.proposal.newRecoveryGeneration===account.recoveryGeneration&&r.trustRootHash&&r.proposal.newTrustRoot).map(r=>{
    const p=r.proposal,root=p.newTrustRoot!;
    if(r.generation!==account.generation||!r.signature||!Number.isSafeInteger(r.sequence)||r.sequence!<1||r.sequence!>account.sequence||p.newRecoverySigningPublicKey!==account.recoverySigningPublicKey||p.newRecoveryReceivingPublicKey!==account.recoveryReceivingPublicKey||envelopeHash(p.envelopes)!==r.envelopesHash||trustRootHash(account.id,account.generation,root)!==r.trustRootHash)throw new Fault(403,"binding_invalid");
    if(!account.trustRoot||root.rootDeviceId!==account.trustRoot.rootDeviceId||root.rootSigningPublicKey!==account.trustRoot.rootSigningPublicKey||root.rootReceivingPublicKey!==account.trustRoot.rootReceivingPublicKey||root.recoveryGeneration!==p.newRecoveryGeneration||root.recoverySigningPublicKey!==p.newRecoverySigningPublicKey||root.recoveryReceivingPublicKey!==p.newRecoveryReceivingPublicKey)throw new Fault(403,"binding_invalid");
    bytes(r.signature,64);verify(p.newRecoverySigningPublicKey,canonical(rotationPayload(account.id,r)),r.signature);
    const proof:RecoveryEnvelopeRotationProof={accountId:account.id,accountGeneration:r.generation,sessionHash:r.sessionHash,recoveryGeneration:r.recoveryGeneration,challengeId:r.id,nonce:r.nonce,expiresAt:String(r.expiresAt),newRecoveryGeneration:p.newRecoveryGeneration,newRecoverySigningPublicKey:p.newRecoverySigningPublicKey,newRecoveryReceivingPublicKey:p.newRecoveryReceivingPublicKey,envelopesHash:r.envelopesHash,trustRootHash:r.trustRootHash!};
    return{sequence:r.sequence!,proposal:structuredClone(p),proof,signature:r.signature};
  }).sort((a,b)=>a.sequence-b.sequence);
  return{profile:"harmonia/recovery-envelope-evidence/v1",environmentChanges,recoveryRotations};
}
