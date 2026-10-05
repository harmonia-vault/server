import { Fault, type SignedGrant } from './model.js';
import { own } from './enrollment-wire.js';
import { originalInitialization } from './initialization-evidence.js';
import { initializationReference } from './recovery-authority-wire.js';
import { issuerAuthorityHash } from './issuer-proof.js';
import { environmentOriginHash, environmentOriginBytes, type SignedEnvironmentOrigin } from './environment-origin.js';
import { environmentChangeHash } from './environment-origin.js';
import { environmentChangeBytes } from './environments.js';
import { verify } from './protocol.js';
import { type IssuerRecoveryAuthority } from './issuer-recovery.js';
import type { EnrollmentAccount } from './enrollment-wire.js';
import { verifyRecoveryDependencyBundle, verifyIssuerRecoveryDAG, type VerifiedRecoveryDAG, type RecoveryDAGPin } from './recovery-dag.js';
import { dagHash, dagArchiveFields, dagPathRows, recordRow, sourceHash, issuerRecoveryDAGProfile, recoverySourceViewProfile, type RecoveryDAGRecord, type RecoveryDependency, type RecoveryDependencyBundle, type RecoverySource, type DAGArchive, type DAGPairedEnrollment, type IssuerRecoveryDAG } from './recovery-dag-wire.js';
import { type EnrollmentApprovalV5 } from './issuer-dag.js';
import { trustRootPayload } from './trust-root.js';
export type RecoveredRecord = Extract<RecoveryDAGRecord,{kind:'recovered-v2'}>;
export interface RecoveryDAGAccount extends EnrollmentAccount {
  recoveryDAGHistory?: Extract<RecoveryDAGRecord,{kind:'transition-v2'|'recovered-v2'}>[];
  recoveryDAGChallenges?: Record<string, import('./recovery-dag-service.js').DAGAuthorityChallenge>;
  recoveredDAGChallenges?: Record<string, import('./recovery-dag-service.js').DAGRecoveredChallenge>;
  dagDeviceEnrollments?: Record<string,EnrollmentApprovalV5>;
  dagPairingSessions?: Record<string,import('./dag-enrollment.js').DAGPairingRecord>;
}
function fail(code='recovery_dag_invalid'):never {throw new Fault(403,code);}
const b64=(b:Uint8Array):string=>Buffer.from(b).toString('base64url');
export function accountDAGBundle(a:RecoveryDAGAccount):RecoveryDependencyBundle {
 const initialization=originalInitialization(a);if(!initialization)fail('initialization_evidence_required');
 const records:RecoveryDAGRecord[]=a.recoveryDAGHistory??[];
 return structuredClone({initialization,records});
}
export function accountDAGPin(a:RecoveryDAGAccount):RecoveryDAGPin {
 const o=originalInitialization(a);if(!o)fail('initialization_evidence_required');
 return {accountId:a.id,accountGeneration:a.generation,rootDeviceId:o.proposal.device.id,signingPublicKey:o.proposal.device.signingPublicKey,receivingPublicKey:o.proposal.device.receivingPublicKey,initializationHash:initializationReference(o)};
}
export function verifiedAccountDAG(a:RecoveryDAGAccount):VerifiedRecoveryDAG {
 const d=verifyRecoveryDependencyBundle(accountDAGPin(a),accountDAGBundle(a)),h=d.head;
 if(h.sequence>a.sequence || h.generation!==a.recoveryGeneration || h.signing!==a.recoverySigningPublicKey || h.receiving!==a.recoveryReceivingPublicKey || !a.trustRoot || JSON.stringify(trustRootPayload(a.id,a.generation,h.root))!==JSON.stringify(trustRootPayload(a.id,a.generation,a.trustRoot)) || h.root.signature!==a.trustRoot.signature)fail('recovery_chain_invalid');
 return d;
}
function storedDAGArchive(a:RecoveryDAGAccount,id:string):EnrollmentApprovalV5|undefined{return own(a.dagDeviceEnrollments,id);}
function archiveDAGEnrollment(c:EnrollmentApprovalV5):DAGPairedEnrollment {
 if(!c.initiatorSignature)fail('issuer_archive_mismatch');
 return {certificateVersion:'5',issuerProofHash:dagHash(c.issuerProof),approval:{context:structuredClone(c.context),pairingProfile:c.pairingProfile,transcriptHash:c.transcriptHash,grants:structuredClone(c.grants),approverSignature:c.approverSignature,initiatorSignature:c.initiatorSignature}};
}
/** 候选records只能取当前唯一账号事务已接受原包；历史签名通过不代替实际接受历史。 */
export function acceptedSourceDAG(a:RecoveryDAGAccount,source:RecoverySource):IssuerRecoveryDAG {
 const full=verifiedAccountDAG(a),nodes=full.records,needed=new Set<string>(),todo=full.direct(source);
 while(todo.length){const h=todo.pop()!;if(needed.has(h))continue;const n=nodes.get(h);if(!n)fail();needed.add(h);todo.push(...n.dependencies);}
 const p:IssuerRecoveryDAG={profile:issuerRecoveryDAGProfile,accountId:a.id,accountGeneration:a.generation,initialization:accountDAGBundle(a).initialization,source:structuredClone(source),records:[...needed].map(h=>structuredClone(nodes.get(h)!.wire))};
 verifyAcceptedDAGEvidence(a,p);return p;
}
export function verifyAcceptedDAGEvidence(a:RecoveryDAGAccount,p:IssuerRecoveryDAG):ReturnType<typeof verifyIssuerRecoveryDAG> {
 const full=verifiedAccountDAG(a);if(p.accountId!==a.id || p.accountGeneration!==a.generation || initializationReference(p.initialization)!==full.pin.initializationHash)fail('initialization_evidence_invalid');
 const result=verifyIssuerRecoveryDAG(full.pin,p),graph=result.graph;
 if(result.dag.head.head!==full.head.head || result.dag.head.sequence!==full.head.sequence)fail('recovery_chain_invalid');
 const accepted=full.records;
 for(const [h,n] of result.dag.records){const old=accepted.get(h);if(!old || old.sequence!==n.sequence || JSON.stringify(old.wire)!==JSON.stringify(n.wire))fail('issuer_archive_mismatch');}
 for(const n of [...p.source.view.path, ...p.source.view.identityPaths.flat()]){
  if(n.kind==='recovered'){if(!accepted.has(n.recoveryEnrollmentHash))fail('issuer_archive_mismatch');continue;}
  const c=storedDAGArchive(a,n.enrollment.approval.context.initiatorDeviceId);if(!c)fail('issuer_archive_mismatch');const archive=archiveDAGEnrollment(c);
  if(JSON.stringify(dagArchiveFields(archive))!==JSON.stringify(dagArchiveFields(n.enrollment)) || archive.approval.approverSignature!==n.enrollment.approval.approverSignature || archive.approval.initiatorSignature!==n.enrollment.approval.initiatorSignature)fail('issuer_archive_mismatch');
 }
 const initial=new Set(p.initialization.proposal.environments.map(e=>issuerAuthorityHash(e.grant)));
 for(const [h,node] of graph.authorities){
  const found=a.grantHistory?.find(e=>issuerAuthorityHash(e.grant)===h);if(!found)fail('issuer_authority_unaccepted');
  const n=node as IssuerRecoveryAuthority;
  if(n.recoveryEnrollmentHash){const record=accepted.get(n.recoveryEnrollmentHash);if(found.recoveryEnrollmentHash!==n.recoveryEnrollmentHash || found.authorization!==null || found.originHash || !record || record.sequence!==found.sequence)fail('issuer_authority_parent_mismatch');}
  else if(found.recoveryEnrollmentHash)fail('issuer_authority_parent_mismatch');
  else if(n.originHash){const event=a.environmentHistory?.find(e=>e.origin&&environmentOriginHash(e.origin)===n.originHash);if(found.originHash!==n.originHash || !found.authorization || issuerAuthorityHash(found.authorization)!==n.parentHash || !event || event.sequence!==found.sequence)fail('issuer_authority_parent_mismatch');}
  else if(!n.parentHash){if(found.authorization!==null || found.originHash || !initial.has(h))fail('issuer_environment_evidence_required');}
  else if(found.originHash || !found.authorization || issuerAuthorityHash(found.authorization)!==n.parentHash)fail('issuer_authority_parent_mismatch');
 }
 for(const [h,raw] of graph.origins){const origin=raw as SignedEnvironmentOrigin,found=a.environmentHistory?.find(e=>e.origin&&environmentOriginHash(e.origin)===h);if(!found?.origin || found.sequence!==Number(origin.origin.expectedSequence)+1 || issuerAuthorityHash(found.authorization)!==origin.origin.authorityHash || found.origin.signature!==origin.signature || b64(environmentOriginBytes(found.origin.origin))!==b64(environmentOriginBytes(origin.origin)) || environmentChangeHash(environmentChangeBytes(found.change.change),found.change.signature)!==origin.origin.changeHash)fail('issuer_origin_unaccepted');verify(graph.identities.get(origin.origin.actorDeviceId)!.signing,environmentChangeBytes(found.change.change),found.change.signature);}
 return result;
}
export function buildIssuerRecoveryDAGEvidence(a: RecoveryDAGAccount, deviceId: string, sources: SignedGrant[], targets: SignedGrant[] = sources, identityIds: string[] = []): IssuerRecoveryDAG | null {
    if (!sources.length)
        return null;
    const initialization = originalInitialization(a);
    const verified = verifiedAccountDAG(a), records = verified.records;
    if (!initialization || !a.trustRoot)
        fail("initialization_evidence_required");
    const initial = new Set(initialization.proposal.environments.map(e => issuerAuthorityHash(e.grant))), root = a.trustRoot, authorities = new Map<string, IssuerRecoveryAuthority>(), origins = new Map<string, SignedEnvironmentOrigin>(), paths = new Map<string, DAGArchive[]>(), recovered = new Map<string, RecoveredRecord>(), visiting = new Set<string>(), expanded = new Set<string>();
    function identityPath(id: string, stack = new Set<string>()): DAGArchive[] {
        if (id === root.rootDeviceId)
            return [];
        const previous = paths.get(id);
        if (previous)
            return previous;
        if (stack.has(id))
            fail();
        stack.add(id);
        const rec = [...records.values()].map(n => n.wire).find((n): n is RecoveredRecord => !n.kind.startsWith('transition') && (n as RecoveredRecord).record.submission.enrollment.deviceId === id);
        let path: DAGArchive[];
        if (rec) {
            const h = recordRow(rec)[1]!;
            recovered.set(h, structuredClone(rec));
            path = [{ kind: 'recovered', recoveryEnrollmentHash: h }];
        }
        else {
            const archive = storedDAGArchive(a, id);
            if (!archive?.initiatorSignature)
                fail('issuer_archive_mismatch');
            path = [...identityPath(archive.context.approverDeviceId, stack), { kind: 'paired', enrollment: archiveDAGEnrollment(archive) }];
        }
        paths.set(id, path);
        stack.delete(id);
        return path;
    }
    function source(signed: SignedGrant): void {
        const h = issuerAuthorityHash(signed);
        if (authorities.has(h))
            return;
        if (visiting.has(h))
            fail();
        visiting.add(h);
        const accepted = a.grantHistory?.find(event => issuerAuthorityHash(event.grant) === h);
        if (!accepted)
            fail('issuer_authority_unaccepted');
        identityPath(signed.grant.issuerDeviceId);
        identityPath(signed.grant.subjectDeviceId);
        const recoveryEnrollmentHash = (accepted as typeof accepted & {
            recoveryEnrollmentHash?: string;
        }).recoveryEnrollmentHash ?? '', node: IssuerRecoveryAuthority = { grant: structuredClone(signed), parentHash: '', originHash: '', previousGrantHash: '', recoveryEnrollmentHash };
        if (recoveryEnrollmentHash) {
            const rec = [...records.values()].map(n=>n.wire).find((r):r is RecoveredRecord => !r.kind.startsWith('transition') && recordRow(r)[1]! === recoveryEnrollmentHash);
            if (!rec || accepted.authorization || accepted.originHash)
                fail();
            recovered.set(recoveryEnrollmentHash, structuredClone(rec));
        }
        else if (!accepted.authorization) {
            if (accepted.originHash || !initial.has(h))
                fail('issuer_environment_evidence_required');
        }
        if (accepted.authorization) {
            node.parentHash = issuerAuthorityHash(accepted.authorization);
            source(accepted.authorization);
        }
        if (accepted.originHash) {
            const event = a.environmentHistory?.find(event => event.origin && environmentOriginHash(event.origin) === accepted.originHash);
            if (!event?.origin)
                fail('issuer_origin_unaccepted');
            node.originHash = accepted.originHash;
            origins.set(node.originHash, structuredClone(event.origin));
            if (event.origin.origin.operation === 'rotate') {
                const before = event.origin.origin.before.find(row => row.subjectDeviceId === signed.grant.subjectDeviceId), previous = before && a.grantHistory?.find(row => issuerAuthorityHash(row.grant) === before.grantHash);
                if (!before || !previous)
                    fail();
                node.previousGrantHash = before.grantHash;
                source(previous.grant);
            }
        }
        authorities.set(h, node);
        visiting.delete(h);
        if (node.originHash && !expanded.has(node.originHash)) {
            expanded.add(node.originHash);
            for (const row of [...origins.get(node.originHash)!.origin.before, ...origins.get(node.originHash)!.origin.after]) {
                const accepted = a.grantHistory?.find(e => issuerAuthorityHash(e.grant) === row.grantHash);
                if (!accepted)
                    fail();
                source(accepted.grant);
            }
        }
    }
    const path = identityPath(deviceId);
    // 未获本环境授权的既有设备也须通过完整受签归档绑定，不能从目录建立公钥信任。
    for (const id of identityIds)
        identityPath(id);
    for (const signed of sources)
        source(signed);
    let processed = 0;
    while (processed < paths.size) {
        const all = [...paths.values()];
        for (; processed < all.length; processed++)
            for (const node of all[processed]!)
                if (node.kind === 'paired')
                    for (const grant of node.enrollment.approval.grants)
                        source(grant);
                else
                    for (const grant of recovered.get(node.recoveryEnrollmentHash)!.record.submission.grants)
                        source(grant);
    }
    const main = JSON.stringify(dagPathRows(path)), branches = [...paths.values()].filter(p => JSON.stringify(dagPathRows(p)) !== main), leaves = branches.filter(p => !branches.some(other => other.length > p.length && JSON.stringify(dagPathRows(other.slice(0, p.length))) === JSON.stringify(dagPathRows(p))));
    const dependencyHashes = new Set<string>();
    if (verified.head.head !== verified.pin.initializationHash) dependencyHashes.add(verified.head.head);
    for (const n of [...path, ...leaves.flat()]) if (n.kind === 'recovered') dependencyHashes.add(n.recoveryEnrollmentHash);
    for (const n of authorities.values()) if (n.recoveryEnrollmentHash) dependencyHashes.add(n.recoveryEnrollmentHash);
    const dependencies: RecoveryDependency[] = [...dependencyHashes].map(h=>{const n=records.get(h);if(!n)fail();return {kind:n.wire.kind,referenceHash:h};}).sort((a,b)=>a.kind<b.kind?-1:a.kind>b.kind?1:a.referenceHash<b.referenceHash?-1:1);
    const candidateSource: RecoverySource = {kind:'proof3',view:{profile:recoverySourceViewProfile,accountId:a.id,accountGeneration:a.generation,initializationHash:verified.pin.initializationHash,trustRoot:structuredClone(root),recoveryHeadHash:verified.head.head,path:structuredClone(path),authorities:[...authorities.values()],targets:targets.map(s=>({environmentId:s.grant.environmentId,authorityHash:issuerAuthorityHash(s)})),origins:[...origins.values()],identityPaths:structuredClone(leaves),dependencies}};
    return acceptedSourceDAG(a, candidateSource);
}
