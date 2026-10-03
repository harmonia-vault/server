import { Fault, type SignedGrant } from "./model.js";
import { grantBytes, verify } from "./protocol.js";
import { initializationReference, submissionReferences, transitionBytes, transitionHash, type AcceptedRecoveryTransition, type RecoveryTransitionSubmission } from "./recovery-authority-wire.js";
import { verifyIssuerOriginGraph, type IssuerOriginProof } from "./issuer-origin.js";
import { issuerAuthorityHash } from "./issuer-proof.js";
import type { OriginalInitialization } from "./initialization-evidence.js";
import type { TrustRoot } from "./trust-root.js";
import { trustRootPayload } from "./trust-root.js";
import { canonical } from "./enrollment-wire.js";
export interface RecoveryAuthorityHead {
    generation: string;
    signing: string;
    receiving: string;
    head: string;
    sequence: number;
    root: TrustRoot;
    operations: Set<string>;
    seenKeys: Set<string>;
}
export function verifyRecoverySource(original: OriginalInitialization, proof: IssuerOriginProof): ReturnType<typeof verifyIssuerOriginGraph> {
    const p = original.proposal, c = original.proof;
    initializationReference(original);
    if (proof.accountId !== c.accountId || proof.accountGeneration !== c.accountGeneration || proof.trustRoot.rootDeviceId !== p.device.id || proof.trustRoot.rootSigningPublicKey !== p.device.signingPublicKey || proof.trustRoot.rootReceivingPublicKey !== p.device.receivingPublicKey)
        throw new Fault(403, "initialization_evidence_invalid");
    const graph = verifyIssuerOriginGraph(proof), initial = new Set(p.environments.map(e => issuerAuthorityHash(e.grant)));
    for (const [h, node] of graph.authorities)
        if (!node.parentHash && !initial.has(h))
            throw new Fault(403, "issuer_environment_evidence_required");
    return graph;
}
export function verifyTransitionAuthorization(original: OriginalInitialization, s: RecoveryTransitionSubmission): void {
    submissionReferences(s);
    const t = s.transition, p = original.proposal;
    if (t.accountId !== original.proof.accountId || t.accountGeneration !== original.proof.accountGeneration || s.newTrustRoot.rootDeviceId !== p.device.id || s.newTrustRoot.rootSigningPublicKey !== p.device.signingPublicKey || s.newTrustRoot.rootReceivingPublicKey !== p.device.receivingPublicKey || s.newTrustRoot.recoveryGeneration !== t.newRecoveryGeneration || s.newTrustRoot.recoverySigningPublicKey !== t.newRecoverySigningPublicKey || s.newTrustRoot.recoveryReceivingPublicKey !== t.newRecoveryReceivingPublicKey)
        throw new Fault(403, "binding_invalid");
    let authorizer = t.oldRecoverySigningPublicKey;
    if (t.authorizationKind === "all-environments-admin") {
        const graph = verifyRecoverySource(original, s.issuerEvidence!), actor = graph.identities.get(t.authorizerDeviceId);
        if ([t.newRecoverySigningPublicKey, t.newRecoveryReceivingPublicKey].some(key => [...graph.identities.values()].some(id => id.signing === key || id.receiving === key)))
            throw new Fault(403, "key_purpose_invalid");
        if (!actor || s.issuerEvidence!.targets.length !== s.environmentManifest.length)
            throw new Fault(403, "all_environment_admin_required");
        authorizer = actor.signing;
        for (let i = 0; i < s.environmentManifest.length; i++) {
            const env = s.environmentManifest[i]!, row = s.authoritySet[i]!, node = graph.authorities.get(row.authorityHash), g = node?.grant.grant, target = s.issuerEvidence!.targets.find(target => target.environmentId === env.environmentId);
            if (!g || !target || target.authorityHash !== row.authorityHash || row.environmentId !== env.environmentId || row.keyVersion !== env.keyVersion || g.environmentId !== env.environmentId || g.keyVersion !== env.keyVersion || g.subjectDeviceId !== t.authorizerDeviceId || g.role !== "admin" || g.grantGeneration !== row.grantGeneration || g.expiresAt !== row.expiresAt)
                throw new Fault(403, "all_environment_admin_required");
        }
    }
    verify(authorizer, transitionBytes(t), s.authorizationSignature);
    verify(t.newRecoverySigningPublicKey, transitionBytes(t), s.newRecoverySignature);
}
export function recoveryAuthorityHead(original: OriginalInitialization, records: AcceptedRecoveryTransition[]): RecoveryAuthorityHead {
    const p = original.proposal, c = original.proof, head = initializationReference(original), root: TrustRoot = { rootDeviceId: p.device.id, rootSigningPublicKey: p.device.signingPublicKey, rootReceivingPublicKey: p.device.receivingPublicKey, recoveryGeneration: p.recoveryGeneration, recoverySigningPublicKey: p.recoverySigningPublicKey, recoveryReceivingPublicKey: p.recoveryReceivingPublicKey, signature: p.trustRootSignature };
    verify(p.recoverySigningPublicKey, canonical(trustRootPayload(c.accountId, c.accountGeneration, root)), root.signature);
    let state: RecoveryAuthorityHead = { generation: p.recoveryGeneration, signing: p.recoverySigningPublicKey, receiving: p.recoveryReceivingPublicKey, head, sequence: 1, root, operations: new Set(), seenKeys: new Set([p.device.signingPublicKey, p.device.receivingPublicKey, p.recoverySigningPublicKey, p.recoveryReceivingPublicKey]) };
    if (!Array.isArray(records) || records.length > 128)
        throw new Fault(503, "account_capacity_reached");
    const sorted = [...records].sort((a, b) => a.sequence - b.sequence);
    for (const record of sorted) {
        const s = record.submission, t = s.transition;
        verifyTransitionAuthorization(original, s);
        if (state.operations.has(t.operationId) || !Number.isSafeInteger(record.sequence) || record.sequence !== Number(t.expectedSequence) + 1 || Number(t.expectedSequence) < state.sequence || t.previousTransitionHash !== state.head)
            throw new Fault(403, "recovery_chain_invalid");
        if (t.chainMode === "continuous") {
            if (t.oldRecoveryGeneration !== state.generation || t.oldRecoverySigningPublicKey !== state.signing || t.oldRecoveryReceivingPublicKey !== state.receiving)
                throw new Fault(403, "recovery_chain_invalid");
        }
        else {
            const l = s.legacyState!, first = JSON.parse(Buffer.from(l.rotations[0]!.signingBytes, "base64url").toString("utf8")) as string[];
            if (BigInt(t.oldRecoveryGeneration) <= BigInt(state.generation) || first[4] !== state.generation || l.rotations.some(r => r.sequence <= state.sequence || r.sequence > Number(t.expectedSequence)) || l.recoveryGeneration !== t.oldRecoveryGeneration || l.recoverySigningPublicKey !== t.oldRecoverySigningPublicKey || l.recoveryReceivingPublicKey !== t.oldRecoveryReceivingPublicKey || l.trustRoot.rootDeviceId !== p.device.id || l.trustRoot.rootSigningPublicKey !== p.device.signingPublicKey || l.trustRoot.rootReceivingPublicKey !== p.device.receivingPublicKey)
                throw new Fault(403, "recovery_chain_invalid");
            for (const r of l.rotations) {
                const f = JSON.parse(Buffer.from(r.signingBytes, "base64url").toString("utf8")) as string[];
                for (const key of [f[9]!, f[10]!]) {
                    if (state.seenKeys.has(key))
                        throw new Fault(403, "key_purpose_invalid");
                    state.seenKeys.add(key);
                }
            }
        }
        for (const key of [t.newRecoverySigningPublicKey, t.newRecoveryReceivingPublicKey]) {
            if (state.seenKeys.has(key))
                throw new Fault(403, "key_purpose_invalid");
            state.seenKeys.add(key);
        }
        state.operations.add(t.operationId);
        state = { ...state, generation: t.newRecoveryGeneration, signing: t.newRecoverySigningPublicKey, receiving: t.newRecoveryReceivingPublicKey, head: transitionHash(s), sequence: record.sequence, root: structuredClone(s.newTrustRoot) };
    }
    return state;
}
