import { DAGRequired, type RecoveryDAGAccount } from './recovery-dag-account.js';
import { Fault, grantKey, type Session } from "./model.js";
import { bytes, generation, identifier, verify } from "./protocol.js";
import { canonical, exact, own, type EnrollmentAccount } from "./enrollment-wire.js";
import { device, next, permission, randomToken, sameAccount, session, tokenHash } from "./service.js";
import type { Store } from "./store.js";
import type { RecoveryAuth } from "./lifecycle-wire.js";
import { rotationPayload } from "./lifecycle-wire.js";
import { originalInitialization, type OriginalInitialization } from "./initialization-evidence.js";
import { buildIssuerEvidence, buildRecoveryIssuerEvidence, verifyAcceptedIssuerOriginEvidence, type IssuerOriginProof } from "./issuer-origin.js";
import { issuerAuthorityHash } from "./issuer-proof.js";
import { recoveryEnvelopeEvidence } from "./recovery-envelope-evidence.js";
import { recoveryAuthorityHead, verifyTransitionAuthorization, type RecoveryAuthorityHead } from "./recovery-authority-history.js";
import { initializationReference, legacyStateHash, recoveryAuthorityCapability, recoveryManifestHash, submissionReferences, transitionHash, type AcceptedRecoveryTransition, type RecoveryAdminAuthority, type RecoveryEnvironmentVersion, type RecoveryLegacyState, type RecoveryTransitionSubmission } from "./recovery-authority-wire.js";
import { recoveredDeviceHash, recoveredEnrollmentBytes, recoveredSubmissionReferences, type AcceptedRecoveredDevice, type RecoveredDeviceSubmission } from "./recovered-device-wire.js";
export interface AuthorityChallenge {
    operationId: string;
    challengeId: string;
    nonce: string;
    expiresAt: number;
    sessionHash: string;
    accountGeneration: string;
    authorizationKind: "old-recovery" | "all-environments-admin";
    chainMode: "continuous" | "manager-reanchor";
    authorizerDeviceId: string;
    expectedSequence: string;
    previousTransitionHash: string;
    oldRecoveryGeneration: string;
    oldRecoverySigningPublicKey: string;
    oldRecoveryReceivingPublicKey: string;
    environmentManifest: RecoveryEnvironmentVersion[];
    authoritySet: RecoveryAdminAuthority[];
    issuerEvidence: IssuerOriginProof | null;
    legacyState: RecoveryLegacyState | null;
}
export interface RecoveredChallenge {
    operationId: string;
    challengeId: string;
    nonce: string;
    expiresAt: number;
    restrictedSessionHash: string;
    expectedSequence: string;
    recoveryGeneration: string;
    recoveryTransitionHash: string;
    accountGeneration: string;
    deviceId: string;
    deviceSigningPublicKey: string;
    deviceReceivingPublicKey: string;
    issuerEvidence: IssuerOriginProof;
}
export interface RecoveryAuthorityAccount extends EnrollmentAccount {
    recoveryAuthorityTransitions?: AcceptedRecoveryTransition[];
    recoveryAuthorityChallenges?: Record<string, AuthorityChallenge>;
    recoveredDeviceChallenges?: Record<string, RecoveredChallenge>;
    recoveredDevices?: Record<string, AcceptedRecoveredDevice>;
}
type AuthoritySession = Session & {
    recoveryAuthorityHead?: string;
};
const ttl = 120;
function authorityView(a: RecoveryAuthorityAccount, c: AuthorityChallenge): Record<string, unknown> { return structuredClone({ challengeId: c.challengeId, nonce: c.nonce, expiresAt: c.expiresAt, sessionHash: c.sessionHash, expectedSequence: c.expectedSequence, previousTransitionHash: c.previousTransitionHash, oldRecoveryGeneration: c.oldRecoveryGeneration, oldRecoverySigningPublicKey: c.oldRecoverySigningPublicKey, oldRecoveryReceivingPublicKey: c.oldRecoveryReceivingPublicKey, environmentManifest: c.environmentManifest, authoritySet: c.authoritySet, issuerEvidence: c.issuerEvidence, legacyState: c.legacyState, originalInitialization: original(a), transitions: (a.recoveryAuthorityTransitions ?? []).filter(r => r.sequence <= Number(c.expectedSequence)) }); }
function recoveredView(c: RecoveredChallenge): Record<string, unknown> { return structuredClone({ challengeId: c.challengeId, nonce: c.nonce, expiresAt: c.expiresAt, restrictedSessionHash: c.restrictedSessionHash, expectedSequence: c.expectedSequence, recoveryGeneration: c.recoveryGeneration, recoveryTransitionHash: c.recoveryTransitionHash, issuerEvidence: c.issuerEvidence }); }
const sortedManifest = (a: EnrollmentAccount): RecoveryEnvironmentVersion[] => Object.values(a.environments).map(e => ({ environmentId: e.id, keyVersion: e.keyVersion })).sort((a, b) => a.environmentId < b.environmentId ? -1 : 1);
function original(a: RecoveryAuthorityAccount): OriginalInitialization { const record = originalInitialization(a); if (!record)
    throw new Fault(403, "initialization_evidence_required"); return record; }
function chain(a: RecoveryAuthorityAccount): RecoveryAuthorityHead { return recoveryAuthorityHead(original(a), a.recoveryAuthorityTransitions ?? []); }
function gap(a: RecoveryAuthorityAccount, h: RecoveryAuthorityHead): boolean { return h.generation !== a.recoveryGeneration || h.signing !== a.recoverySigningPublicKey || h.receiving !== a.recoveryReceivingPublicKey; }
function currentActor(a: RecoveryAuthorityAccount, auth: RecoveryAuth, hash: string, now: number): AuthoritySession {
    sameAccount(a, auth.accountGeneration);
    const s = session(a, hash, now, true) as AuthoritySession;
    if (s.kind === "recovery") {
        if (s.recoveryGeneration !== a.recoveryGeneration)
            throw new Fault(403, "recovery_session_stale");
    }
    else {
        if (!auth.deviceId || s.deviceId !== auth.deviceId)
            throw new Fault(403, "device_proof_required");
        device(a, auth.deviceId);
    }
    return s;
}
function allAdmin(a: RecoveryAuthorityAccount, id: string, now: number): void {
    const ids = Object.keys(a.environments);
    if (!ids.length || ids.some(env => permission(a, id, env, now).role !== "admin"))
        throw new Fault(403, "all_environment_admin_required");
}
function legacy(a: RecoveryAuthorityAccount, h: RecoveryAuthorityHead): RecoveryLegacyState {
    if (!a.trustRoot)
        throw new Fault(403, "trust_root_required");
    const rotations = Object.values(a.recoveryRotations ?? {}).filter(r => r.state === "complete" && r.sequence! > h.sequence).sort((a, b) => a.sequence! - b.sequence!).map(r => {
        if (!r.signature || !r.sequence || !r.trustRootHash)
            throw new Fault(403, "recovery_chain_invalid");
        return { idempotencyKey: r.proposal.idempotencyKey, signingBytes: Buffer.from(canonical(rotationPayload(a.id, r))).toString("base64url"), signature: r.signature, sequence: r.sequence };
    });
    const state: RecoveryLegacyState = { recoveryGeneration: a.recoveryGeneration, recoverySigningPublicKey: a.recoverySigningPublicKey!, recoveryReceivingPublicKey: a.recoveryReceivingPublicKey!, trustRoot: structuredClone(a.trustRoot), rotations };
    legacyStateHash(a.id, a.generation, state);
    return state;
}
function novelKeys(a: RecoveryAuthorityAccount, keys: string[], h: RecoveryAuthorityHead): void {
    if (keys[0] === keys[1] || keys.some(k => h.seenKeys.has(k) || Object.values(a.devices).some(d => d.signingPublicKey === k || d.receivingPublicKey === k) || k === a.recoverySigningPublicKey || k === a.recoveryReceivingPublicKey))
        throw new Fault(403, "key_purpose_invalid");
}
export class RecoveryAuthorityService {
    constructor(readonly store: Store, private readonly clock: () => number = () => Math.floor(Date.now() / 1000)) { }
    private async authenticated<T>(id: string, auth: RecoveryAuth, fn: (a: RecoveryAuthorityAccount, s: AuthoritySession, hash: string, now: number) => T): Promise<T> {
        identifier(id);
        generation(auth.accountGeneration);
        bytes(auth.token, 32);
        if (auth.deviceId)
            identifier(auth.deviceId);
        const hash = await tokenHash(auth.token);
        return this.store.transaction(id, account => { const a = account as RecoveryAuthorityAccount, now = this.clock(), s = currentActor(a, auth, hash, now); if(DAGRequired(a as RecoveryDAGAccount))throw new Fault(426,"protocol_upgrade_required"); return fn(a, s, hash, now); });
    }
    async challenge(id: string, auth: RecoveryAuth, input: {
        operationId: string;
        authorizationKind: AuthorityChallenge["authorizationKind"];
        chainMode: AuthorityChallenge["chainMode"];
    }): Promise<Record<string, unknown>> {
        exact(input, ["operationId", "authorizationKind", "chainMode"]);
        identifier(input.operationId);
        if (!["old-recovery", "all-environments-admin"].includes(input.authorizationKind) || !["continuous", "manager-reanchor"].includes(input.chainMode))
            throw new Fault(400, "fields_invalid");
        return this.authenticated(id, auth, (a, s, hash, now) => {
            const h = chain(a), hasGap = gap(a, h);
            if (input.authorizationKind === "old-recovery") {
                if (s.kind !== "recovery" || input.chainMode !== "continuous" || hasGap)
                    throw new Fault(403, "recovery_chain_invalid");
            }
            else {
                if (s.kind !== "login" || !auth.deviceId)
                    throw new Fault(403, "device_proof_required");
                allAdmin(a, auth.deviceId, now);
                if ((input.chainMode === "manager-reanchor") !== hasGap)
                    throw new Fault(403, "recovery_chain_invalid");
            }
            const prior = own(a.recoveryAuthorityChallenges, input.operationId);
            if (prior) {
                if (prior.sessionHash !== hash || prior.authorizationKind !== input.authorizationKind || prior.chainMode !== input.chainMode || prior.accountGeneration !== a.generation)
                    throw new Fault(409, "idempotency_conflict");
                return authorityView(a, prior);
            }
            a.recoveryAuthorityChallenges ??= {};
            if (Object.keys(a.recoveryAuthorityChallenges).length >= 128 || h.operations.has(input.operationId))
                throw new Fault(503, "account_capacity_reached");
            const manifest = sortedManifest(a);
            recoveryManifestHash(manifest);
            let authoritySet: RecoveryAdminAuthority[] = [], issuerEvidence: IssuerOriginProof | null = null;
            if (input.authorizationKind === "all-environments-admin") {
                const grants = manifest.map(e => a.grants[grantKey(e.environmentId, auth.deviceId!)]!);
                authoritySet = grants.map(signed => { const g = signed.grant; return { environmentId: g.environmentId, keyVersion: g.keyVersion, grantGeneration: g.grantGeneration, expiresAt: g.expiresAt, authorityHash: issuerAuthorityHash(signed) }; });
                issuerEvidence = buildIssuerEvidence(a, auth.deviceId!, grants);
            }
            const c: AuthorityChallenge = { ...input, challengeId: crypto.randomUUID(), nonce: randomToken(), expiresAt: now + ttl, sessionHash: hash, accountGeneration: a.generation, authorizerDeviceId: input.authorizationKind === "all-environments-admin" ? auth.deviceId! : "", expectedSequence: String(a.sequence), previousTransitionHash: h.head, oldRecoveryGeneration: a.recoveryGeneration, oldRecoverySigningPublicKey: a.recoverySigningPublicKey!, oldRecoveryReceivingPublicKey: a.recoveryReceivingPublicKey!, environmentManifest: manifest, authoritySet, issuerEvidence, legacyState: hasGap ? legacy(a, h) : null };
            a.recoveryAuthorityChallenges[input.operationId] = c;
            return authorityView(a, c);
        });
    }
    async transition(id: string, auth: RecoveryAuth, submission: RecoveryTransitionSubmission): Promise<Record<string, unknown>> {
        submissionReferences(submission);
        const t = submission.transition, contentHash = transitionHash(submission);
        return this.authenticated(id, auth, (a, s, hash, now) => {
            const prior = (a.recoveryAuthorityTransitions ?? []).find(r => r.submission.transition.operationId === t.operationId);
            if (prior) {
                if (prior.submission.transition.sessionHash !== hash || transitionHash(prior.submission) !== contentHash)
                    throw new Fault(409, "idempotency_conflict");
                return { sequence: prior.sequence, replayed: true, transitionHash: contentHash, contentHash };
            }
            const h = chain(a), c = own(a.recoveryAuthorityChallenges, t.operationId);
            if (!c || c.sessionHash !== hash || c.accountGeneration !== a.generation || c.expiresAt <= now || c.challengeId !== t.challengeId || c.nonce !== t.nonce || String(c.expiresAt) !== t.expiresAt || t.sessionHash !== hash || t.accountId !== a.id || t.accountGeneration !== a.generation)
                throw new Fault(403, "challenge_invalid");
            if (t.authorizationKind !== c.authorizationKind || t.chainMode !== c.chainMode || t.authorizerDeviceId !== c.authorizerDeviceId || t.expectedSequence !== c.expectedSequence || t.expectedSequence !== String(a.sequence) || t.previousTransitionHash !== c.previousTransitionHash || t.previousTransitionHash !== h.head || t.oldRecoveryGeneration !== a.recoveryGeneration || t.oldRecoverySigningPublicKey !== a.recoverySigningPublicKey || t.oldRecoveryReceivingPublicKey !== a.recoveryReceivingPublicKey || JSON.stringify(sortedManifest(a)) !== JSON.stringify(c.environmentManifest) || JSON.stringify(submission.environmentManifest) !== JSON.stringify(c.environmentManifest) || JSON.stringify(submission.authoritySet) !== JSON.stringify(c.authoritySet) || JSON.stringify(submission.issuerEvidence) !== JSON.stringify(c.issuerEvidence) || JSON.stringify(submission.legacyState) !== JSON.stringify(c.legacyState))
                throw new Fault(409, "recovery_context_changed");
            if (t.authorizationKind === "old-recovery") {
                if (s.kind !== "recovery" || gap(a, h))
                    throw new Fault(403, "recovery_chain_invalid");
            }
            else {
                if (s.kind !== "login" || auth.deviceId !== t.authorizerDeviceId)
                    throw new Fault(403, "device_proof_required");
                allAdmin(a, auth.deviceId, now);
                verifyAcceptedIssuerOriginEvidence(a, submission.issuerEvidence!);
                for (const row of submission.authoritySet)
                    if (issuerAuthorityHash(a.grants[grantKey(row.environmentId, auth.deviceId)]!) !== row.authorityHash)
                        throw new Fault(403, "issuer_authority_changed");
            }
            novelKeys(a, [t.newRecoverySigningPublicKey, t.newRecoveryReceivingPublicKey], h);
            verifyTransitionAuthorization(original(a), submission);
            const accepted: AcceptedRecoveryTransition = { submission: structuredClone(submission), sequence: a.sequence + 1 };
            recoveryAuthorityHead(original(a), [...(a.recoveryAuthorityTransitions ?? []), accepted]);
            a.recoveryGeneration = t.newRecoveryGeneration;
            a.recoverySigningPublicKey = t.newRecoverySigningPublicKey;
            a.recoveryReceivingPublicKey = t.newRecoveryReceivingPublicKey;
            a.trustRoot = structuredClone(submission.newTrustRoot);
            for (const row of submission.envelopes) {
                const env = a.environments[row.environmentId]!;
                env.recoveryEnvelope = row.envelope;
                env.recoveryGeneration = a.recoveryGeneration;
                env.recoveryKeyVersion = env.keyVersion;
            }
            a.sessions = a.sessions.filter(other => other.kind !== "recovery" || other.tokenHash === hash);
            if (s.kind === "recovery") {
                s.recoveryGeneration = a.recoveryGeneration;
                s.rotationRequired = false;
                s.recoveryAuthorityHead = contentHash;
            }
            const sequence = next(a);
            a.recoveryAuthorityTransitions ??= [];
            a.recoveryAuthorityTransitions.push(accepted);
            return { sequence, replayed: false, transitionHash: contentHash, contentHash };
        });
    }
    async transitionStatus(id: string, auth: RecoveryAuth, operationId: string): Promise<Record<string, unknown>> {
        identifier(operationId);
        return this.authenticated(id, auth, (a, s) => { const record = a.recoveryAuthorityTransitions?.find(r => r.submission.transition.operationId === operationId); if (!record)
            return { operationId, accepted: false }; if (s.kind === "login" && record.submission.transition.authorizerDeviceId !== auth.deviceId)
            throw new Fault(403, "operation_forbidden"); const contentHash = transitionHash(record.submission); return { operationId, accepted: true, sequence: record.sequence, contentHash, transitionHash: contentHash }; });
    }
    async vault(id: string, auth: RecoveryAuth): Promise<Record<string, unknown>> {
        return this.authenticated(id, auth, (a, s, _, now) => {
            if (s.kind !== "recovery")
                allAdmin(a, auth.deviceId!, now);
            const head = chain(a);
            if (gap(a, head))
                throw new Fault(403, "recovery_chain_invalid");
            return structuredClone({ accountId: a.id, accountGeneration: a.generation, recoveryGeneration: a.recoveryGeneration, recoverySigningPublicKey: a.recoverySigningPublicKey, recoveryReceivingPublicKey: a.recoveryReceivingPublicKey, rotationRequired: s.kind === "recovery" ? s.rotationRequired : false, sequence: a.sequence, originalInitialization: original(a), issuerEvidence: buildRecoveryIssuerEvidence(a), transitions: a.recoveryAuthorityTransitions ?? [], trustRoot: a.trustRoot ?? null, publicDevices: Object.values(a.devices), currentGrants: Object.values(a.grants), grantHistory: a.grantHistory ?? [], environments: Object.values(a.environments).map(e => ({ environmentId: e.id, keyVersion: e.keyVersion, envelope: e.recoveryEnvelope })), events: a.events.filter(e => e.mutation.mutation.keyVersion === a.environments[e.mutation.mutation.environmentId]?.keyVersion), envelopeEvidence: recoveryEnvelopeEvidence(a) });
        });
    }
    async recoveredChallenge(id: string, auth: RecoveryAuth, input: {
        operationId: string;
        deviceId: string;
        deviceSigningPublicKey: string;
        deviceReceivingPublicKey: string;
    }): Promise<Record<string, unknown>> {
        exact(input, ["operationId", "deviceId", "deviceSigningPublicKey", "deviceReceivingPublicKey"]);
        identifier(input.operationId);
        identifier(input.deviceId);
        bytes(input.deviceSigningPublicKey, 32);
        bytes(input.deviceReceivingPublicKey, 32);
        return this.authenticated(id, auth, (a, s, hash, now) => {
            const h = chain(a);
            if (s.kind !== "recovery" || s.rotationRequired !== false || gap(a, h) || !(a.recoveryAuthorityTransitions?.length))
                throw new Fault(403, "recovery_rotation_required");
            const prior = own(a.recoveredDeviceChallenges, input.operationId);
            if (prior) {
                if (prior.restrictedSessionHash !== hash || prior.deviceId !== input.deviceId || prior.deviceSigningPublicKey !== input.deviceSigningPublicKey || prior.deviceReceivingPublicKey !== input.deviceReceivingPublicKey)
                    throw new Fault(409, "idempotency_conflict");
                return recoveredView(prior);
            }
            if (own(a.devices, input.deviceId))
                throw new Fault(409, "device_exists");
            novelKeys(a, [input.deviceSigningPublicKey, input.deviceReceivingPublicKey], h);
            a.recoveredDeviceChallenges ??= {};
            if (Object.keys(a.recoveredDeviceChallenges).length >= 128)
                throw new Fault(503, "account_capacity_reached");
            const proof = buildRecoveryIssuerEvidence(a);
            if (!proof)
                throw new Fault(403, "issuer_authority_unaccepted");
            const c: RecoveredChallenge = { ...input, challengeId: crypto.randomUUID(), nonce: randomToken(), expiresAt: now + ttl, restrictedSessionHash: hash, expectedSequence: String(a.sequence), recoveryGeneration: a.recoveryGeneration, recoveryTransitionHash: h.head, accountGeneration: a.generation, issuerEvidence: proof };
            a.recoveredDeviceChallenges[input.operationId] = c;
            return recoveredView(c);
        });
    }
    async recoverDevice(id: string, auth: RecoveryAuth, submission: RecoveredDeviceSubmission): Promise<Record<string, unknown>> {
        recoveredSubmissionReferences(submission);
        const e = submission.enrollment, contentHash = recoveredDeviceHash(submission);
        return this.authenticated(id, auth, (a, s, hash, now) => {
            if (s.kind !== "recovery" || s.rotationRequired !== false)
                throw new Fault(403, "recovery_rotation_required");
            const existing = Object.values(a.recoveredDevices ?? {}).find(r => r.submission.enrollment.operationId === e.operationId);
            if (existing) {
                if (existing.submission.enrollment.restrictedSessionHash !== hash || recoveredDeviceHash(existing.submission) !== contentHash)
                    throw new Fault(409, "idempotency_conflict");
                return { sequence: existing.sequence, replayed: true, recoveryEnrollmentHash: contentHash, contentHash };
            }
            const h = chain(a), c = own(a.recoveredDeviceChallenges, e.operationId);
            if (gap(a, h) || !c || c.accountGeneration !== a.generation || c.restrictedSessionHash !== hash || e.restrictedSessionHash !== hash || c.expiresAt <= now || e.challengeId !== c.challengeId || e.nonce !== c.nonce || e.expiresAt !== String(c.expiresAt) || e.accountId !== a.id || e.accountGeneration !== a.generation || e.expectedSequence !== c.expectedSequence || e.expectedSequence !== String(a.sequence) || e.recoveryGeneration !== c.recoveryGeneration || e.recoveryGeneration !== a.recoveryGeneration || e.recoveryTransitionHash !== c.recoveryTransitionHash || e.recoveryTransitionHash !== h.head || e.deviceId !== c.deviceId || e.deviceSigningPublicKey !== c.deviceSigningPublicKey || e.deviceReceivingPublicKey !== c.deviceReceivingPublicKey || JSON.stringify(submission.issuerEvidence) !== JSON.stringify(c.issuerEvidence))
                throw new Fault(403, "challenge_invalid");
            if (own(a.devices, e.deviceId))
                throw new Fault(409, "device_exists");
            novelKeys(a, [e.deviceSigningPublicKey, e.deviceReceivingPublicKey], h);
            verifyAcceptedIssuerOriginEvidence(a, submission.issuerEvidence);
            for (const row of submission.selectedRights) {
                if (a.environments[row.environmentId]?.keyVersion !== row.keyVersion)
                    throw new Fault(409, "key_version_stale");
                if (row.expiresAt !== "0" && BigInt(row.expiresAt) <= BigInt(now))
                    throw new Fault(400, "grant_already_expired");
            }
            verify(h.signing, recoveredEnrollmentBytes(e), submission.recoverySignature);
            verify(e.deviceSigningPublicKey, recoveredEnrollmentBytes(e), submission.deviceSignature);
            if (Object.keys(a.devices).length >= 256)
                throw new Fault(503, "account_capacity_reached");
            a.devices[e.deviceId] = { id: e.deviceId, signingPublicKey: e.deviceSigningPublicKey, receivingPublicKey: e.deviceReceivingPublicKey, revoked: false };
            const sequence = next(a);
            a.recoveredDevices ??= {};
            a.recoveredDevices[e.deviceId] = { submission: structuredClone(submission), sequence };
            a.grantHistory ??= [];
            for (const signed of submission.grants) {
                a.grants[grantKey(signed.grant.environmentId, e.deviceId)] = structuredClone(signed);
                a.grantHistory.push({ sequence, grant: structuredClone(signed), authorization: null, recoveryEnrollmentHash: contentHash } as typeof a.grantHistory[number]);
            }
            return { sequence, replayed: false, recoveryEnrollmentHash: contentHash, contentHash };
        });
    }
    async recoveredStatus(id: string, auth: RecoveryAuth, operationId: string): Promise<Record<string, unknown>> {
        identifier(operationId);
        return this.authenticated(id, auth, (a, s) => { const record = Object.values(a.recoveredDevices ?? {}).find(r => r.submission.enrollment.operationId === operationId); if (!record)
            return { operationId, accepted: false }; if (s.kind === "login" && s.deviceId !== record.submission.enrollment.deviceId)
            throw new Fault(403, "operation_forbidden"); const contentHash = recoveredDeviceHash(record.submission); return { operationId, accepted: true, sequence: record.sequence, contentHash, recoveryEnrollmentHash: contentHash }; });
    }
}
