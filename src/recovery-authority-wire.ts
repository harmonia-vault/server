import { canonical, exact, hash, initializationHash } from "./enrollment-wire.js";
import { bytes, generation, identifier, verify } from "./protocol.js";
import { Fault } from "./model.js";
import { issuerOriginCanonical, type IssuerOriginProof } from "./issuer-origin.js";
import { trustRootPayload, trustRootHash, validateTrustRoot, type TrustRoot } from "./trust-root.js";
import type { OriginalInitialization } from "./initialization-evidence.js";
import type { Envelope } from "./lifecycle-wire.js";
export const recoveryAuthorityCapability = "issuer-recovery-v1";
export interface RecoveryEnvironmentVersion {
    environmentId: string;
    keyVersion: string;
}
export interface RecoveryAdminAuthority extends RecoveryEnvironmentVersion {
    grantGeneration: string;
    expiresAt: string;
    authorityHash: string;
}
export interface RecoveryLegacyRotation {
    idempotencyKey: string;
    signingBytes: string;
    signature: string;
    sequence: number;
}
export interface RecoveryLegacyState {
    recoveryGeneration: string;
    recoverySigningPublicKey: string;
    recoveryReceivingPublicKey: string;
    trustRoot: TrustRoot;
    rotations: RecoveryLegacyRotation[];
}
export interface RecoveryAuthorityTransition {
    accountId: string;
    accountGeneration: string;
    operationId: string;
    challengeId: string;
    nonce: string;
    expiresAt: string;
    sessionHash: string;
    expectedSequence: string;
    previousTransitionHash: string;
    oldRecoveryGeneration: string;
    oldRecoverySigningPublicKey: string;
    oldRecoveryReceivingPublicKey: string;
    newRecoveryGeneration: string;
    newRecoverySigningPublicKey: string;
    newRecoveryReceivingPublicKey: string;
    authorizationKind: "old-recovery" | "all-environments-admin";
    authorizerDeviceId: string;
    environmentManifestHash: string;
    authoritySetHash: string;
    issuerEvidenceHash: string;
    envelopesHash: string;
    newTrustRootHash: string;
    chainMode: "continuous" | "manager-reanchor";
    legacyStateHash: string;
}
export interface RecoveryTransitionSubmission {
    transition: RecoveryAuthorityTransition;
    environmentManifest: RecoveryEnvironmentVersion[];
    authoritySet: RecoveryAdminAuthority[];
    issuerEvidence: IssuerOriginProof | null;
    envelopes: Envelope[];
    newTrustRoot: TrustRoot;
    legacyState: RecoveryLegacyState | null;
    authorizationSignature: string;
    newRecoverySignature: string;
}
export interface AcceptedRecoveryTransition {
    submission: RecoveryTransitionSubmission;
    sequence: number;
}
export function digest(value: string): void { if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value))
    throw new Fault(400, "encoding_invalid"); }
export function decimal(value: string): void { if (value !== "0")
    generation(value); }
export function sequence(value: string): void { decimal(value); if (BigInt(value) >= BigInt(Number.MAX_SAFE_INTEGER))
    throw new Fault(400, "checkpoint_invalid"); }
export function publicPair(signing: string, receiving: string): void { bytes(signing, 32); bytes(receiving, 32); if (signing === receiving)
    throw new Fault(400, "key_purpose_invalid"); }
const b64 = (b: Uint8Array): string => Buffer.from(b).toString("base64url");
export function initializationReference(original: OriginalInitialization): string {
    exact(original, ["proposal", "proof", "deviceSignature", "recoverySignature", "sequence"]);
    const p = original.proposal, c = original.proof;
    exact(c, ["accountId", "accountGeneration", "loginTokenHash", "challengeId", "nonce", "expiresAt", "proposalHash"]);
    if (original.sequence !== 1 || initializationHash(c.accountId, c.accountGeneration, p) !== c.proposalHash)
        throw new Fault(403, "initialization_evidence_invalid");
    const envs = [...p.environments].sort((a, b) => a.environmentId < b.environmentId ? -1 : 1).map(e => [e.environmentId, e.keyVersion, e.recoveryEnvelope, b64(importGrantBytes(e.grant.grant)), e.grant.signature]);
    const proposal = canonical(["harmonia/vault-initialization-proposal/v1", p.idempotencyKey, p.device.id, p.device.signingPublicKey, p.device.receivingPublicKey, p.recoveryGeneration, p.recoverySigningPublicKey, p.recoveryReceivingPublicKey, p.trustRootSignature, envs]);
    identifier(c.accountId);
    generation(c.accountGeneration);
    identifier(c.challengeId);
    bytes(c.nonce, 32);
    generation(c.expiresAt);
    digest(c.loginTokenHash);
    digest(c.proposalHash);
    const proof = canonical(["harmonia/vault-initialize/v1", c.accountId, c.accountGeneration, c.loginTokenHash, c.challengeId, c.nonce, c.expiresAt, c.proposalHash]);
    verify(p.device.signingPublicKey, proof, original.deviceSignature);
    verify(p.recoverySigningPublicKey, proof, original.recoverySignature);
    return hash(["harmonia/recovery-initialization-anchor/v1", b64(proposal), b64(proof), original.deviceSignature, original.recoverySignature, "1"]);
}
import { grantBytes as importGrantBytes } from "./protocol.js";
export function transitionBytes(t: RecoveryAuthorityTransition): Uint8Array {
    exact(t, ["accountId", "accountGeneration", "operationId", "challengeId", "nonce", "expiresAt", "sessionHash", "expectedSequence", "previousTransitionHash", "oldRecoveryGeneration", "oldRecoverySigningPublicKey", "oldRecoveryReceivingPublicKey", "newRecoveryGeneration", "newRecoverySigningPublicKey", "newRecoveryReceivingPublicKey", "authorizationKind", "authorizerDeviceId", "environmentManifestHash", "authoritySetHash", "issuerEvidenceHash", "envelopesHash", "newTrustRootHash", "chainMode", "legacyStateHash"]);
    for (const id of [t.accountId, t.operationId, t.challengeId])
        identifier(id);
    for (const n of [t.accountGeneration, t.oldRecoveryGeneration, t.newRecoveryGeneration, t.expiresAt])
        generation(n);
    sequence(t.expectedSequence);
    bytes(t.nonce, 32);
    if (BigInt(t.expiresAt) > 9223372036854775807n || BigInt(t.newRecoveryGeneration) !== BigInt(t.oldRecoveryGeneration) + 1n)
        throw new Fault(400, "generation_invalid");
    publicPair(t.oldRecoverySigningPublicKey, t.oldRecoveryReceivingPublicKey);
    publicPair(t.newRecoverySigningPublicKey, t.newRecoveryReceivingPublicKey);
    if ([t.newRecoverySigningPublicKey, t.newRecoveryReceivingPublicKey].some(key => [t.oldRecoverySigningPublicKey, t.oldRecoveryReceivingPublicKey].includes(key)))
        throw new Fault(400, "key_purpose_invalid");
    for (const h of [t.sessionHash, t.previousTransitionHash, t.environmentManifestHash, t.envelopesHash, t.newTrustRootHash])
        digest(h);
    if (t.authorizationKind === "old-recovery") {
        if (t.authorizerDeviceId !== "" || t.authoritySetHash !== "" || t.issuerEvidenceHash !== "" || t.chainMode !== "continuous")
            throw new Fault(400, "fields_invalid");
    }
    else if (t.authorizationKind === "all-environments-admin") {
        identifier(t.authorizerDeviceId);
        digest(t.authoritySetHash);
        digest(t.issuerEvidenceHash);
    }
    else
        throw new Fault(400, "fields_invalid");
    if (t.chainMode === "continuous") {
        if (t.legacyStateHash !== "")
            throw new Fault(400, "fields_invalid");
    }
    else if (t.chainMode !== "manager-reanchor" || t.authorizationKind !== "all-environments-admin")
        throw new Fault(400, "fields_invalid");
    else
        digest(t.legacyStateHash);
    return canonical(["harmonia/recovery-authority-transition/v1", t.accountId, t.accountGeneration, t.operationId, t.challengeId, t.nonce, t.expiresAt, t.sessionHash, t.expectedSequence, t.previousTransitionHash, t.oldRecoveryGeneration, t.oldRecoverySigningPublicKey, t.oldRecoveryReceivingPublicKey, t.newRecoveryGeneration, t.newRecoverySigningPublicKey, t.newRecoveryReceivingPublicKey, t.authorizationKind, t.authorizerDeviceId, t.environmentManifestHash, t.authoritySetHash, t.issuerEvidenceHash, t.envelopesHash, t.newTrustRootHash, t.chainMode, t.legacyStateHash]);
}
function ordered<T extends RecoveryEnvironmentVersion>(rows: T[], fields: string[]): void { if (!Array.isArray(rows) || rows.length < 1 || rows.length > 256)
    throw new Fault(400, "manifest_invalid"); let last = ""; for (const row of rows) {
    exact(row, fields);
    identifier(row.environmentId);
    generation(row.keyVersion);
    if (row.environmentId <= last)
        throw new Fault(400, "manifest_invalid");
    last = row.environmentId;
} }
export function recoveryManifestHash(rows: RecoveryEnvironmentVersion[]): string { ordered(rows, ["environmentId", "keyVersion"]); return hash(["harmonia/recovery-environment-manifest/v1", rows.map(r => [r.environmentId, r.keyVersion])]); }
export function recoveryAdminHash(rows: RecoveryAdminAuthority[]): string { ordered(rows, ["environmentId", "keyVersion", "grantGeneration", "expiresAt", "authorityHash"]); for (const row of rows) {
    generation(row.grantGeneration);
    decimal(row.expiresAt);
    digest(row.authorityHash);
} return hash(["harmonia/recovery-admin-authorities/v1", rows.map(r => [r.environmentId, r.keyVersion, r.grantGeneration, r.expiresAt, r.authorityHash])]); }
export function recoveryEnvelopeRows(rows: Envelope[]): string[][] { ordered(rows, ["environmentId", "keyVersion", "envelope"]); for (const row of rows)
    bytes(row.envelope, 80); return rows.map(r => [r.environmentId, r.keyVersion, r.envelope]); }
export const recoveryEnvelopesHash = (rows: Envelope[]): string => hash(["harmonia/recovery-envelopes/v1", recoveryEnvelopeRows(rows)]);
export const recoveryEvidenceHash = (proof: IssuerOriginProof): string => hash(["harmonia/recovery-issuer-evidence-ref/v1", proof.profile, b64(issuerOriginCanonical(proof))]);
export function recoveryRootHash(accountId: string, gen: string, root: TrustRoot): string { validateTrustRoot(accountId, gen, root); return hash(["harmonia/recovery-trust-root-ref/v1", b64(canonical(trustRootPayload(accountId, gen, root))), root.signature]); }
export function transitionHash(s: RecoveryTransitionSubmission): string { bytes(s.authorizationSignature, 64); bytes(s.newRecoverySignature, 64); return hash(["harmonia/recovery-authority-transition-ref/v1", b64(transitionBytes(s.transition)), s.authorizationSignature, s.newRecoverySignature]); }
export function legacyStateHash(account: string, gen: string, l: RecoveryLegacyState): string {
    exact(l, ["recoveryGeneration", "recoverySigningPublicKey", "recoveryReceivingPublicKey", "trustRoot", "rotations"]);
    generation(l.recoveryGeneration);
    publicPair(l.recoverySigningPublicKey, l.recoveryReceivingPublicKey);
    validateTrustRoot(account, gen, l.trustRoot);
    if (l.trustRoot.recoveryGeneration !== l.recoveryGeneration || l.trustRoot.recoverySigningPublicKey !== l.recoverySigningPublicKey || l.trustRoot.recoveryReceivingPublicKey !== l.recoveryReceivingPublicKey || !Array.isArray(l.rotations) || !l.rotations.length || l.rotations.length > 128)
        throw new Fault(403, "recovery_session_stale");
    let last = 1, previousGeneration = "";
    const ids = new Set<string>();
    const rows = l.rotations.map(row => {
        exact(row, ["idempotencyKey", "signingBytes", "signature", "sequence"]);
        identifier(row.idempotencyKey);
        if (ids.has(row.idempotencyKey) || !Number.isSafeInteger(row.sequence) || row.sequence <= last)
            throw new Fault(400, "fields_invalid");
        ids.add(row.idempotencyKey);
        last = row.sequence;
        const raw = bytes(row.signingBytes);
        if (!raw.length || raw.length > 4096)
            throw new Fault(400, "fields_invalid");
        let fields: string[];
        try {
            fields = JSON.parse(Buffer.from(raw).toString("utf8")) as string[];
        }
        catch {
            throw new Fault(400, "fields_invalid");
        }
        if (!Array.isArray(fields) || fields.length !== 13 || fields.some(v => typeof v !== "string") || b64(canonical(fields)) !== row.signingBytes || fields[0] !== "harmonia/recovery-rotation/v1" || fields[1] !== account || fields[2] !== gen || previousGeneration && fields[4] !== previousGeneration)
            throw new Fault(400, "fields_invalid");
        for (const i of [2, 4, 7, 8])
            generation(fields[i]!);
        identifier(fields[5]!);
        bytes(fields[6]!, 32);
        digest(fields[3]!);
        digest(fields[11]!);
        digest(fields[12]!);
        publicPair(fields[9]!, fields[10]!);
        if (BigInt(fields[8]!) !== BigInt(fields[4]!) + 1n)
            throw new Fault(400, "generation_invalid");
        verify(fields[9]!, raw, row.signature);
        previousGeneration = fields[8]!;
        if (row === l.rotations.at(-1) && (fields[8] !== l.recoveryGeneration || fields[9] !== l.recoverySigningPublicKey || fields[10] !== l.recoveryReceivingPublicKey || fields[12] !== trustRootHash(account, gen, l.trustRoot)))
            throw new Fault(403, "recovery_session_stale");
        return [row.idempotencyKey, row.signingBytes, row.signature, String(row.sequence)];
    });
    return hash(["harmonia/recovery-legacy-state/v1", l.recoveryGeneration, l.recoverySigningPublicKey, l.recoveryReceivingPublicKey, b64(canonical(trustRootPayload(account, gen, l.trustRoot))), l.trustRoot.signature, rows]);
}
export function submissionReferences(s: RecoveryTransitionSubmission): void {
    exact(s, ["transition", "environmentManifest", "authoritySet", "issuerEvidence", "envelopes", "newTrustRoot", "legacyState", "authorizationSignature", "newRecoverySignature"]);
    const t = s.transition;
    transitionBytes(t);
    bytes(s.authorizationSignature, 64);
    bytes(s.newRecoverySignature, 64);
    if (recoveryManifestHash(s.environmentManifest) !== t.environmentManifestHash || recoveryEnvelopesHash(s.envelopes) !== t.envelopesHash || recoveryRootHash(t.accountId, t.accountGeneration, s.newTrustRoot) !== t.newTrustRootHash || s.envelopes.length !== s.environmentManifest.length || s.envelopes.some((e, i) => e.environmentId !== s.environmentManifest[i]!.environmentId || e.keyVersion !== s.environmentManifest[i]!.keyVersion))
        throw new Fault(403, "binding_invalid");
    if (t.authorizationKind === "old-recovery") {
        if (!Array.isArray(s.authoritySet) || s.authoritySet.length || s.issuerEvidence !== null)
            throw new Fault(400, "fields_invalid");
    }
    else if (!s.issuerEvidence || recoveryAdminHash(s.authoritySet) !== t.authoritySetHash || recoveryEvidenceHash(s.issuerEvidence) !== t.issuerEvidenceHash || s.authoritySet.length !== s.environmentManifest.length)
        throw new Fault(403, "binding_invalid");
    if (t.chainMode === "continuous") {
        if (s.legacyState !== null)
            throw new Fault(400, "fields_invalid");
    }
    else if (!s.legacyState || legacyStateHash(t.accountId, t.accountGeneration, s.legacyState) !== t.legacyStateHash)
        throw new Fault(403, "binding_invalid");
    if (Buffer.byteLength(JSON.stringify(s)) > 2 * 1024 * 1024)
        throw new Fault(413, "body_too_large");
}
