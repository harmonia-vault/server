import { canonical, exact, hash, initializationHash } from "./enrollment-wire.js";
import { bytes, generation, identifier, verify } from "./protocol.js";
import { Fault } from "./model.js";
import type { RecoverySource } from "./recovery-dag-wire.js";
import { trustRootPayload, trustRootHash, validateTrustRoot, type TrustRoot } from "./trust-root.js";
import type { OriginalInitialization } from "./initialization-evidence.js";
import type { Envelope } from "./lifecycle-wire.js";
export interface RecoveryEnvironmentVersion {
    environmentId: string;
    keyVersion: string;
}
export interface RecoveryAdminAuthority extends RecoveryEnvironmentVersion {
    grantGeneration: string;
    expiresAt: string;
    authorityHash: string;
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
}
export interface RecoveryTransitionSubmission {
    transition: RecoveryAuthorityTransition;
    environmentManifest: RecoveryEnvironmentVersion[];
    authoritySet: RecoveryAdminAuthority[];
    issuerEvidence: RecoverySource | null;
    envelopes: Envelope[];
    newTrustRoot: TrustRoot;
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
    exact(t, ["accountId", "accountGeneration", "operationId", "challengeId", "nonce", "expiresAt", "sessionHash", "expectedSequence", "previousTransitionHash", "oldRecoveryGeneration", "oldRecoverySigningPublicKey", "oldRecoveryReceivingPublicKey", "newRecoveryGeneration", "newRecoverySigningPublicKey", "newRecoveryReceivingPublicKey", "authorizationKind", "authorizerDeviceId", "environmentManifestHash", "authoritySetHash", "issuerEvidenceHash", "envelopesHash", "newTrustRootHash"]);
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
        if (t.authorizerDeviceId !== "" || t.authoritySetHash !== "" || t.issuerEvidenceHash !== "")
            throw new Fault(400, "fields_invalid");
    }
    else if (t.authorizationKind === "all-environments-admin") {
        identifier(t.authorizerDeviceId);
        digest(t.authoritySetHash);
        digest(t.issuerEvidenceHash);
    }
    else
        throw new Fault(400, "fields_invalid");
    return canonical(["harmonia/recovery-authority-transition/v2", t.accountId, t.accountGeneration, t.operationId, t.challengeId, t.nonce, t.expiresAt, t.sessionHash, t.expectedSequence, t.previousTransitionHash, t.oldRecoveryGeneration, t.oldRecoverySigningPublicKey, t.oldRecoveryReceivingPublicKey, t.newRecoveryGeneration, t.newRecoverySigningPublicKey, t.newRecoveryReceivingPublicKey, t.authorizationKind, t.authorizerDeviceId, t.environmentManifestHash, t.authoritySetHash, t.issuerEvidenceHash, t.envelopesHash, t.newTrustRootHash]);
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
export function recoveryRootHash(accountId: string, gen: string, root: TrustRoot): string { validateTrustRoot(accountId, gen, root); return hash(["harmonia/recovery-trust-root-ref/v1", b64(canonical(trustRootPayload(accountId, gen, root))), root.signature]); }
