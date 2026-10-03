import { exact, hash } from "./enrollment-wire.js";
import { canonical } from "./enrollment-wire.js";
import { bytes, generation, grantBytes, identifier, verify } from "./protocol.js";
import { Fault, type SignedGrant } from "./model.js";
import type { Envelope } from "./lifecycle-wire.js";
import type { IssuerOriginProof } from "./issuer-origin.js";
import { decimal, digest, publicPair, recoveryAuthorityCapability, recoveryEnvelopeRows, recoveryEvidenceHash, sequence } from "./recovery-authority-wire.js";
export interface RecoveredRight {
    environmentId: string;
    keyVersion: string;
    role: "ro" | "rw" | "admin";
    expiresAt: string;
}
export interface RecoveredEnrollment {
    accountId: string;
    accountGeneration: string;
    recoveryGeneration: string;
    recoveryTransitionHash: string;
    operationId: string;
    challengeId: string;
    nonce: string;
    expiresAt: string;
    restrictedSessionHash: string;
    expectedSequence: string;
    deviceId: string;
    deviceSigningPublicKey: string;
    deviceReceivingPublicKey: string;
    selectedRightsHash: string;
    grantsHash: string;
    issuerEvidenceHash: string;
    envelopesHash: string;
}
export interface RecoveredDeviceSubmission {
    certificateVersion: "4";
    capabilities: [
        "issuer-recovery-v1"
    ];
    enrollment: RecoveredEnrollment;
    selectedRights: RecoveredRight[];
    grants: SignedGrant[];
    issuerEvidence: IssuerOriginProof;
    envelopes: Envelope[];
    recoverySignature: string;
    deviceSignature: string;
}
export interface AcceptedRecoveredDevice {
    submission: RecoveredDeviceSubmission;
    sequence: number;
}
const b64 = (v: Uint8Array): string => Buffer.from(v).toString("base64url");
export function recoveredEnrollmentBytes(c: RecoveredEnrollment): Uint8Array {
    exact(c, ["accountId", "accountGeneration", "recoveryGeneration", "recoveryTransitionHash", "operationId", "challengeId", "nonce", "expiresAt", "restrictedSessionHash", "expectedSequence", "deviceId", "deviceSigningPublicKey", "deviceReceivingPublicKey", "selectedRightsHash", "grantsHash", "issuerEvidenceHash", "envelopesHash"]);
    for (const id of [c.accountId, c.operationId, c.challengeId, c.deviceId])
        identifier(id);
    for (const n of [c.accountGeneration, c.recoveryGeneration, c.expiresAt])
        generation(n);
    sequence(c.expectedSequence);
    bytes(c.nonce, 32);
    publicPair(c.deviceSigningPublicKey, c.deviceReceivingPublicKey);
    if (BigInt(c.expiresAt) > 9223372036854775807n)
        throw new Fault(400, "expiry_invalid");
    for (const h of [c.recoveryTransitionHash, c.restrictedSessionHash, c.selectedRightsHash, c.grantsHash, c.issuerEvidenceHash, c.envelopesHash])
        digest(h);
    return canonical(["harmonia/recovered-device-enrollment/v1", c.accountId, c.accountGeneration, c.recoveryGeneration, c.recoveryTransitionHash, c.operationId, c.challengeId, c.nonce, c.expiresAt, c.restrictedSessionHash, c.expectedSequence, c.deviceId, c.deviceSigningPublicKey, c.deviceReceivingPublicKey, c.selectedRightsHash, c.grantsHash, c.issuerEvidenceHash, c.envelopesHash]);
}
export function recoveredRightsHash(rows: RecoveredRight[]): string {
    if (!Array.isArray(rows) || !rows.length || rows.length > 256)
        throw new Fault(400, "manifest_invalid");
    let prior = "";
    for (const r of rows) {
        exact(r, ["environmentId", "keyVersion", "role", "expiresAt"]);
        identifier(r.environmentId);
        generation(r.keyVersion);
        decimal(r.expiresAt);
        if (r.environmentId <= prior || !["ro", "rw", "admin"].includes(r.role) || BigInt(r.expiresAt) > 9223372036854775807n)
            throw new Fault(400, "fields_invalid");
        prior = r.environmentId;
    }
    return hash(["harmonia/recovered-device-rights/v1", rows.map(r => [r.environmentId, r.keyVersion, r.role, r.expiresAt])]);
}
export function recoveredGrantsHash(rows: SignedGrant[]): string {
    if (!Array.isArray(rows) || !rows.length || rows.length > 256)
        throw new Fault(400, "manifest_invalid");
    let prior = "";
    return hash(["harmonia/recovered-device-grants/v1", rows.map(s => { exact(s, ["grant", "signature"]); bytes(s.signature, 64); const raw = grantBytes(s.grant); if (s.grant.environmentId <= prior)
            throw new Fault(400, "manifest_invalid"); prior = s.grant.environmentId; return [s.grant.environmentId, b64(raw), s.signature]; })]);
}
export const recoveredEnvelopesHash = (rows: Envelope[]): string => hash(["harmonia/recovered-device-envelopes/v1", recoveryEnvelopeRows(rows)]);
export function recoveredDeviceHash(s: RecoveredDeviceSubmission): string { bytes(s.recoverySignature, 64); bytes(s.deviceSignature, 64); return hash(["harmonia/recovered-device-enrollment-ref/v1", b64(recoveredEnrollmentBytes(s.enrollment)), s.recoverySignature, s.deviceSignature]); }
export function recoveredSubmissionReferences(s: RecoveredDeviceSubmission): void {
    exact(s, ["certificateVersion", "capabilities", "enrollment", "selectedRights", "grants", "issuerEvidence", "envelopes", "recoverySignature", "deviceSignature"]);
    if (s.certificateVersion !== "4" || !Array.isArray(s.capabilities) || JSON.stringify(s.capabilities) !== JSON.stringify([recoveryAuthorityCapability]))
        throw new Fault(400, "recovery_capability_required");
    const c = s.enrollment;
    recoveredEnrollmentBytes(c);
    bytes(s.recoverySignature, 64);
    bytes(s.deviceSignature, 64);
    if (recoveredRightsHash(s.selectedRights) !== c.selectedRightsHash || recoveredGrantsHash(s.grants) !== c.grantsHash || recoveredEnvelopesHash(s.envelopes) !== c.envelopesHash || recoveryEvidenceHash(s.issuerEvidence) !== c.issuerEvidenceHash || s.grants.length !== s.selectedRights.length || s.envelopes.length !== s.grants.length)
        throw new Fault(403, "binding_invalid");
    for (let i = 0; i < s.grants.length; i++) {
        const sgrant = s.grants[i]!, g = sgrant.grant, r = s.selectedRights[i]!, e = s.envelopes[i]!;
        if (g.accountId !== c.accountId || g.accountGeneration !== c.accountGeneration || g.issuerDeviceId !== c.deviceId || g.subjectDeviceId !== c.deviceId || g.subjectSigningPublicKey !== c.deviceSigningPublicKey || g.subjectReceivingPublicKey !== c.deviceReceivingPublicKey || g.grantGeneration !== "1" || g.environmentId !== r.environmentId || g.keyVersion !== r.keyVersion || g.role !== r.role || g.expiresAt !== r.expiresAt || g.environmentId !== e.environmentId || g.keyVersion !== e.keyVersion || g.envelope !== e.envelope)
            throw new Fault(403, "binding_invalid");
        verify(c.deviceSigningPublicKey, grantBytes(g), sgrant.signature);
    }
    if (Buffer.byteLength(JSON.stringify(s)) > 2 * 1024 * 1024)
        throw new Fault(413, "body_too_large");
}
