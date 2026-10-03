import { enrollmentV4Fields, issuerRecoveryStillCurrent, type EnrollmentApprovalV4, type IssuerRecoveryProof } from "./issuer-recovery.js";
import { registrationVerificationRequired } from "./registration.js";
import { recoveryAuthorityCapability } from "./recovery-authority-wire.js";
import type { RecoveryAuthorityAccount } from "./recovery-authority.js";
import { enrollmentV3Fields, issuerOriginCapability, issuerOriginStillCurrent, type EnrollmentApprovalV3, type IssuerOriginProof } from "./issuer-origin.js";
import { enrollmentV2Fields, issuerProofCapability, issuerProofStillCurrent, type EnrollmentApprovalV2, type IssuerProof } from "./issuer-proof.js";
import type { Account, Auth, SignedGrant } from "./model.js";
import { Fault, grantKey } from "./model.js";
import type { Store } from "./store.js";
import { bytes, generation, grantBytes, identifier, verify } from "./protocol.js";
import { device, next, permission, randomToken, sameAccount, session, tokenHash } from "./service.js";
import { canonical, enrollmentFields, exact, initializationFields, initializationHash, own, pairingProfile, proposalRoot, transcriptHash,
  type EnrollmentAccount, type EnrollmentCertificate, type InitializationProposal, type InitializationRecord, type PairingRecord } from "./enrollment-wire.js";
export interface LoginAuth { token: string; accountGeneration: string }
export interface PairingProposal { idempotencyKey: string; deviceId: string; signingPublicKey: string; receivingPublicKey: string; approverDeviceId: string }
export interface PairingProposalV2 extends PairingProposal { certificateVersion: "2"; capabilities: string[] }
export interface ApprovalRequestV2 { certificateVersion: "2"; capabilities: string[]; grants: SignedGrant[]; transcriptHash: string; issuerProof: IssuerProof; signature: string }
export interface PairingProposalV3 extends PairingProposal { certificateVersion: "3"; capabilities: string[] }
export interface ApprovalRequestV3 { certificateVersion: "3"; capabilities: string[]; grants: SignedGrant[]; transcriptHash: string; issuerProof: IssuerOriginProof; signature: string }
export interface PairingProposalV4 extends PairingProposal { certificateVersion:"4"; capabilities:string[] }
export interface ApprovalRequestV4 {certificateVersion:"4";capabilities:string[];grants:SignedGrant[];transcriptHash:string;issuerProof:IssuerRecoveryProof;signature:string}
export interface Relay { side: "initiator" | "approver"; kind: "message" | "confirmation"; payload: string; signature: string }
function empty(a: EnrollmentAccount): void {
  if (a.trustRoot || a.recoverySigningPublicKey || Object.keys(a.devices).length || Object.keys(a.environments).length ||
    Object.keys(a.grants).length || a.events.length || a.sequence !== 0) throw new Fault(409, "vault_already_initialized");
}
function rootView(accountId: string, r: InitializationRecord): Record<string, unknown> {
  return { state: r.complete ? "complete" : "pending", challengeId: r.id, idempotencyKey: r.proposal.idempotencyKey, nonce: r.nonce,
    expiresAt: r.expiresAt, proposalHash: r.proposalHash, signingPayload: initializationFields(accountId, r), sequence: r.complete?.sequence ?? null };
}
function manager(a: Account, auth: Auth, hash: string, now: number): void {
  const current = session(a, hash, now); device(a, auth.deviceId);
  if (current.deviceId !== auth.deviceId) throw new Fault(403, "device_proof_required");
  if (!Object.keys(a.environments).some(id => { try { return permission(a, auth.deviceId, id, now).role === "admin"; } catch { return false; } })) throw new Fault(403, "admin_required");
}
function approvalStillValid(a: EnrollmentAccount, r: PairingRecord, grants: SignedGrant[], now: number): void {
  const c = r.context;
  device(a, c.approverDeviceId);
  const d = own(a.devices, c.approverDeviceId)!;
  if (d.signingPublicKey !== c.approverSigningPublicKey || d.receivingPublicKey !== c.approverReceivingPublicKey) throw new Fault(403, "device_key_mismatch");
  for (const signed of grants) {
    const g = signed.grant; const authority = permission(a, c.approverDeviceId, g.environmentId, now);
    if (authority.role !== "admin") throw new Fault(403, "admin_required");
    if (g.accountId !== a.id || g.accountGeneration !== a.generation || g.issuerDeviceId !== c.approverDeviceId || g.subjectDeviceId !== c.initiatorDeviceId ||
      g.subjectSigningPublicKey !== c.initiatorSigningPublicKey || g.subjectReceivingPublicKey !== c.initiatorReceivingPublicKey || g.keyVersion !== authority.keyVersion ||
      g.grantGeneration !== "1" || g.role === "none") throw new Fault(403, "enrollment_grant_binding_invalid");
    if (g.expiresAt !== "0" && BigInt(g.expiresAt) <= BigInt(now)) throw new Fault(400, "grant_already_expired");
    if (authority.expiresAt !== "0" && (g.expiresAt === "0" || BigInt(g.expiresAt) > BigInt(authority.expiresAt))) throw new Fault(403, "expiry_escalation");
    verify(c.approverSigningPublicKey, grantBytes(g), signed.signature);
  }
}
function requireV1Root(a: EnrollmentAccount, r: PairingRecord): void {
  const root = a.trustRoot, c = r.context;
  if (!root || root.rootDeviceId !== c.approverDeviceId || root.rootSigningPublicKey !== c.approverSigningPublicKey || root.rootReceivingPublicKey !== c.approverReceivingPublicKey) throw new Fault(403, "issuer_proof_capability_required");
}
export class EnrollmentService {
  constructor(readonly store: Store, _legacyGlobalVerification = true, private readonly clock = () => Math.floor(Date.now() / 1000)) {}
  private async authorized<T>(accountId: string, auth: LoginAuth, operation: (account: EnrollmentAccount, now: number, hash: string) => T): Promise<T> {
    identifier(accountId); generation(auth.accountGeneration); bytes(auth.token, 32); const hash = await tokenHash(auth.token);
    return this.store.transaction(accountId, raw => {
      const a = raw as EnrollmentAccount; const now = this.clock(); sameAccount(a, auth.accountGeneration); session(a, hash, now);
      if (registrationVerificationRequired(a) && !a.verified) throw new Fault(403, "email_verification_required");
      return operation(a, now, hash);
    });
  }
  async initialize(accountId: string, auth: LoginAuth, proposal: InitializationProposal): Promise<Record<string, unknown>> {
    const proposalHash = initializationHash(accountId, auth.accountGeneration, proposal);
    return this.authorized(accountId, auth, (a, now, hash) => {
      const prior = own(a.vaultInitializations, proposal.idempotencyKey);
      if (prior) {
        if (prior.sessionHash !== hash || prior.proposalHash !== proposalHash) throw new Fault(409, "idempotency_conflict");
        return rootView(accountId, prior);
      }
      empty(a); a.vaultInitializations ??= {};
      for (const [key, old] of Object.entries(a.vaultInitializations)) if (!old.complete && old.expiresAt <= now) delete a.vaultInitializations[key];
      if (Object.keys(a.vaultInitializations).length >= 16) throw new Fault(429, "challenge_capacity_reached");
      const r: InitializationRecord = { id: crypto.randomUUID(), sessionHash: hash, accountGeneration: a.generation, nonce: randomToken(), expiresAt: now + 120,
        proposal: structuredClone(proposal), proposalHash };
      a.vaultInitializations[proposal.idempotencyKey] = r;
      return rootView(accountId, r);
    });
  }
  async initializationStatus(accountId: string, auth: LoginAuth, idempotencyKey: string): Promise<Record<string, unknown>> {
    identifier(idempotencyKey);
    return this.authorized(accountId, auth, (a, _, hash) => {
      const r = own(a.vaultInitializations, idempotencyKey);
      if (!r) return { state: "absent", idempotencyKey };
      if (r.sessionHash !== hash) throw new Fault(403, "initialization_forbidden");
      return rootView(accountId, r);
    });
  }
  async completeInitialization(accountId: string, auth: LoginAuth, idempotencyKey: string, challengeId: string, deviceSignature: string, recoverySignature: string): Promise<Record<string, unknown>> {
    identifier(idempotencyKey); identifier(challengeId); bytes(deviceSignature, 64); bytes(recoverySignature, 64);
    return this.authorized(accountId, auth, (a, now, hash) => {
      const r = own(a.vaultInitializations, idempotencyKey);
      if (!r || r.sessionHash !== hash || r.id !== challengeId || r.accountGeneration !== a.generation) throw new Fault(403, "challenge_invalid");
      if (r.complete) {
        if (r.complete.deviceSignature !== deviceSignature || r.complete.recoverySignature !== recoverySignature) throw new Fault(409, "idempotency_conflict");
        return { ...rootView(accountId, r), replayed: true };
      }
      empty(a); if (r.expiresAt <= now) throw new Fault(403, "challenge_invalid");
      if (initializationHash(a.id, a.generation, r.proposal) !== r.proposalHash) throw new Fault(409, "proposal_changed");
      const p = r.proposal, message = canonical(initializationFields(a.id, r));
      verify(p.device.signingPublicKey, message, deviceSignature); verify(p.recoverySigningPublicKey, message, recoverySignature);
      a.devices[p.device.id] = { ...p.device, revoked: false }; a.trustRoot = proposalRoot(p);
      a.recoveryGeneration = p.recoveryGeneration; a.recoverySigningPublicKey = p.recoverySigningPublicKey; a.recoveryReceivingPublicKey = p.recoveryReceivingPublicKey;
      for (const e of p.environments) {
        a.environments[e.environmentId] = { id: e.environmentId, keyVersion: e.keyVersion, recoveryEnvelope: e.recoveryEnvelope,
          recoveryGeneration: a.recoveryGeneration, recoveryKeyVersion: e.keyVersion };
        a.grants[grantKey(e.environmentId, p.device.id)] = structuredClone(e.grant);
      }
      const sequence = next(a);
      a.grantHistory ??= [];
      for (const e of p.environments) a.grantHistory.push({ sequence, grant: structuredClone(e.grant), authorization: null });
      r.complete = { sequence, deviceSignature, recoverySignature };
      // Competing pending init challenges cannot replace an initialized root.
      a.vaultInitializations = { [idempotencyKey]: r };
      return { ...rootView(accountId, r), replayed: false };
    });
  }
  async beginPairing(accountId: string, auth: LoginAuth, proposal: PairingProposal | PairingProposalV2 | PairingProposalV3 | PairingProposalV4, version: "1" | "2" | "3" | "4" = "1"): Promise<Record<string, unknown>> {
    exact(proposal, ["idempotencyKey", "deviceId", "signingPublicKey", "receivingPublicKey", "approverDeviceId", ...(version !== "1" ? ["certificateVersion", "capabilities"] : [])]);
    if (version === "2") negotiated(proposal as PairingProposalV2);
    if (version === "3") negotiatedV3(proposal as PairingProposalV3);
    if (version === "4") negotiatedV4(proposal as PairingProposalV4);
    identifier(proposal.idempotencyKey); identifier(proposal.deviceId); identifier(proposal.approverDeviceId);
    bytes(proposal.signingPublicKey, 32); bytes(proposal.receivingPublicKey, 32);
    if (proposal.deviceId === proposal.approverDeviceId || proposal.signingPublicKey === proposal.receivingPublicKey) throw new Fault(400, "pairing_identity_invalid");
    return this.authorized(accountId, auth, (a, now, hash) => {
      if (!a.trustRoot) throw new Fault(409, "trust_root_required");
      if (version === "1" && proposal.approverDeviceId !== a.trustRoot.rootDeviceId) throw new Fault(403, "issuer_proof_capability_required");
      device(a, proposal.approverDeviceId);
      if (!Object.keys(a.environments).some(id => { try { return permission(a, proposal.approverDeviceId, id, now).role === "admin"; } catch { return false; } })) throw new Fault(403, "admin_required");
      const approver = own(a.devices, proposal.approverDeviceId)!;
      if (proposal.signingPublicKey === approver.signingPublicKey) throw new Fault(400, "pairing_identity_invalid");
      a.pairingSessions ??= {};
      const prior = own(a.pairingSessions, proposal.idempotencyKey);
      if (prior) {
        const c = prior.context;
        if (prior.initiatorSessionHash !== hash || c.initiatorDeviceId !== proposal.deviceId || c.initiatorSigningPublicKey !== proposal.signingPublicKey ||
          c.initiatorReceivingPublicKey !== proposal.receivingPublicKey || c.approverDeviceId !== proposal.approverDeviceId || (prior.certificateVersion ?? "1") !== version) throw new Fault(409, "idempotency_conflict");
        return pairingView(prior);
      }
      if (own(a.devices, proposal.deviceId)) throw new Fault(409, "device_id_exists");
      const allKeys = Object.values(a.devices).flatMap(d => [d.signingPublicKey, d.receivingPublicKey]);
      if (allKeys.includes(proposal.signingPublicKey) || allKeys.includes(proposal.receivingPublicKey) || [a.recoverySigningPublicKey, a.recoveryReceivingPublicKey].some(k => k === proposal.signingPublicKey || k === proposal.receivingPublicKey)) throw new Fault(400, "pairing_identity_invalid");
      for (const [key, old] of Object.entries(a.pairingSessions)) if (!old.sequence && Number(old.context.expiresAt) <= now) delete a.pairingSessions[key];
      if (Object.keys(a.devices).length >= 64 || Object.keys(a.pairingSessions).length >= 64) throw new Fault(429, "pairing_capacity_reached");
      const record: PairingRecord = { idempotencyKey: proposal.idempotencyKey, initiatorSessionHash: hash, ...(version !== "1" ? { certificateVersion: version } : {}),
        context: { accountId, accountGeneration: a.generation, purpose: "enroll-device", sessionId: crypto.randomUUID(), challengeNonce: randomToken(), expiresAt: String(now + 120),
          initiatorDeviceId: proposal.deviceId, initiatorSigningPublicKey: proposal.signingPublicKey, initiatorReceivingPublicKey: proposal.receivingPublicKey,
          approverDeviceId: proposal.approverDeviceId, approverSigningPublicKey: approver.signingPublicKey, approverReceivingPublicKey: approver.receivingPublicKey },
        messages: {}, confirmations: {} };
      a.pairingSessions[proposal.idempotencyKey] = record;
      return pairingView(record);
    });
  }
  private async pairing<T>(accountId: string, auth: LoginAuth & { deviceId?: string }, key: string, operation: (a: EnrollmentAccount, r: PairingRecord, side: "initiator" | "approver", now: number) => T, version: "1" | "2" | "3" | "4" = "1"): Promise<T> {
    identifier(key); if (auth.deviceId) identifier(auth.deviceId);
    return this.authorized(accountId, auth, (a, now, hash) => {
      const r = own(a.pairingSessions, key);
      if (!r || (r.certificateVersion ?? "1") !== version || r.context.accountGeneration !== a.generation) throw new Fault(404, "pairing_not_found");
      let side: "initiator" | "approver";
      if (hash === r.initiatorSessionHash) side = "initiator";
      else if (auth.deviceId === r.context.approverDeviceId) { manager(a, auth as Auth, hash, now); side = "approver"; }
      else throw new Fault(403, "pairing_forbidden");
      if (!r.sequence && Number(r.context.expiresAt) <= now) throw new Fault(403, "challenge_invalid");
      return operation(a, r, side, now);
    });
  }
  async pairingStatus(accountId: string, auth: LoginAuth & { deviceId?: string }, key: string, version: "1" | "2" | "3" | "4" = "1"): Promise<Record<string, unknown>> {
    return this.pairing(accountId, auth, key, (_, r) => pairingView(r), version);
  }
  async relay(accountId: string, auth: LoginAuth & { deviceId?: string }, key: string, value: Relay, version: "1" | "2" | "3" | "4" = "1"): Promise<Record<string, unknown>> {
    exact(value, ["side", "kind", "payload", "signature"]);
    if (!["initiator", "approver"].includes(value.side) || !["message", "confirmation"].includes(value.kind)) throw new Fault(400, "relay_invalid");
    bytes(value.payload, 32); bytes(value.signature, 64);
    return this.pairing(accountId, auth, key, (_, r, side) => {
      if (r.sequence || r.approval || side !== value.side) throw new Fault(403, "pairing_step_invalid");
      if (value.kind === "confirmation" && (!r.messages.initiator || !r.messages.approver)) throw new Fault(409, "pairing_messages_required");
      verify(side === "initiator" ? r.context.initiatorSigningPublicKey : r.context.approverSigningPublicKey,
        canonical(relayFields(r, value)), value.signature);
      const target = value.kind === "message" ? r.messages : r.confirmations;
      const old = target[side]; if (old && old !== value.payload) throw new Fault(409, "relay_already_consumed");
      if (value.kind === "message" && value.payload === r.messages[side === "initiator" ? "approver" : "initiator"]) throw new Fault(400, "pairing_reflection");
      target[side] = value.payload;
      return pairingView(r);
    }, version);
  }
  async approve(accountId: string, auth: Auth, key: string, value: { grants: SignedGrant[]; transcriptHash: string; signature: string }): Promise<Record<string, unknown>> {
    exact(value, ["grants", "transcriptHash", "signature"]);
    return this.pairing(accountId, auth, key, (a, r, side, now) => {
      if (side !== "approver" || r.sequence) throw new Fault(403, "admin_required");
      requireV1Root(a, r);
      if (value.transcriptHash !== transcriptHash(r)) throw new Fault(403, "pairing_transcript_mismatch");
      const certificate: EnrollmentCertificate = { context: structuredClone(r.context), pairingProfile, transcriptHash: value.transcriptHash,
        grants: structuredClone(value.grants), approverSignature: value.signature };
      const fields = enrollmentFields(certificate); approvalStillValid(a, r, certificate.grants, now);
      verify(r.context.approverSigningPublicKey, canonical(fields), value.signature);
      if (r.approval && JSON.stringify(r.approval) !== JSON.stringify(certificate)) throw new Fault(409, "approval_already_consumed");
      r.approval = certificate;
      return pairingView(r);
    });
  }
  async approveV2(accountId: string, auth: Auth, key: string, value: ApprovalRequestV2): Promise<Record<string, unknown>> {
    exact(value, ["certificateVersion", "capabilities", "grants", "transcriptHash", "issuerProof", "signature"]); negotiated(value);
    return this.pairing(accountId, auth, key, (a, r, side, now) => {
      if (side !== "approver" || r.sequence) throw new Fault(403, "admin_required");
      if (value.transcriptHash !== transcriptHash(r)) throw new Fault(403, "pairing_transcript_mismatch");
      const certificate: EnrollmentApprovalV2 = { certificateVersion: "2", context: structuredClone(r.context), pairingProfile,
        transcriptHash: value.transcriptHash, grants: structuredClone(value.grants), issuerProof: structuredClone(value.issuerProof), approverSignature: value.signature };
      enrollmentV2Fields(certificate);
      approvalStillValid(a, r, certificate.grants, now);
      issuerProofStillCurrent(a, certificate);
      if (r.approval && (JSON.stringify(enrollmentV2Fields(r.approval as EnrollmentApprovalV2)) !== JSON.stringify(enrollmentV2Fields(certificate)) || r.approval.approverSignature !== certificate.approverSignature)) throw new Fault(409, "approval_already_consumed");
      r.approval = certificate;
      return pairingView(r);
    }, "2");
  }
  async approveV3(accountId: string, auth: Auth, key: string, value: ApprovalRequestV3): Promise<Record<string, unknown>> {
    exact(value, ["certificateVersion", "capabilities", "grants", "transcriptHash", "issuerProof", "signature"]); negotiatedV3(value);
    return this.pairing(accountId, auth, key, (a, record, side, now) => {
      if (side !== "approver" || record.sequence) throw new Fault(403, "admin_required");
      if (value.transcriptHash !== transcriptHash(record)) throw new Fault(403, "pairing_transcript_mismatch");
      const certificate: EnrollmentApprovalV3 = { certificateVersion: "3", context: structuredClone(record.context), pairingProfile,
        transcriptHash: value.transcriptHash, grants: structuredClone(value.grants), issuerProof: structuredClone(value.issuerProof), approverSignature: value.signature };
      enrollmentV3Fields(certificate);
      approvalStillValid(a, record, certificate.grants, now);
      issuerOriginStillCurrent(a, certificate);
      if (record.approval && (JSON.stringify(enrollmentV3Fields(record.approval as EnrollmentApprovalV3)) !== JSON.stringify(enrollmentV3Fields(certificate)) || record.approval.approverSignature !== certificate.approverSignature)) throw new Fault(409, "approval_already_consumed");
      record.approval = certificate;
      return pairingView(record);
    }, "3");
  }
  async approveV4(accountId: string, auth: Auth, key: string, value: ApprovalRequestV4): Promise<Record<string, unknown>> {
    exact(value, ["certificateVersion", "capabilities", "grants", "transcriptHash", "issuerProof", "signature"]); negotiatedV4(value);
    return this.pairing(accountId, auth, key, (a, record, side, now) => {
      if (side !== "approver" || record.sequence) throw new Fault(403, "admin_required");
      if (value.transcriptHash !== transcriptHash(record)) throw new Fault(403, "pairing_transcript_mismatch");
      const certificate: EnrollmentApprovalV4 = { certificateVersion: "4", capabilities:["issuer-recovery-v1"], context: structuredClone(record.context), pairingProfile,
        transcriptHash: value.transcriptHash, grants: structuredClone(value.grants), issuerProof: structuredClone(value.issuerProof), approverSignature: value.signature };
      enrollmentV4Fields(certificate);
      approvalStillValid(a, record, certificate.grants, now);
      issuerRecoveryStillCurrent(a as RecoveryAuthorityAccount, certificate);
      if (record.approval && (JSON.stringify(enrollmentV4Fields(record.approval as EnrollmentApprovalV4)) !== JSON.stringify(enrollmentV4Fields(certificate)) || record.approval.approverSignature !== certificate.approverSignature)) throw new Fault(409, "approval_already_consumed");
      record.approval = certificate;
      return pairingView(record);
    }, "4");
  }
  async completePairing(accountId: string, auth: LoginAuth, key: string, signature: string, version: "1" | "2" | "3" | "4" = "1"): Promise<Record<string, unknown>> {
    bytes(signature, 64);
    return this.pairing(accountId, auth, key, (a, r, side, now) => {
      if (side !== "initiator" || !r.approval) throw new Fault(403, "approval_required");
      const certificate = r.approval;
      if (r.sequence) {
        if (certificate.initiatorSignature !== signature) throw new Fault(409, "idempotency_conflict");
        device(a, r.context.initiatorDeviceId);
        return { ...pairingView(r), replayed: true };
      }
      if (own(a.devices, r.context.initiatorDeviceId)) throw new Fault(409, "device_id_exists");
      if (!r.certificateVersion) requireV1Root(a, r);
      approvalStillValid(a, r, certificate.grants, now);
      if (r.certificateVersion === "2") issuerProofStillCurrent(a, certificate as EnrollmentApprovalV2);
      if (r.certificateVersion === "3") issuerOriginStillCurrent(a, certificate as EnrollmentApprovalV3);
      if(r.certificateVersion==="4")issuerRecoveryStillCurrent(a as RecoveryAuthorityAccount,certificate as EnrollmentApprovalV4);
      const fields = r.certificateVersion === "4" ? enrollmentV4Fields(certificate as EnrollmentApprovalV4) : r.certificateVersion === "3" ? enrollmentV3Fields(certificate as EnrollmentApprovalV3) : r.certificateVersion === "2" ? enrollmentV2Fields(certificate as EnrollmentApprovalV2) : enrollmentFields(certificate);
      verify(r.context.approverSigningPublicKey, canonical(fields), certificate.approverSignature);
      verify(r.context.initiatorSigningPublicKey, canonical(fields), signature);
      certificate.initiatorSignature = signature;
      const c = r.context;
      a.devices[c.initiatorDeviceId] = { id: c.initiatorDeviceId, signingPublicKey: c.initiatorSigningPublicKey, receivingPublicKey: c.initiatorReceivingPublicKey, revoked: false };
      for (const g of certificate.grants) a.grants[grantKey(g.grant.environmentId, c.initiatorDeviceId)] = structuredClone(g);
      a.deviceEnrollments ??= {}; a.deviceEnrollments[c.initiatorDeviceId] = structuredClone(certificate);
      r.sequence = next(a);
      a.grantHistory ??= [];
      for (const g of certificate.grants) a.grantHistory.push({ sequence: r.sequence, grant: structuredClone(g), authorization: structuredClone(a.grants[grantKey(g.grant.environmentId, c.approverDeviceId)]!) });
      return { ...pairingView(r), replayed: false };
    }, version);
  }
}
export function relayFields(r: PairingRecord, value: Pick<Relay, "side" | "kind" | "payload">): string[] {
  const c = r.context;
  return ["harmonia/pairing-relay/v1", c.accountId, c.accountGeneration, c.sessionId, c.challengeNonce, value.side, value.kind, value.payload];
}
function pairingView(r: PairingRecord): Record<string, unknown> {
  return structuredClone({ state: r.sequence ? "complete" : r.approval ? "approved" : "pending", idempotencyKey: r.idempotencyKey,
    ...(r.certificateVersion ? { certificateVersion: r.certificateVersion, capabilities: [r.certificateVersion === "4" ? recoveryAuthorityCapability : r.certificateVersion === "3" ? issuerOriginCapability : issuerProofCapability] } : {}), pairingProfile, context: r.context, messages: r.messages, confirmations: r.confirmations, approval: r.approval ?? null, sequence: r.sequence ?? null });
}

function negotiated(value: { certificateVersion: string; capabilities: string[] }): void {
  if (value.certificateVersion !== "2" || !Array.isArray(value.capabilities) || value.capabilities.length !== 1 || value.capabilities[0] !== issuerProofCapability) throw new Fault(400, "issuer_proof_capability_required");
}

function negotiatedV3(value: { certificateVersion: string; capabilities: string[] }): void {
  if (value.certificateVersion !== "3" || !Array.isArray(value.capabilities) || value.capabilities.length !== 1 || value.capabilities[0] !== issuerOriginCapability) throw new Fault(400, "issuer_origin_capability_required");
}

function negotiatedV4(value:{certificateVersion:string;capabilities:string[]}):void{if(value.certificateVersion!=="4"||!Array.isArray(value.capabilities)||JSON.stringify(value.capabilities)!==JSON.stringify([recoveryAuthorityCapability]))throw new Fault(400,"recovery_capability_required");}
