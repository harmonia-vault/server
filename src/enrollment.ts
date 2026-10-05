import { registrationVerificationRequired } from "./registration.js";
import type { Account, Auth, SignedGrant } from "./model.js";
import { Fault, grantKey } from "./model.js";
import type { Store } from "./store.js";
import { bytes, generation, grantBytes, identifier, verify } from "./protocol.js";
import { device, next, permission, randomToken, sameAccount, session, tokenHash } from "./service.js";
import { canonical, exact, initializationFields, initializationHash, own, pairingProfile, proposalRoot, transcriptHash,
  type EnrollmentAccount, type EnrollmentCertificate, type InitializationProposal, type InitializationRecord, type PairingRecord } from "./enrollment-wire.js";
export interface LoginAuth { token: string; accountGeneration: string }
export interface Relay { side: "initiator" | "approver"; kind: "message" | "confirmation"; payload: string; signature: string }
function empty(a: EnrollmentAccount): void {
  if (a.trustRoot || a.recoverySigningPublicKey || Object.keys(a.devices).length || Object.keys(a.environments).length ||
    Object.keys(a.grants).length || a.events.length || a.sequence !== 0) throw new Fault(409, "vault_already_initialized");
}
function rootView(accountId: string, r: InitializationRecord): Record<string, unknown> {
  return { state: r.complete ? "complete" : "pending", challengeId: r.id, idempotencyKey: r.proposal.idempotencyKey, nonce: r.nonce,
    expiresAt: r.expiresAt, proposalHash: r.proposalHash, signingPayload: initializationFields(accountId, r), sequence: r.complete?.sequence ?? null };
}
export function approvalStillValid(a: EnrollmentAccount, r: Pick<PairingRecord, "context">, grants: SignedGrant[], now: number): void {
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
export class EnrollmentService {
  constructor(readonly store: Store, private readonly clock = () => Math.floor(Date.now() / 1000)) {}
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
}
export function relayFields(r: Pick<PairingRecord, "context">, value: Pick<Relay, "side" | "kind" | "payload">): string[] {
  const c = r.context;
  return ["harmonia/pairing-relay/v1", c.accountId, c.accountGeneration, c.sessionId, c.challengeNonce, value.side, value.kind, value.payload];
}
