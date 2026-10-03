import { DAGRequired, type RecoveryDAGAccount } from './recovery-dag-account.js';
import { originalInitialization } from "./initialization-evidence.js";
import { recoveryEnvelopeCapability, recoveryEnvelopeEvidence } from "./recovery-envelope-evidence.js";
import { buildRecoveryIssuerEvidence, issuerOriginCapability } from "./issuer-origin.js";
import type { Account, Auth, Session } from "./model.js";
import { Fault } from "./model.js";
import { bytes, generation, identifier, verify } from "./protocol.js";
import type { Store } from "./store.js";
import { device, next, permission, randomToken, sameAccount, session, tokenHash } from "./service.js";
import { bootPayload, canonical, fullEnvelopes, recoveryPayload, rotationPayload, rotationTrustHash, validateRecoveryState,
  type Envelope, type RecoveryAuth, type RotationProposal, type RotationRecord } from "./lifecycle-wire.js";
const ttl = 120;
function granted(account: Account, deviceId: string, now: number): void {
  device(account, deviceId);
  const valid = Object.keys(account.environments).some(id => { try { permission(account, deviceId, id, now); return true; } catch { return false; } });
  if (!valid) throw new Fault(403, "no_current_grant");
}
function recoveryInitialized(account: Account): void {
  if (!account.recoverySigningPublicKey || !account.recoveryReceivingPublicKey) throw new Fault(409, "recovery_uninitialized");
  validateRecoveryState(account);
}
function actor(account: Account, auth: RecoveryAuth, hash: string, now: number): Session {
  sameAccount(account, auth.accountGeneration);
  const current = session(account, hash, now, true);
  if (current.kind === "recovery") {
    if (current.recoveryGeneration !== account.recoveryGeneration) throw new Fault(403, "recovery_session_stale");
    return current;
  }
  if (!auth.deviceId || current.deviceId !== auth.deviceId) throw new Fault(403, "device_proof_required");
  granted(account, auth.deviceId, now);
  const envs = Object.keys(account.environments);
  if (!envs.length || envs.some(id => permission(account, auth.deviceId!, id, now).role !== "admin")) throw new Fault(403, "all_environment_admin_required");
  return current;
}
function sessionAdd(account: Account, value: Session, now: number): void {
  account.sessions = account.sessions.filter(s => s.expiresAt > now);
  if (account.sessions.length >= 64) account.sessions.shift();
  account.sessions.push(value);
}
function view(accountId: string, record: RotationRecord, now: number, currentGeneration: string): Record<string, unknown> {
  const state = record.state === "complete" ? "complete" : record.recoveryGeneration !== currentGeneration ? "superseded" : record.expiresAt <= now ? "expired" : "pending";
  return { state, idempotencyKey: record.proposal.idempotencyKey, challengeId: record.id, nonce: record.nonce, expiresAt: record.expiresAt,
    recoveryGeneration: record.recoveryGeneration, newRecoveryGeneration: record.proposal.newRecoveryGeneration,
    envelopesHash: record.envelopesHash, trustRootHash: record.trustRootHash ?? null, sequence: record.sequence ?? null, signingPayload: rotationPayload(accountId, record) };
}
export class LifecycleService {
  constructor(readonly store: Store, private readonly clock: () => number = () => Math.floor(Date.now() / 1000)) {}
  bootChallenge(accountId: string, deviceId: string, accountGeneration: string): { challengeId: string; nonce: string; expiresAt: number; signingPayload: string[] } {
    identifier(accountId); identifier(deviceId); generation(accountGeneration);
    return this.store.transaction(accountId, account => {
      const now = this.clock(); sameAccount(account, accountGeneration); granted(account, deviceId, now);
      account.bootChallenges = (account.bootChallenges ?? []).filter(c => c.expiresAt > now);
      if (account.bootChallenges.length >= 32) throw new Fault(429, "challenge_capacity_reached");
      const d = account.devices[deviceId]!;
      const c = { id: crypto.randomUUID(), deviceId, generation: account.generation, signingPublicKey: d.signingPublicKey,
        receivingPublicKey: d.receivingPublicKey, nonce: randomToken(), expiresAt: now + ttl };
      account.bootChallenges.push(c);
      return { challengeId: c.id, nonce: c.nonce, expiresAt: c.expiresAt, signingPayload: bootPayload(account.id, c) };
    });
  }
  async bootSession(accountId: string, deviceId: string, accountGeneration: string, challengeId: string, signature: string): Promise<{ token: string; expiresAt: number }> {
    identifier(accountId); identifier(deviceId); identifier(challengeId); generation(accountGeneration);
    const token = randomToken(); const hash = await tokenHash(token);
    return this.store.transaction(accountId, account => {
      const now = this.clock(); sameAccount(account, accountGeneration); granted(account, deviceId, now);
      const c = account.bootChallenges?.find(c => c.id === challengeId);
      const d = account.devices[deviceId]!;
      if (!c || c.deviceId !== deviceId || c.generation !== account.generation || c.expiresAt <= now || c.signingPublicKey !== d.signingPublicKey || c.receivingPublicKey !== d.receivingPublicKey) throw new Fault(403, "challenge_invalid");
      verify(d.signingPublicKey, canonical(bootPayload(account.id, c)), signature);
      account.bootChallenges = account.bootChallenges!.filter(other => other.id !== c.id);
      const expiresAt = now + 3600;
      sessionAdd(account, { tokenHash: hash, generation: account.generation, expiresAt, kind: "login", deviceId }, now);
      return { token, expiresAt };
    });
  }
  recoveryChallenge(accountId: string, accountGeneration: string): { challengeId: string; nonce: string; expiresAt: number; recoveryGeneration: string; signingPayload: string[] } {
    identifier(accountId); generation(accountGeneration);
    return this.store.transaction(accountId, account => {
      const now = this.clock(); sameAccount(account, accountGeneration); recoveryInitialized(account);
      account.recoveryChallenges = (account.recoveryChallenges ?? []).filter(c => c.expiresAt > now);
      if (account.recoveryChallenges.length >= 16) throw new Fault(429, "challenge_capacity_reached");
      const c = { id: crypto.randomUUID(), generation: account.generation, recoveryGeneration: account.recoveryGeneration,
        signingPublicKey: account.recoverySigningPublicKey!, nonce: randomToken(), expiresAt: now + ttl };
      account.recoveryChallenges.push(c);
      return { challengeId: c.id, nonce: c.nonce, expiresAt: c.expiresAt, recoveryGeneration: c.recoveryGeneration, signingPayload: recoveryPayload(account.id, c) };
    });
  }
  async recoverySession(accountId: string, accountGeneration: string, challengeId: string, signature: string): Promise<{ token: string; expiresAt: number; rotationRequired: true }> {
    identifier(accountId); identifier(challengeId); generation(accountGeneration);
    const token = randomToken(); const hash = await tokenHash(token);
    return this.store.transaction(accountId, account => {
      const now = this.clock(); sameAccount(account, accountGeneration); recoveryInitialized(account);
      const c = account.recoveryChallenges?.find(c => c.id === challengeId);
      if (!c || c.generation !== account.generation || c.recoveryGeneration !== account.recoveryGeneration || c.signingPublicKey !== account.recoverySigningPublicKey || c.expiresAt <= now) throw new Fault(403, "challenge_invalid");
      verify(account.recoverySigningPublicKey!, canonical(recoveryPayload(account.id, c)), signature);
      account.recoveryChallenges = account.recoveryChallenges!.filter(other => other.id !== c.id);
      const expiresAt = now + 900;
      sessionAdd(account, { id: c.id, tokenHash: hash, generation: account.generation, recoveryGeneration: account.recoveryGeneration,
        expiresAt, kind: "recovery", rotationRequired: true }, now);
      return { token, expiresAt, rotationRequired: true };
    });
  }
  private async authorized<T>(accountId: string, auth: RecoveryAuth, operation: (account: Account, now: number, hash: string, current: Session) => T): Promise<T> {
    identifier(accountId); generation(auth.accountGeneration); bytes(auth.token, 32); if (auth.deviceId) identifier(auth.deviceId);
    const hash = await tokenHash(auth.token);
    return this.store.transaction(accountId, account => {
      const now = this.clock(); sameAccount(account, auth.accountGeneration); recoveryInitialized(account); const current = actor(account, auth, hash, now); if(DAGRequired(account as RecoveryDAGAccount))throw new Fault(426,"protocol_upgrade_required");
      return operation(account, now, hash, current);
    });
  }
  async recoveryVault(accountId: string, auth: RecoveryAuth, capability?: string, envelopeEvidence?: string): Promise<Record<string, unknown>> {
    if (capability !== undefined && capability !== issuerOriginCapability) throw new Fault(400, "issuer_origin_capability_required");
    if (envelopeEvidence !== undefined && (envelopeEvidence !== recoveryEnvelopeCapability || capability !== issuerOriginCapability)) throw new Fault(400, "issuer_origin_capability_required");
    return this.authorized(accountId, auth, (account, _, __, current) => {
      return structuredClone({ accountId, accountGeneration: account.generation, recoveryGeneration: account.recoveryGeneration,
        recoverySigningPublicKey: account.recoverySigningPublicKey, recoveryReceivingPublicKey: account.recoveryReceivingPublicKey,
        rotationRequired: current.kind === "recovery" ? current.rotationRequired : false, sequence: account.sequence,
        ...(capability ? { originalInitialization: originalInitialization(account), issuerEvidence: buildRecoveryIssuerEvidence(account) } : {}),
        ...(envelopeEvidence ? { envelopeEvidence: recoveryEnvelopeEvidence(account) } : {}),
        trustRoot: account.trustRoot ?? null, publicDevices: Object.values(account.devices), currentGrants: Object.values(account.grants), grantHistory: account.grantHistory ?? [],
        environments: Object.values(account.environments).map(e => ({ environmentId: e.id, keyVersion: e.keyVersion, envelope: e.recoveryEnvelope })),
        events: account.events.filter(e => e.mutation.mutation.keyVersion === account.environments[e.mutation.mutation.environmentId]?.keyVersion) });
    });
  }
  async beginRotation(accountId: string, auth: RecoveryAuth, proposal: RotationProposal): Promise<Record<string, unknown>> {
    if (!proposal || Object.keys(proposal).sort().join("|") !== (proposal.newTrustRoot ? "envelopes|idempotencyKey|newRecoveryGeneration|newRecoveryReceivingPublicKey|newRecoverySigningPublicKey|newTrustRoot" : "envelopes|idempotencyKey|newRecoveryGeneration|newRecoveryReceivingPublicKey|newRecoverySigningPublicKey")) throw new Fault(400, "proposal_fields_invalid");
    identifier(proposal.idempotencyKey); generation(proposal.newRecoveryGeneration); bytes(proposal.newRecoverySigningPublicKey, 32); bytes(proposal.newRecoveryReceivingPublicKey, 32);
    return this.authorized(accountId, auth, (account, now, hash) => {
      const manifestHash = rotationTrustHash(account, proposal);
      account.recoveryRotations ??= {};
      const old = account.recoveryRotations[proposal.idempotencyKey];
      if (old) {
        if (old.sessionHash !== hash || old.proposal.newRecoveryGeneration !== proposal.newRecoveryGeneration || old.proposal.newRecoverySigningPublicKey !== proposal.newRecoverySigningPublicKey || old.proposal.newRecoveryReceivingPublicKey !== proposal.newRecoveryReceivingPublicKey || old.envelopesHash !== fullEnvelopes(account, proposal.envelopes) || old.trustRootHash !== manifestHash) throw new Fault(409, "idempotency_conflict");
        return view(accountId, old, now, account.recoveryGeneration);
      }
      if (Object.keys(account.recoveryRotations).length >= 128) throw new Fault(503, "rotation_capacity_reached");
      if (BigInt(proposal.newRecoveryGeneration) !== BigInt(account.recoveryGeneration) + 1n) throw new Fault(409, "recovery_generation_conflict");
      if (proposal.newRecoverySigningPublicKey === account.recoverySigningPublicKey || proposal.newRecoveryReceivingPublicKey === account.recoveryReceivingPublicKey) throw new Fault(400, "recovery_key_unchanged");
      const hashEnvelopes = fullEnvelopes(account, proposal.envelopes);
      const record: RotationRecord = { state: "pending", id: crypto.randomUUID(), generation: account.generation,
        recoveryGeneration: account.recoveryGeneration, sessionHash: hash, deviceId: auth.deviceId ?? null, nonce: randomToken(), expiresAt: now + ttl,
        proposal: structuredClone(proposal), envelopesHash: hashEnvelopes, ...(manifestHash ? { trustRootHash: manifestHash } : {}) };
      account.recoveryRotations[proposal.idempotencyKey] = record;
      return view(accountId, record, now, account.recoveryGeneration);
    });
  }
  async completeRotation(accountId: string, auth: RecoveryAuth, idempotencyKey: string, challengeId: string, signature: string): Promise<Record<string, unknown>> {
    identifier(idempotencyKey); identifier(challengeId); bytes(signature, 64);
    return this.authorized(accountId, auth, (account, now, hash, current) => {
      const record = account.recoveryRotations?.[idempotencyKey];
      if (!record || record.sessionHash !== hash || record.id !== challengeId || record.generation !== account.generation) throw new Fault(403, "challenge_invalid");
      if (record.state === "complete") {
        if (record.signature !== signature) throw new Fault(409, "idempotency_conflict");
        return { ...view(accountId, record, now, account.recoveryGeneration), replayed: true };
      }
      if (record.expiresAt <= now || record.recoveryGeneration !== account.recoveryGeneration) throw new Fault(403, "challenge_invalid");
      if (fullEnvelopes(account, record.proposal.envelopes) !== record.envelopesHash) throw new Fault(409, "envelope_set_stale_or_incomplete");
      if (rotationTrustHash(account, record.proposal) !== record.trustRootHash) throw new Fault(409, "trust_root_stale");
      verify(record.proposal.newRecoverySigningPublicKey, canonical(rotationPayload(accountId, record)), signature);
      account.recoveryGeneration = record.proposal.newRecoveryGeneration;
      account.recoverySigningPublicKey = record.proposal.newRecoverySigningPublicKey;
      account.recoveryReceivingPublicKey = record.proposal.newRecoveryReceivingPublicKey;
      if (record.proposal.newTrustRoot) account.trustRoot = structuredClone(record.proposal.newTrustRoot);
      for (const e of record.proposal.envelopes) {
        const env = account.environments[e.environmentId]!;
        env.recoveryEnvelope = e.envelope; env.recoveryGeneration = account.recoveryGeneration; env.recoveryKeyVersion = env.keyVersion;
      }
      account.sessions = account.sessions.filter(s => s.kind !== "recovery" || s.tokenHash === hash);
      if (current.kind === "recovery") { current.recoveryGeneration = account.recoveryGeneration; current.rotationRequired = false; }
      record.state = "complete"; record.signature = signature; record.sequence = next(account);
      return { ...view(accountId, record, now, account.recoveryGeneration), replayed: false };
    });
  }
  async rotationStatus(accountId: string, auth: RecoveryAuth, idempotencyKey: string): Promise<Record<string, unknown>> {
    identifier(idempotencyKey);
    return this.authorized(accountId, auth, (account, now, hash) => {
      const record = account.recoveryRotations?.[idempotencyKey];
      if (!record) return { state: "absent", idempotencyKey };
      if (record.sessionHash !== hash) throw new Fault(403, "rotation_forbidden");
      return view(accountId, record, now, account.recoveryGeneration);
    });
  }
  async requireRecoveryManagement(accountId: string, auth: RecoveryAuth): Promise<void> {
    await this.authorized(accountId, auth, (_, __, ___, current) => {
      if (current.kind !== "recovery" || current.rotationRequired !== false) throw new Fault(403, "recovery_rotation_required");
      // Capability gate for future SPAKE2 management approval; never enrolls a device.
    });
  }
}
