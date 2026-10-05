import type { Account, Auth, Session } from "./model.js";
import { Fault } from "./model.js";
import { bytes, generation, identifier, verify } from "./protocol.js";
import type { Store } from "./store.js";
import { device, next, permission, randomToken, sameAccount, session, tokenHash } from "./service.js";
import { bootPayload, canonical, recoveryPayload, validateRecoveryState } from "./lifecycle-wire.js";
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
function sessionAdd(account: Account, value: Session, now: number): void {
  account.sessions = account.sessions.filter(s => s.expiresAt > now);
  if (account.sessions.length >= 64) account.sessions.shift();
  account.sessions.push(value);
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
}
