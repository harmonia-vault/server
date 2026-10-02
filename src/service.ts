import type { Account, Auth, Grant, Pull, SignedGrant, SignedMutation } from "./model.js";
import { Fault, grantKey } from "./model.js";
import { bytes, generation, grantBytes, identifier, mutationBytes, verify } from "./protocol.js";
import { DUMMY_VERIFIER, wasmPassword, type PasswordHasher } from "./password.js";
import type { Store } from "./store.js";
export interface Policy { allowRegistration: boolean; requireEmailVerification: boolean }
const sessionTTL = 3600;
const unix = (): number => Math.floor(Date.now() / 1000);
export function normalizeEmail(email: string): string {
  if (typeof email !== "string" || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Fault(400, "email_invalid");
  return email.toLowerCase();
}
function randomToken(): string { return Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url"); }
// SHA256 here only hashes random session tokens. Password derivation is performed by the client.
export async function tokenHash(token: string): Promise<string> {
  return Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token))).toString("hex");
}
function sameAccount(account: Account, generationValue: string): void {
  if (account.generation !== generationValue) throw new Fault(401, "generation_stale");
}
function session(account: Account, hash: string, now: number, restricted = false): import("./model.js").Session {
  const found = account.sessions.find(s => s.tokenHash === hash && s.generation === account.generation && s.expiresAt > now);
  if (!found || (!restricted && found.kind !== "login")) throw new Fault(401, "unauthorized");
  return found;
}
function device(account: Account, deviceId: string): void {
  const current = account.devices[deviceId];
  if (!current || current.revoked) throw new Fault(403, "device_untrusted");
}
function permission(account: Account, deviceId: string, environmentId: string, now: number): Grant {
  device(account, deviceId);
  const grant = account.grants[grantKey(environmentId, deviceId)]?.grant;
  if (!grant || grant.accountGeneration !== account.generation || grant.role === "none" ||
    (grant.expiresAt !== "0" && BigInt(grant.expiresAt) <= BigInt(now))) throw new Fault(403, "environment_forbidden");
  const env = account.environments[environmentId];
  if (!env || env.keyVersion !== grant.keyVersion) throw new Fault(403, "key_version_stale");
  return grant;
}
function next(account: Account): number {
  if (account.sequence >= Number.MAX_SAFE_INTEGER) throw new Fault(503, "sequence_exhausted");
  return ++account.sequence;
}
function idempotent(account: Account, key: string, content: string): { sequence: number; replayed: true } | undefined {
  const old = account.idempotency[key];
  if (!old) return;
  if (old.content !== content) throw new Fault(409, "idempotency_conflict");
  return { sequence: old.sequence, replayed: true };
}
export class VaultService {
  constructor(readonly store: Store, readonly policy: Policy, private readonly clock: () => number = unix, private readonly passwords: PasswordHasher = wasmPassword) {}
  async register(email: string, clientCredential: string): Promise<{ accountId: string; accountGeneration: string }> {
    if (!this.policy.allowRegistration) throw new Fault(403, "registration_disabled");
    // Email proof is not implemented: verification-required registration must not create usable accounts.
    if (this.policy.requireEmailVerification) throw new Fault(503, "email_verification_unavailable");
    const canonical = normalizeEmail(email);
    const passwordVerifier = await this.passwords.hash(clientCredential);
    const account: Account = { schema: 1, id: crypto.randomUUID(), email: canonical, generation: "1", verified: false,
      passwordVerifier, sequence: 0, devices: {}, environments: {}, grants: {}, sessions: [], deviceChallenges: [], events: [],
      idempotency: {}, recoveryGeneration: "1", recoverySigningPublicKey: null };
    this.store.create(account);
    return { accountId: account.id, accountGeneration: account.generation };
  }
  async login(email: string, clientCredential: string): Promise<{ accountId: string; accountGeneration: string; token: string; expiresAt: number }> {
    const accountId = this.store.byEmail(normalizeEmail(email));
    const snapshot = accountId ? this.store.read(accountId) : undefined;
    // Dummy Argon2 avoids a cheap unknown-account oracle without logging the credential.
    const verifier = snapshot?.passwordVerifier ?? DUMMY_VERIFIER;
    const valid = await this.passwords.verify(clientCredential, verifier);
    if (!snapshot || !accountId || !valid) throw new Fault(401, "unauthorized");
    const token = randomToken(); const hash = await tokenHash(token); const now = this.clock();
    const expiresAt = now + sessionTTL;
    this.store.transaction(accountId, account => {
      sameAccount(account, snapshot.generation);
      if (account.passwordVerifier !== snapshot.passwordVerifier || (this.policy.requireEmailVerification && !account.verified)) throw new Fault(401, "unauthorized");
      account.sessions = account.sessions.filter(s => s.expiresAt > now);
      if (account.sessions.length >= 64) account.sessions.shift();
      account.sessions.push({ tokenHash: hash, generation: account.generation, expiresAt, kind: "login" });
    });
    return { accountId, accountGeneration: snapshot.generation, token, expiresAt };
  }
  async deviceChallenge(accountId: string, auth: Auth): Promise<{ challengeId: string; nonce: string; expiresAt: number; signingPayload: string[] }> {
    identifier(accountId); identifier(auth.deviceId); generation(auth.accountGeneration); bytes(auth.token, 32);
    const hash = await tokenHash(auth.token);
    return this.store.transaction(accountId, account => {
      const now = this.clock(); sameAccount(account, auth.accountGeneration); session(account, hash, now); device(account, auth.deviceId);
      account.deviceChallenges = account.deviceChallenges.filter(c => c.expiresAt > now);
      if (account.deviceChallenges.length >= 32) throw new Fault(429, "challenge_capacity_reached");
      const c = { id: crypto.randomUUID(), deviceId: auth.deviceId, sessionHash: hash, nonce: randomToken(), expiresAt: now + 120, generation: account.generation };
      account.deviceChallenges.push(c);
      const signingPayload = ["harmonia/device-session/v1", account.id, account.generation, c.deviceId, c.sessionHash, c.id, c.nonce, String(c.expiresAt)];
      return { challengeId: c.id, nonce: c.nonce, expiresAt: c.expiresAt, signingPayload };
    });
  }
  async deviceSession(accountId: string, auth: Auth, challengeId: string, signature: string): Promise<{ token: string; expiresAt: number }> {
    identifier(accountId); identifier(auth.deviceId); identifier(challengeId); generation(auth.accountGeneration); bytes(auth.token, 32);
    const hash = await tokenHash(auth.token); const token = randomToken(); const scopedHash = await tokenHash(token);
    return this.store.transaction(accountId, account => {
      const now = this.clock(); sameAccount(account, auth.accountGeneration); const login = session(account, hash, now); device(account, auth.deviceId);
      const c = account.deviceChallenges.find(c => c.id === challengeId);
      if (!c || c.sessionHash !== hash || c.deviceId !== auth.deviceId || c.generation !== account.generation || c.expiresAt <= now) throw new Fault(403, "challenge_invalid");
      const message = new TextEncoder().encode(JSON.stringify(["harmonia/device-session/v1", account.id, account.generation, c.deviceId, c.sessionHash, c.id, c.nonce, String(c.expiresAt)]));
      verify(account.devices[auth.deviceId]!.signingPublicKey, message, signature);
      account.deviceChallenges = account.deviceChallenges.filter(other => other.id !== c.id);
      account.sessions = account.sessions.filter(s => s.expiresAt > now);
      if (account.sessions.length >= 64) account.sessions.shift();
      const expiresAt = Math.min(now + sessionTTL, login.expiresAt);
      account.sessions.push({ tokenHash: scopedHash, generation: account.generation, expiresAt, kind: "login", deviceId: auth.deviceId });
      return { token, expiresAt };
    });
  }
  private async authenticated<T>(accountId: string, auth: Auth, operation: (a: Account, now: number) => T): Promise<T> {
    identifier(accountId); identifier(auth.deviceId); generation(auth.accountGeneration);
    bytes(auth.token, 32); const hash = await tokenHash(auth.token);
    return this.store.transaction(accountId, account => {
      const now = this.clock(); sameAccount(account, auth.accountGeneration);
      const currentSession = session(account, hash, now); device(account, auth.deviceId);
      if (currentSession.deviceId !== auth.deviceId) throw new Fault(403, "device_proof_required");
      return operation(account, now);
    });
  }
  async mutate(accountId: string, auth: Auth, signed: SignedMutation): Promise<{ sequence: number; replayed: boolean }> {
    const encoded = mutationBytes(signed.mutation);
    return this.authenticated(accountId, auth, (account, now) => {
      const m = signed.mutation;
      if (m.accountId !== accountId || m.deviceId !== auth.deviceId || m.accountGeneration !== account.generation) throw new Fault(403, "binding_invalid");
      const grant = permission(account, auth.deviceId, m.environmentId, now);
      if (grant.role !== "rw" && grant.role !== "admin") throw new Fault(403, "write_forbidden");
      if (m.grantGeneration !== grant.grantGeneration || m.keyVersion !== grant.keyVersion) throw new Fault(403, "grant_stale");
      verify(account.devices[auth.deviceId]!.signingPublicKey, encoded, signed.signature);
      const content = Buffer.from(encoded).toString("base64url") + "." + signed.signature;
      const key = `mutation/${m.deviceId}/${m.idempotencyKey}`;
      const prior = idempotent(account, key, content); if (prior) return prior;
      if (account.events.length >= 10000) throw new Fault(503, "account_capacity_reached");
      const sequence = next(account);
      account.events.push({ sequence, mutation: structuredClone(signed), authorization: structuredClone(account.grants[grantKey(m.environmentId, m.deviceId)]!) });
      account.idempotency[key] = { content, sequence };
      return { sequence, replayed: false };
    });
  }
  async changeGrant(accountId: string, auth: Auth, signed: SignedGrant): Promise<{ sequence: number; replayed: boolean }> {
    const encoded = grantBytes(signed.grant);
    return this.authenticated(accountId, auth, (account, now) => {
      const g = signed.grant;
      if (g.accountId !== accountId || g.accountGeneration !== account.generation || g.issuerDeviceId !== auth.deviceId) throw new Fault(403, "binding_invalid");
      const authority = permission(account, auth.deviceId, g.environmentId, now);
      if (authority.role !== "admin") throw new Fault(403, "admin_required");
      const subject = account.devices[g.subjectDeviceId];
      // First-device establishment and pairing require a separate verified ceremony; no public bootstrap bypass.
      if (!subject || subject.revoked) throw new Fault(403, "pairing_required");
      if (subject.signingPublicKey !== g.subjectSigningPublicKey || subject.receivingPublicKey !== g.subjectReceivingPublicKey) throw new Fault(403, "device_key_mismatch");
      if (authority.keyVersion !== g.keyVersion) throw new Fault(403, "key_version_stale");
      if (g.expiresAt !== "0" && BigInt(g.expiresAt) <= BigInt(now)) throw new Fault(400, "grant_already_expired");
      // A temporary Admin must not delegate privileges beyond its own lifetime.
      if (authority.expiresAt !== "0" && (g.expiresAt === "0" || BigInt(g.expiresAt) > BigInt(authority.expiresAt))) throw new Fault(403, "expiry_escalation");
      verify(account.devices[auth.deviceId]!.signingPublicKey, encoded, signed.signature);
      const key = `grant/${g.issuerDeviceId}/${g.idempotencyKey}`;
      const content = Buffer.from(encoded).toString("base64url") + "." + signed.signature;
      const prior = idempotent(account, key, content); if (prior) return prior;
      const current = account.grants[grantKey(g.environmentId, g.subjectDeviceId)]?.grant.grantGeneration ?? "0";
      if (BigInt(g.grantGeneration) !== BigInt(current) + 1n) throw new Fault(409, "grant_generation_conflict");
      const sequence = next(account);
      account.grants[grantKey(g.environmentId, g.subjectDeviceId)] = structuredClone(signed);
      account.idempotency[key] = { content, sequence };
      return { sequence, replayed: false };
    });
  }
  async pull(accountId: string, auth: Auth, after: number): Promise<Pull> {
    if (!Number.isSafeInteger(after) || after < 0) throw new Fault(400, "checkpoint_invalid");
    return this.authenticated(accountId, auth, (account, now) => {
      if (after > account.sequence) throw new Fault(409, "checkpoint_ahead");
      const grants: SignedGrant[] = [];
      const readable = new Set<string>();
      for (const signed of Object.values(account.grants)) {
        const g = signed.grant;
        if (g.subjectDeviceId !== auth.deviceId) continue;
        // Return current signed revocations and expiries too so cached material can be removed.
        grants.push(signed);
        try { permission(account, auth.deviceId, g.environmentId, now); readable.add(g.environmentId); } catch { /* revoked/expired grants carry no ciphertext */ }
      }
      return structuredClone({ accountId, accountGeneration: account.generation, sequence: account.sequence, grants,
        events: account.events.filter(e => e.sequence > after && readable.has(e.mutation.mutation.environmentId) && e.mutation.mutation.keyVersion === account.environments[e.mutation.mutation.environmentId]?.keyVersion) });
    });
  }
}
