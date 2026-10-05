import type { Account } from "./model.js";
import { Fault } from "./model.js";
import { assertRegistration, registrationComplete, registrationVerificationRequired } from "./registration.js";
import { bytes, generation, identifier } from "./protocol.js";
import type { Store } from "./store.js";
import type { PasswordHasher } from "./password.js";
import { credential } from "./password.js";
import type { EmailTransport } from "./email-transport.js";
import { codeEmail } from "./email-templates.js";
import { reserveEmailSend } from "./email-rate-limit.js";
import { emailCodeAttempts, emailCodeLifetime, emailCodeToken, normalizeEmailCode, randomEmailCode, type EmailCodeState } from "./email-code.js";
import { normalizeEmail, randomToken, sameAccount, tokenHash, type Policy } from "./service.js";
export interface EmailProof { id: string; purpose: "verification" | "reset"; generation: string; tokenHash: string; verifierHash: string; expiresAt: number; code: EmailCodeState }
export interface ResetReceipt { id: string; oldGeneration: string; generation: string; tokenHash: string; contentHash: string; expiresAt: number; code: EmailCodeState }
export interface VerificationInput { accountGeneration: string; code: string }
export interface ProofInput { accountGeneration: string; challengeId: string; token: string }
export interface ResetInput extends ProofInput { newCredential: string; confirmation: "DELETE_OLD_VAULT" }
export function emptyAccount(id: string, email: string, accountGeneration: string, passwordVerifier: string, registration: Pick<Account, "verificationRequiredAtRegistration" | "registrationAdmission">, verified = false): Account {
  return { schema: 2, id, email, generation: accountGeneration, verified, passwordVerifier, verificationRequiredAtRegistration: registration.verificationRequiredAtRegistration, registrationAdmission: structuredClone(registration.registrationAdmission), sequence: 0, devices: {}, environments: {}, grants: {},
    sessions: [], deviceChallenges: [], events: [], idempotency: {}, recoveryGeneration: "1", recoverySigningPublicKey: null, recoveryReceivingPublicKey: null };
}
const accepted = (): { accepted: true } => ({ accepted: true });
export class AccountLifecycle {
  constructor(readonly store: Store, private readonly passwords: PasswordHasher, private readonly clock: () => number = () => Math.floor(Date.now() / 1000), readonly mail?: EmailTransport) {}
  requireMail(): EmailTransport { if (!this.mail) throw new Fault(503, "email_verification_unavailable"); return this.mail; }
  async register(email: string, value: string, policy: Policy, reservedAccountId?: string, clientIP?: string): Promise<{ accountId: string; accountGeneration: string; verificationRequired: boolean }> {
    const open = policy.allowRegistration, configuredVerification = policy.requireEmailVerification;
    const state = await this.store.registrationAuthority.info();
    if (!open && state.firstCompleted) throw new Fault(403, "registration_disabled");
    if (configuredVerification) this.requireMail();
    const address = normalizeEmail(email), oldId = this.store.byEmail(address), old = oldId ? this.store.read(oldId) : undefined;
    if (old && (registrationComplete(old) || old.registrationAdmission!.state === "proof-ready" || old.registrationAdmission!.expiresAt > this.clock() || Object.keys(old.devices).length || Object.keys(old.environments).length || old.sequence)) throw new Fault(409, "account_exists");
    const required = old ? registrationVerificationRequired(old) : configuredVerification;
    if (required) this.requireMail();
    const id = oldId ?? reservedAccountId ?? crypto.randomUUID(); identifier(id);
    credential(value);
    if (required) await reserveEmailSend(this.store.emailRateLimit, address, clientIP, this.clock());
    const passwordVerifier = await this.passwords.hash(value), now = this.clock();
    const build = (generation: string): Account => {
      return emptyAccount(id, address, generation, passwordVerifier, {
        verificationRequiredAtRegistration: required,
        registrationAdmission: { id: crypto.randomUUID(), mode: open ? "open" : "initial", state: required ? "pending" : "proof-ready", expiresAt: now + 900, ...(required ? {} : { readyAt: now }) },
      });
    };
    let accountGeneration: string;
    if (old) {
      accountGeneration = this.store.transaction(id, a => {
        if (a.generation !== old.generation || a.passwordVerifier !== old.passwordVerifier || registrationComplete(a) || a.registrationAdmission?.state !== "pending" || a.registrationAdmission.expiresAt > now || Object.keys(a.devices).length || Object.keys(a.environments).length || a.sequence) throw new Fault(409, "account_changed");
        if (BigInt(a.generation) >= 18446744073709551615n) throw new Fault(503, "generation_exhausted");
        const generation = String(BigInt(a.generation) + 1n), replacement = build(generation);
        for (const key of Object.keys(a)) delete (a as unknown as Record<string, unknown>)[key]; Object.assign(a, replacement); return generation;
      });
    } else { accountGeneration = "1"; this.store.create(build(accountGeneration)); }
    if (required) await this.sendProof(address, "verification"); else await this.resumeRegistration(id);
    return { accountId: id, accountGeneration, verificationRequired: required };
  }
  // 只能由服务器已持久的证明成功状态补全；login调用者须先核验正确密码。
  async resumeRegistration(accountId: string, expected?: { generation: string; passwordVerifier: string }, reopenedLogin = false): Promise<void> {
    const snapshot = this.store.read(accountId), admission = snapshot?.registrationAdmission;
    if (!snapshot || !admission || admission.state !== "proof-ready") return;
    if (expected && (snapshot.generation !== expected.generation || snapshot.passwordVerifier !== expected.passwordVerifier)) throw new Fault(409, "account_changed");
    if (reopenedLogin && !expected) throw new Fault(401, "unauthorized");
    const decision = await this.store.registrationAuthority.complete(accountId, admission.id, reopenedLogin ? "open" : admission.mode);
    if (!decision.accepted) throw new Fault(403, "registration_disabled");
    this.store.transaction(accountId, a => {
      if (a.generation !== snapshot.generation || a.passwordVerifier !== snapshot.passwordVerifier || a.registrationAdmission?.id !== admission.id || a.registrationAdmission.state === "pending") throw new Fault(409, "account_changed");
      a.registrationAdmission.state = "complete";
      if (a.emailProofs) a.emailProofs = a.emailProofs.filter(proof => proof.purpose !== "verification");
    });
  }
  async requestProof(email: string, purpose: "verification" | "reset", clientIP?: string): Promise<{ accepted: true }> {
    this.requireMail();
    const address = normalizeEmail(email);
    await reserveEmailSend(this.store.emailRateLimit, address, clientIP, this.clock());
    return this.sendProof(address, purpose);
  }
  private async sendProof(email: string, purpose: "verification" | "reset"): Promise<{ accepted: true }> {
    const mail = this.requireMail(), address = normalizeEmail(email), accountId = this.store.byEmail(address);
    if (!accountId) return accepted();
    const snapshot = this.store.read(accountId)!;
    if (purpose === "reset") assertRegistration(snapshot);
    if (purpose === "verification" && snapshot.verified) return accepted();
    const code = randomEmailCode(), salt = randomToken(), token = await emailCodeToken(salt, code), hash = await tokenHash(token), verifierHash = await tokenHash(snapshot.passwordVerifier), id = crypto.randomUUID();
    const expiresAt = this.store.transaction(accountId, account => {
      sameAccount(account, snapshot.generation);
      if (account.passwordVerifier !== snapshot.passwordVerifier) throw new Fault(409, "account_changed");
      const now = this.clock(), admission = account.registrationAdmission;
      const deadline = purpose === "verification" && admission?.state === "pending"
        ? Math.min(now + emailCodeLifetime, admission.expiresAt) : now + emailCodeLifetime;
      if (deadline <= now) throw new Fault(401, "registration_expired");
      account.emailProofs = (account.emailProofs ?? []).filter(p => p.expiresAt > now);
      account.emailProofs = account.emailProofs.filter(p => p.purpose !== purpose);
      account.emailProofs.push({ id, purpose, generation: account.generation, tokenHash: hash, verifierHash, expiresAt: deadline,
        code: { salt, failedAttempts: 0, expiresAt: deadline } });
      return deadline;
    });
    const message = codeEmail({ purpose, email: address, code, minutes: Math.max(1, Math.floor((expiresAt - this.clock()) / 60)) });
    try { await mail.send({ to: address, ...message }); }
    catch {
      this.store.transaction(accountId, account => { account.emailProofs = (account.emailProofs ?? []).filter(p => p.id !== id); });
      throw new Fault(503, "email_delivery_failed");
    }
    return accepted();
  }
  async resolveCode(email: string, code: string): Promise<ProofInput & { accountId: string }> {
    const accountId = this.store.byEmail(normalizeEmail(email));
    if (!accountId) throw new Fault(401, "email_code_invalid");
    return this.resolveAccountCode(accountId, code, "reset");
  }
  private async resolveAccountCode(accountId: string, code: string, purpose: EmailProof["purpose"], expectedGeneration?: string): Promise<ProofInput & { accountId: string }> {
    identifier(accountId);
    const normalized = normalizeEmailCode(code);
    if (!normalized) throw new Fault(400, "email_code_invalid");
    const snapshot = this.store.read(accountId);
    if (!snapshot) throw new Fault(401, "email_code_invalid");
    if (expectedGeneration !== undefined) { generation(expectedGeneration); sameAccount(snapshot, expectedGeneration); }
    const source = snapshot.emailProofs?.find(p => p.purpose === purpose) ?? (purpose === "reset" ? snapshot.resetReceipt : undefined);
    if (!source?.code) throw new Fault(401, "email_code_invalid");
    const token = await emailCodeToken(source.code.salt, normalized), hash = await tokenHash(token), verifierHash = await tokenHash(snapshot.passwordVerifier);
    const result = this.store.transaction(accountId, account => {
      sameAccount(account, snapshot.generation);
      if (account.passwordVerifier !== snapshot.passwordVerifier) throw new Fault(409, "account_changed");
      const proof = account.emailProofs?.find(p => p.purpose === purpose);
      const current = proof ?? (purpose === "reset" ? account.resetReceipt : undefined);
      if (!current?.code || current.id !== source.id) return new Fault(401, "email_code_invalid");
      if (purpose === "reset") assertRegistration(account);
      if (purpose === "verification" && account.registrationAdmission?.state === "pending" && account.registrationAdmission.expiresAt <= this.clock()) return new Fault(401, "registration_expired");
      if (proof && (proof.generation !== account.generation || proof.verifierHash !== verifierHash)) return new Fault(401, "email_code_invalid");
      if (current.code.expiresAt <= this.clock() || current.expiresAt <= this.clock()) return new Fault(401, "email_code_expired");
      if (current.code.failedAttempts >= emailCodeAttempts) return new Fault(429, "email_code_attempts_exhausted");
      if (current.tokenHash !== hash) {
        current.code.failedAttempts++;
        return new Fault(current.code.failedAttempts === emailCodeAttempts ? 429 : 401,
          current.code.failedAttempts === emailCodeAttempts ? "email_code_attempts_exhausted" : "email_code_invalid");
      }
      return { accountId, accountGeneration: proof ? proof.generation : account.resetReceipt!.oldGeneration, challengeId: current.id, token };
    });
    // Throw only after commit: failed guesses must survive transaction rollback/restart.
    if (result instanceof Fault) throw result;
    return result;
  }
  private async proof(accountId: string, input: ProofInput): Promise<{ hash: string; verifierHash: string; snapshot: Account }> {
    identifier(accountId); identifier(input.challengeId); generation(input.accountGeneration); bytes(input.token, 32);
    const hash = await tokenHash(input.token), snapshot = this.store.read(accountId);
    if (!snapshot) throw new Fault(401, "email_proof_invalid");
    sameAccount(snapshot, input.accountGeneration);
    return { hash, snapshot, verifierHash: await tokenHash(snapshot.passwordVerifier) };
  }
  private currentProof(account: Account, input: ProofInput, hash: string, verifierHash: string, purpose: EmailProof["purpose"]): EmailProof {
    sameAccount(account, input.accountGeneration);
    if (purpose === "reset") assertRegistration(account);
    const p = account.emailProofs?.find(p => p.id === input.challengeId && p.purpose === purpose && p.tokenHash === hash);
    if (!p?.code || p.generation !== account.generation || p.verifierHash !== verifierHash || p.expiresAt <= this.clock()) throw new Fault(401, "email_proof_invalid");
    return p;
  }
  async verifyEmail(accountId: string, verification: VerificationInput): Promise<{ verified: true }> {
    const input = await this.resolveAccountCode(accountId, verification.code, "verification", verification.accountGeneration);
    const { hash, verifierHash, snapshot } = await this.proof(accountId, input);
    this.store.transaction(accountId, account => {
      if (account.passwordVerifier !== snapshot.passwordVerifier) throw new Fault(409, "account_changed");
      const admission = account.registrationAdmission;
      if (admission?.state === "pending" && admission.expiresAt <= this.clock()) throw new Fault(401, "registration_expired");
      this.currentProof(account, input, hash, verifierHash, "verification");
      account.verified = true;
      if (registrationComplete(account)) account.emailProofs = account.emailProofs!.filter(p => p.purpose !== "verification");
      if (admission?.state === "pending") {
        admission.state = "proof-ready";
        admission.readyAt = this.clock();
      }
    });
    await this.resumeRegistration(accountId);
    return { verified: true };
  }
  private receipt(account: Account, input: ProofInput, hash: string): ResetReceipt | undefined {
    const r = account.resetReceipt;
    return r && r.id === input.challengeId && r.oldGeneration === input.accountGeneration && r.tokenHash === hash && r.generation === account.generation && r.expiresAt > this.clock() ? r : undefined;
  }
  async resetStatus(accountId: string, input: ProofInput): Promise<{ state: "pending" | "complete"; accountId: string; accountGeneration: string }> {
    identifier(accountId); identifier(input.challengeId); generation(input.accountGeneration); bytes(input.token, 32);
    const hash = await tokenHash(input.token), snapshot = this.store.read(accountId); if (!snapshot) throw new Fault(401, "email_proof_invalid");
    const verifierHash = await tokenHash(snapshot.passwordVerifier);
    return this.store.transaction(accountId, account => {
      if (account.passwordVerifier !== snapshot.passwordVerifier) throw new Fault(409, "account_changed");
      const r = this.receipt(account, input, hash); if (r) return { state: "complete", accountId, accountGeneration: account.generation };
      this.currentProof(account, input, hash, verifierHash, "reset");
      return { state: "pending", accountId, accountGeneration: account.generation };
    });
  }
  async reset(accountId: string, input: ResetInput): Promise<{ accountId: string; accountGeneration: string; replayed: boolean }> {
    identifier(accountId); identifier(input.challengeId); generation(input.accountGeneration); bytes(input.token, 32); credential(input.newCredential);
    if (input.confirmation !== "DELETE_OLD_VAULT") throw new Fault(400, "destructive_confirmation_required");
    const hash = await tokenHash(input.token), contentHash = await tokenHash(JSON.stringify(["harmonia/reset-commit/v1", accountId, input.accountGeneration, input.challengeId, hash, input.newCredential, input.confirmation]));
    const snapshot = this.store.read(accountId); if (!snapshot) throw new Fault(401, "email_proof_invalid");
    assertRegistration(snapshot);
    const prior = this.receipt(snapshot, input, hash);
    if (prior) { if (prior.contentHash !== contentHash) throw new Fault(409, "idempotency_conflict"); return { accountId, accountGeneration: snapshot.generation, replayed: true }; }
    const verifierHash = await tokenHash(snapshot.passwordVerifier);
    this.currentProof(snapshot, input, hash, verifierHash, "reset");
    // Expensive derivation must not hold SQLite/DO transaction; commit rechecks every old authority value.
    const passwordVerifier = await this.passwords.hash(input.newCredential);
    return this.store.transaction(accountId, account => {
      const existing = this.receipt(account, input, hash);
      if (existing) { if (existing.contentHash !== contentHash) throw new Fault(409, "idempotency_conflict"); return { accountId, accountGeneration: account.generation, replayed: true }; }
      sameAccount(account, snapshot.generation);
      if (account.passwordVerifier !== snapshot.passwordVerifier) throw new Fault(409, "account_changed");
      const proof = this.currentProof(account, input, hash, verifierHash, "reset");
      if (BigInt(account.generation) >= 18446744073709551615n) throw new Fault(503, "generation_exhausted");
      assertRegistration(account);
      const newGeneration = String(BigInt(account.generation) + 1n), replacement = emptyAccount(account.id, account.email, newGeneration, passwordVerifier, account, true);
      replacement.resetReceipt = { id: input.challengeId, oldGeneration: snapshot.generation, generation: newGeneration, tokenHash: hash, contentHash, expiresAt: this.clock() + 900, code: structuredClone(proof.code) };
      // Remove even future extension fields: old init/enrollment/recovery nonces cannot survive a reset.
      for (const key of Object.keys(account)) delete (account as unknown as Record<string, unknown>)[key];
      Object.assign(account, replacement);
      return { accountId, accountGeneration: newGeneration, replayed: false };
    });
  }
}
