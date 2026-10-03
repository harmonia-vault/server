import type { Account } from "./model.js";
import { Fault } from "./model.js";
import { assertRegistration, registrationComplete, registrationVerificationRequired } from "./registration.js";
import { bytes, generation, identifier } from "./protocol.js";
import type { Store } from "./store.js";
import type { PasswordHasher } from "./password.js";
import { credential } from "./password.js";
import type { EmailTransport } from "./email-transport.js";
import { normalizeEmail, randomToken, sameAccount, tokenHash, type Policy } from "./service.js";
export interface EmailProof { id: string; purpose: "verification" | "reset"; generation: string; tokenHash: string; verifierHash: string; expiresAt: number }
export interface ResetReceipt { id: string; oldGeneration: string; generation: string; tokenHash: string; contentHash: string; expiresAt: number }
export interface ProofInput { accountGeneration: string; challengeId: string; token: string }
export interface ResetInput extends ProofInput { newCredential: string; confirmation: "DELETE_OLD_VAULT" }
export function emptyAccount(id: string, email: string, accountGeneration: string, passwordVerifier: string, verified = false): Account {
  return { schema: 1, id, email, generation: accountGeneration, verified, passwordVerifier, sequence: 0, devices: {}, environments: {}, grants: {},
    sessions: [], deviceChallenges: [], events: [], idempotency: {}, recoveryGeneration: "1", recoverySigningPublicKey: null, recoveryReceivingPublicKey: null };
}
const accepted = (): { accepted: true } => ({ accepted: true });
export class AccountLifecycle {
  constructor(readonly store: Store, private readonly passwords: PasswordHasher, private readonly clock: () => number = () => Math.floor(Date.now() / 1000), readonly mail?: EmailTransport) {}
  requireMail(): EmailTransport { if (!this.mail) throw new Fault(503, "email_verification_unavailable"); return this.mail; }
  async register(email: string, value: string, policy: Policy, reservedAccountId?: string): Promise<{ accountId: string; accountGeneration: string; verificationRequired: boolean }> {
    const open = policy.allowRegistration, configuredVerification = policy.requireEmailVerification;
    const state = await this.store.registrationAuthority.info();
    if (!open && state.firstCompleted) throw new Fault(403, "registration_disabled");
    if (configuredVerification) this.requireMail();
    const address = normalizeEmail(email), oldId = this.store.byEmail(address), old = oldId ? this.store.read(oldId) : undefined;
    if (old && (registrationComplete(old) || old.registrationAdmission!.state === "proof-ready" || old.registrationAdmission!.expiresAt > this.clock() || Object.keys(old.devices).length || Object.keys(old.environments).length || old.sequence)) throw new Fault(409, "account_exists");
    const required = old ? registrationVerificationRequired(old) : configuredVerification;
    if (required) this.requireMail();
    const id = oldId ?? reservedAccountId ?? crypto.randomUUID(); identifier(id);
    const passwordVerifier = await this.passwords.hash(value), now = this.clock();
    const build = (generation: string): Account => {
      const a = emptyAccount(id, address, generation, passwordVerifier);
      a.verificationRequiredAtRegistration = required;
      a.registrationAdmission = { id: crypto.randomUUID(), mode: open ? "open" : "initial", state: required ? "pending" : "proof-ready", expiresAt: now + 900, ...(required ? {} : { readyAt: now }) };
      return a;
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
    if (required) await this.requestProof(address, "verification"); else await this.resumeRegistration(id);
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
    });
  }
  async requestProof(email: string, purpose: "verification" | "reset"): Promise<{ accepted: true }> {
    const mail = this.requireMail(), address = normalizeEmail(email), accountId = this.store.byEmail(address);
    if (!accountId) return accepted();
    const snapshot = this.store.read(accountId)!;
    if (purpose === "reset") assertRegistration(snapshot);
    if (purpose === "verification" && snapshot.verified) return accepted();
    const token = randomToken(), hash = await tokenHash(token), verifierHash = await tokenHash(snapshot.passwordVerifier), now = this.clock(), id = crypto.randomUUID();
    this.store.transaction(accountId, account => {
      sameAccount(account, snapshot.generation);
      if (account.passwordVerifier !== snapshot.passwordVerifier) throw new Fault(409, "account_changed");
      account.emailProofs = (account.emailProofs ?? []).filter(p => p.expiresAt > now);
      const last = account.emailProofs.filter(p => p.purpose === purpose).reduce((maximum, p) => Math.max(maximum, p.expiresAt - 900), 0);
      if (last + 60 > now) throw new Fault(429, "email_request_limited");
      if (account.emailProofs.length >= 8) throw new Fault(429, "email_proof_capacity_reached");
      account.emailProofs.push({ id, purpose, generation: account.generation, tokenHash: hash, verifierHash, expiresAt: now + 900 });
    });
    const payload = JSON.stringify({ accountId, accountGeneration: snapshot.generation, challengeId: id, token });
    const text = purpose === "reset" ? `您请求了 Harmonia 账号重置。此操作会永久删除旧 vault、设备授权和恢复状态，不会恢复旧数据。请仅在您主动发起的客户端输入下列证明，再明确确认删除旧 vault。证明十五分钟内单次有效。\n${payload}\n如果不是您发起，请忽略此邮件。` : `您请求了 Harmonia 邮箱验证。请仅在您主动发起的客户端输入下列证明。证明十五分钟内单次有效。\n${payload}\n如果不是您发起，请忽略此邮件。`;
    try { await mail.send({ to: address, subject: purpose === "reset" ? "Harmonia 账号重置证明" : "Harmonia 邮箱验证", text }); }
    catch {
      this.store.transaction(accountId, account => { account.emailProofs = (account.emailProofs ?? []).filter(p => p.id !== id); });
      throw new Fault(503, "email_delivery_failed");
    }
    return accepted();
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
    if (!p || p.generation !== account.generation || p.verifierHash !== verifierHash || p.expiresAt <= this.clock()) throw new Fault(401, "email_proof_invalid");
    return p;
  }
  async verifyEmail(accountId: string, input: ProofInput): Promise<{ verified: true }> {
    const { hash, verifierHash, snapshot } = await this.proof(accountId, input);
    this.store.transaction(accountId, account => {
      if (account.passwordVerifier !== snapshot.passwordVerifier) throw new Fault(409, "account_changed");
      const a = account.registrationAdmission, replay = a?.state === "proof-ready" && a.proofReceipt?.challengeId === input.challengeId && a.proofReceipt.tokenHash === hash && a.proofReceipt.generation === input.accountGeneration;
      if (!replay) {
        this.currentProof(account, input, hash, verifierHash, "verification");
        if (a?.state === "pending" && a.expiresAt <= this.clock()) throw new Fault(401, "email_proof_invalid");
        account.verified = true; account.emailProofs = account.emailProofs!.filter(p => p.purpose !== "verification");
        if (a?.state === "pending") { a.state = "proof-ready"; a.readyAt = this.clock(); a.proofReceipt = { challengeId: input.challengeId, tokenHash: hash, generation: account.generation }; }
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
      this.currentProof(account, input, hash, verifierHash, "reset");
      if (BigInt(account.generation) >= 18446744073709551615n) throw new Fault(503, "generation_exhausted");
      assertRegistration(account);
      const newGeneration = String(BigInt(account.generation) + 1n), replacement = emptyAccount(account.id, account.email, newGeneration, passwordVerifier, true);
      replacement.verificationRequiredAtRegistration = registrationVerificationRequired(account);
      if (account.registrationAdmission) { replacement.registrationAdmission = structuredClone(account.registrationAdmission); delete replacement.registrationAdmission.proofReceipt; }
      replacement.resetReceipt = { id: input.challengeId, oldGeneration: snapshot.generation, generation: newGeneration, tokenHash: hash, contentHash, expiresAt: this.clock() + 900 };
      // Remove even future extension fields: old init/enrollment/recovery nonces cannot survive a reset.
      for (const key of Object.keys(account)) delete (account as unknown as Record<string, unknown>)[key];
      Object.assign(account, replacement);
      return { accountId, accountGeneration: newGeneration, replayed: false };
    });
  }
}
