import { Fault, type Account } from "./model.js";
import type { Sql } from "./store.js";
import { identifier } from "./protocol.js";
export interface RegistrationAdmission {
  id: string; mode: "open" | "initial"; state: "pending" | "proof-ready" | "complete";
  expiresAt: number; readyAt?: number;
}
export interface RegistrationState { firstCompleted: boolean; winnerAccountId: string | null; winnerAdmissionId: string | null }
export interface RegistrationAuthority {
  info(): Promise<RegistrationState>;
  complete(accountId: string, admissionId: string, mode: RegistrationAdmission["mode"]): Promise<{ accepted: boolean }>;
}
export function registrationComplete(a: Account): boolean { return a.registrationAdmission?.state === "complete"; }
export function registrationVerificationRequired(a: Account): boolean { return a.verificationRequiredAtRegistration === true; }
export function assertRegistration(a: Account): void {
  if (!registrationComplete(a)) throw new Fault(403, "registration_pending");
}
export function validateRegistration(a: Account): void {
  if (typeof a.verificationRequiredAtRegistration !== "boolean") throw new Fault(400, "registration_state_invalid");
  const v = a.registrationAdmission;
  if (!v || typeof v !== "object" || Array.isArray(v)) throw new Fault(400, "registration_state_invalid");
  identifier(v.id);
  if (!["open", "initial"].includes(v.mode) || !["pending", "proof-ready", "complete"].includes(v.state) || !Number.isSafeInteger(v.expiresAt) || v.expiresAt <= 0) throw new Fault(400, "registration_state_invalid");
  if (v.state !== "pending" && (!Number.isSafeInteger(v.readyAt) || v.readyAt! > v.expiresAt || registrationVerificationRequired(a) && !a.verified)) throw new Fault(400, "registration_state_invalid");
}
// 实例只保留不可逆首次完成决定；凭据、证明和激活进度仍只有账号 Store 一份。
export class SqlRegistrationAuthority implements RegistrationAuthority {
  constructor(private readonly sql: Sql) {
    sql.execute("CREATE TABLE IF NOT EXISTS instance_registration (singleton INTEGER PRIMARY KEY CHECK(singleton=1), completed INTEGER NOT NULL, account_id TEXT, admission_id TEXT)");
    sql.execute("INSERT INTO instance_registration(singleton,completed) VALUES(1,0) ON CONFLICT(singleton) DO NOTHING");
  }
  private current(): RegistrationState {
    const r = this.sql.rows("SELECT completed,account_id,admission_id FROM instance_registration WHERE singleton=1")[0]!;
    return { firstCompleted: r.completed === 1, winnerAccountId: r.account_id as string | null, winnerAdmissionId: r.admission_id as string | null };
  }
  async info(): Promise<RegistrationState> {
    return this.current();
  }
  async complete(accountId: string, admissionId: string, mode: RegistrationAdmission["mode"]): Promise<{ accepted: boolean }> {
    identifier(accountId); identifier(admissionId); if (mode !== "open" && mode !== "initial") throw new Fault(400, "registration_state_invalid");
    await this.info();
    return this.sql.transaction(() => {
      const state = this.current();
      if (!state.firstCompleted) this.sql.execute("UPDATE instance_registration SET completed=1,account_id=?,admission_id=? WHERE singleton=1 AND completed=0", [accountId, admissionId]);
      const final = this.current();
      return { accepted: mode === "open" || final.winnerAccountId === accountId && final.winnerAdmissionId === admissionId };
    });
  }
}
export async function instanceInfo(authority: RegistrationAuthority, policy: { allowRegistration: boolean; requireEmailVerification: boolean }): Promise<unknown> {
  const state = await authority.info();
  return { product: "harmonia", status: "experimental", protocol: { supportedMajors: [2], capabilities: ["registration-policy-v1", "email-proof-v1"] }, initialRegistrationAvailable: !state.firstCompleted, allowRegistration: policy.allowRegistration, emailVerificationRequired: policy.requireEmailVerification };
}
