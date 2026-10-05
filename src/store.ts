import { validateRecoveryOperationClosures } from "./recovery-operation-guards.js";
import type { Account } from "./model.js";
import { Fault } from "./model.js";
import { SqlRegistrationAuthority, validateRegistration, registrationVerificationRequired, type RegistrationAuthority } from "./registration.js";
import { validateRecoveryState } from "./lifecycle-wire.js";
import { SqlEmailRateLimit, type EmailRateLimit } from "./email-rate-limit.js";
export interface Store {
  readonly emailRateLimit: EmailRateLimit;
  readonly registrationAuthority: RegistrationAuthority;
  create(account: Account): void;
  byEmail(email: string): string | undefined;
  read(accountId: string): Account | undefined;
  transaction<T>(accountId: string, operation: (account: Account) => T): T;
  onCommit?(listener: (accountId: string) => void): () => void;
}
export interface Sql {
  execute(query: string, params?: (string | number | null)[]): void;
  rows(query: string, params?: (string | number | null)[]): Record<string, unknown>[];
  transaction<T>(operation: () => T): T;
}
// A single versioned account row keeps credentials, permissions and events in one atomic domain.
// M1 uses a bounded account document; a normalized event table is a later scaling step.
export class SqlStore implements Store {
  readonly emailRateLimit: EmailRateLimit;
  readonly registrationAuthority: RegistrationAuthority;
  private readonly listeners = new Set<(accountId: string) => void>();
  onCommit(listener: (accountId: string) => void): () => void { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; }
  private document(account: Account): string {
    validateAccountSchema(account);
    validateRecoveryOperationClosures(account);
    validateRegistration(account);
    validateRecoveryState(account);
    const data = JSON.stringify(account);
    if (Buffer.byteLength(data) > 1_000_000) throw new Fault(503, "account_capacity_reached");
    return data;
  }
  constructor(private readonly sql: Sql, authority?: RegistrationAuthority, emailRateLimit?: EmailRateLimit) {
    sql.execute("CREATE TABLE IF NOT EXISTS accounts (id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, data TEXT NOT NULL)");
    this.registrationAuthority = authority ?? new SqlRegistrationAuthority(sql);
    this.emailRateLimit = emailRateLimit ?? new SqlEmailRateLimit(sql);
  }
  create(account: Account): void {
    this.sql.transaction(() => {
      if (this.byEmail(account.email) || this.read(account.id)) throw new Fault(409, "account_exists");
      this.sql.execute("INSERT INTO accounts(id,email,data) VALUES(?,?,?)", [account.id, account.email, this.document(account)]);
    });
  }
  byEmail(email: string): string | undefined {
    return this.sql.rows("SELECT id FROM accounts WHERE email=?", [email])[0]?.id as string | undefined;
  }
  read(accountId: string): Account | undefined {
    const row = this.sql.rows("SELECT data FROM accounts WHERE id=?", [accountId])[0];
    if (!row) return undefined;
    const account = JSON.parse(String(row.data)) as Account;
    validateAccountSchema(account);
    validateRecoveryOperationClosures(account);
    validateRegistration(account);
    return account;
  }
  transaction<T>(accountId: string, operation: (account: Account) => T): T {
    let changed = false;
    const result = this.sql.transaction(() => {
      const account = this.read(accountId);
      if (!account) throw new Fault(401, "unauthorized");
      const required = registrationVerificationRequired(account), before = JSON.stringify(account), result = operation(account), after = this.document(account);
      if (required !== registrationVerificationRequired(account)) throw new Fault(409, "registration_policy_immutable");
      this.sql.execute("UPDATE accounts SET data=? WHERE id=?", [after, accountId]);
      changed = before !== after;
      return result;
    });
    // 通知失败不能把已提交事务伪装为失败；观察者只在真正 COMMIT 后运行。
    if (changed) for (const listener of this.listeners) { try { listener(accountId); } catch { /* 下次拉取仍可补漏 */ } }
    return result;
  }
}

function validateAccountSchema(account: Account): void {
  if (account.schema !== 2 || ["pairingSessions", "deviceEnrollments", "recoveryRotations", "recoveryAuthorityTransitions", "recoveryAuthorityChallenges", "recoveredDeviceChallenges", "recoveredDevices"].some(key => Object.hasOwn(account, key))) throw new Fault(409, "account_format_unsupported");
}
