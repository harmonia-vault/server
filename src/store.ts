import { validateRecoveryOperationClosures } from "./recovery-operation-guards.js";
import type { Account } from "./model.js";
import { Fault } from "./model.js";
import { SqlRegistrationAuthority, validateRegistration, registrationVerificationRequired, type RegistrationAuthority } from "./registration.js";
import { validateRecoveryState } from "./lifecycle-wire.js";
import { SqlEmailRateLimit, type EmailRateLimit } from "./email-rate-limit.js";
import { TemporaryStore, unixTime } from './temporary-store.js';
import { splitAccount, joinAccount } from './account-temporary.js';
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
// 正式账号和临时权限状态共用事务；未验证申请只进入 TTL 存储。
export class SqlStore implements Store {
  readonly temporary: TemporaryStore;
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
  constructor(private readonly sql: Sql, authority?: RegistrationAuthority, emailRateLimit?: EmailRateLimit, clock: () => number = unixTime) {
    sql.execute("CREATE TABLE IF NOT EXISTS accounts (id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, data TEXT NOT NULL)");
    this.temporary = new TemporaryStore(sql, clock);
    this.registrationAuthority = authority ?? new SqlRegistrationAuthority(sql);
    this.emailRateLimit = emailRateLimit ?? new SqlEmailRateLimit(sql, this.temporary);
  }
  private save(account: Account, insert: boolean): void {
    const { persistent, temporary } = splitAccount(account), data = JSON.stringify(persistent);
    this.temporary.removeOwner(account.id);
    this.temporary.remove('registration', '', account.id);
    if (account.registrationAdmission.state === 'pending') {
      this.temporary.releaseLookup('registration', account.email);
      this.temporary.put({ namespace: 'registration', owner: '', key: account.id, lookup: account.email, value: persistent, expiresAt: account.registrationAdmission.expiresAt });
    } else if (insert) {
      this.sql.execute('INSERT INTO accounts(id,email,data) VALUES(?,?,?)', [account.id, account.email, data]);
    } else {
      this.sql.execute('UPDATE accounts SET data=? WHERE id=?', [data, account.id]);
    }
    for (const record of temporary) this.temporary.put(record);
  }
  create(account: Account): void {
    this.sql.transaction(() => {
      if (this.byEmail(account.email) || this.read(account.id)) throw new Fault(409, "account_exists");
      this.document(account);
      this.save(account, true);
    });
    this.temporary.changed();
  }
  byEmail(email: string): string | undefined {
    const id = this.sql.rows("SELECT id FROM accounts WHERE email=?", [email])[0]?.id as string | undefined;
    return id ?? this.temporary.lookup('registration', email);
  }
  read(accountId: string): Account | undefined {
    const row = this.sql.rows("SELECT data FROM accounts WHERE id=?", [accountId])[0];
    const account = row ? JSON.parse(String(row.data)) as Account : this.temporary.get<Account>('registration', '', accountId);
    if (!account) return undefined;
    validateAccountSchema(account);
    joinAccount(account, this.temporary.list(accountId));
    validateRecoveryOperationClosures(account);
    validateRegistration(account);
    return account;
  }
  transaction<T>(accountId: string, operation: (account: Account) => T): T {
    let changed = false;
    const result = this.sql.transaction(() => {
      const account = this.read(accountId);
      if (!account) throw new Fault(401, "unauthorized");
      const pending = account.registrationAdmission.state === 'pending';
      const required = registrationVerificationRequired(account), before = JSON.stringify(account), result = operation(account), after = this.document(account);
      if (required !== registrationVerificationRequired(account)) throw new Fault(409, "registration_policy_immutable");
      this.save(account, pending);
      changed = before !== after;
      return result;
    });
    this.temporary.changed();
    // 通知失败不能把已提交事务伪装为失败；观察者只在真正 COMMIT 后运行。
    if (changed) for (const listener of this.listeners) { try { listener(accountId); } catch { /* 下次拉取仍可补漏 */ } }
    return result;
  }
}

function validateAccountSchema(account: Account): void {
  if (account.schema !== 3 || ["pairingSessions", "deviceEnrollments", "recoveryRotations", "recoveryAuthorityTransitions", "recoveryAuthorityChallenges", "recoveredDeviceChallenges", "recoveredDevices"].some(key => Object.hasOwn(account, key))) throw new Fault(409, "account_format_unsupported");
}
