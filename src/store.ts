import type { Account } from "./model.js";
import { Fault } from "./model.js";
import { validateRecoveryState } from "./lifecycle-wire.js";
export interface Store {
  create(account: Account): void;
  byEmail(email: string): string | undefined;
  read(accountId: string): Account | undefined;
  transaction<T>(accountId: string, operation: (account: Account) => T): T;
}
export interface Sql {
  execute(query: string, params?: (string | number | null)[]): void;
  rows(query: string, params?: (string | number | null)[]): Record<string, unknown>[];
  transaction<T>(operation: () => T): T;
}
// A single versioned account row keeps credentials, permissions and events in one atomic domain.
// M1 uses a bounded account document; a normalized event table is a later scaling step.
export class SqlStore implements Store {
  private document(account: Account): string {
    validateRecoveryState(account);
    const data = JSON.stringify(account);
    if (Buffer.byteLength(data) > 1_000_000) throw new Fault(503, "account_capacity_reached");
    return data;
  }
  constructor(private readonly sql: Sql) {
    sql.execute("CREATE TABLE IF NOT EXISTS accounts (id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, data TEXT NOT NULL)");
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
    return row ? JSON.parse(String(row.data)) as Account : undefined;
  }
  transaction<T>(accountId: string, operation: (account: Account) => T): T {
    return this.sql.transaction(() => {
      const account = this.read(accountId);
      if (!account) throw new Fault(401, "unauthorized");
      const result = operation(account);
      this.sql.execute("UPDATE accounts SET data=? WHERE id=?", [this.document(account), accountId]);
      return result;
    });
  }
}
