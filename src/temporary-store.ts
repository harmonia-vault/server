import type { Sql } from './store.js';

export const unixTime = (): number => Math.floor(Date.now() / 1000);
export interface TemporaryRecord<T = unknown> { namespace: string; owner: string; key: string; value: T; expiresAt: number; lookup?: string }

/** TTL 数据与账号共用事务。过期立即不可读，运行时负责独立于请求的物理回收。 */
export class TemporaryStore {
  private readonly listeners = new Set<() => void>();
  constructor(private readonly sql: Sql, readonly clock: () => number = unixTime) {
    sql.execute('CREATE TABLE IF NOT EXISTS temporary_records (namespace TEXT NOT NULL, owner TEXT NOT NULL, key TEXT NOT NULL, data TEXT NOT NULL, expires_at INTEGER NOT NULL, lookup TEXT, PRIMARY KEY(namespace,owner,key))');
    sql.execute('CREATE INDEX IF NOT EXISTS temporary_expiry ON temporary_records(expires_at)');
    sql.execute('CREATE INDEX IF NOT EXISTS temporary_owner ON temporary_records(owner)');
    sql.execute('CREATE UNIQUE INDEX IF NOT EXISTS temporary_lookup ON temporary_records(namespace,lookup)');
  }
  put(record: TemporaryRecord): void {
    if (!Number.isSafeInteger(record.expiresAt) || record.expiresAt <= 0) throw new Error('temporary_expiry_invalid');
    this.sql.execute('INSERT INTO temporary_records(namespace,owner,key,data,expires_at,lookup) VALUES(?,?,?,?,?,?) ON CONFLICT(namespace,owner,key) DO UPDATE SET data=excluded.data,expires_at=excluded.expires_at,lookup=excluded.lookup',
      [record.namespace, record.owner, record.key, JSON.stringify(record.value), record.expiresAt, record.lookup ?? null]);
  }
  get<T>(namespace: string, owner: string, key: string, now = this.clock()): T | undefined {
    const row = this.sql.rows('SELECT data FROM temporary_records WHERE namespace=? AND owner=? AND key=? AND expires_at>?', [namespace, owner, key, now])[0];
    return row ? JSON.parse(String(row.data)) as T : undefined;
  }
  lookup(namespace: string, lookup: string): string | undefined {
    return this.sql.rows('SELECT key FROM temporary_records WHERE namespace=? AND lookup=? AND expires_at>?', [namespace, lookup, this.clock()])[0]?.key as string | undefined;
  }
  list(owner: string): TemporaryRecord[] {
    return this.sql.rows('SELECT namespace,key,data,expires_at FROM temporary_records WHERE owner=? AND expires_at>? ORDER BY rowid', [owner, this.clock()])
      .map(row => ({ namespace: String(row.namespace), owner, key: String(row.key), value: JSON.parse(String(row.data)) as unknown, expiresAt: Number(row.expires_at) }));
  }
  remove(namespace: string, owner: string, key: string): void { this.sql.execute('DELETE FROM temporary_records WHERE namespace=? AND owner=? AND key=?', [namespace, owner, key]); }
  removeOwner(owner: string): void { this.sql.execute('DELETE FROM temporary_records WHERE owner=?', [owner]); }
  releaseLookup(namespace: string, lookup: string): void {
    this.sql.execute('DELETE FROM temporary_records WHERE namespace=? AND lookup=? AND expires_at<=?', [namespace, lookup, this.clock()]);
  }
  nextExpiry(): number | undefined {
    const value = this.sql.rows('SELECT MIN(expires_at) AS deadline FROM temporary_records')[0]?.deadline;
    return value == null ? undefined : Number(value);
  }
  sweep(): void {
    this.sql.execute('DELETE FROM temporary_records WHERE rowid IN (SELECT rowid FROM temporary_records WHERE expires_at<=? ORDER BY expires_at LIMIT 256)', [this.clock()]);
  }
  onChange(listener: () => void): () => void { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; }
  // 调度只在外层事务提交后触发，回滚不会留下提前清理的副作用。
  changed(): void { for (const listener of this.listeners) listener(); }
}
