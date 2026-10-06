import { DatabaseSync } from "node:sqlite";
import { SqlStore, type Sql } from "./store.js";
import { unixTime, type TemporaryStore } from './temporary-store.js';
export class NodeSql implements Sql {
  readonly db: DatabaseSync;
  private stopExpiry: (() => void) | undefined;
  constructor(path: string) {
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000");
  }
  execute(query: string, params: (string | number | null)[] = []): void { this.db.prepare(query).run(...params); }
  rows(query: string, params: (string | number | null)[] = []): Record<string, unknown>[] { return this.db.prepare(query).all(...params); }
  transaction<T>(operation: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try { const result = operation(); this.db.exec("COMMIT"); return result; }
    catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }
  scheduleExpiry(temporary: TemporaryStore): void {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const collect = (): void => {
      try { temporary.sweep(); schedule(); }
      catch { timer = setTimeout(collect, 1000); timer.unref(); }
    };
    const schedule = (): void => {
      clearTimeout(timer);
      const deadline = temporary.nextExpiry();
      if (deadline === undefined) return;
      const delay = Math.max(1, (deadline - temporary.clock()) * 1000);
      timer = setTimeout(collect, delay);
      timer.unref();
    };
    const unsubscribe = temporary.onChange(schedule);
    this.stopExpiry = () => { clearTimeout(timer); unsubscribe(); };
    collect();
  }
  close(): void { this.stopExpiry?.(); this.db.close(); }
}
export function nodeStore(path: string, clock: () => number = unixTime): { store: SqlStore; sql: NodeSql } {
  const sql = new NodeSql(path), store = new SqlStore(sql, undefined, undefined, clock);
  sql.scheduleExpiry(store.temporary);
  return { sql, store };
}
