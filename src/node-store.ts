import { DatabaseSync } from "node:sqlite";
import { SqlStore, type Sql } from "./store.js";
export class NodeSql implements Sql {
  readonly db: DatabaseSync;
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
  close(): void { this.db.close(); }
}
export function nodeStore(path: string): { store: SqlStore; sql: NodeSql } {
  const sql = new NodeSql(path); return { sql, store: new SqlStore(sql) };
}
