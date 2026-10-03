// 仅测试：负例替换合成账号；生产 Worker 没有此 RPC。
export { default, InstanceRegistry } from "./worker-harness.js";
import { SyntheticVault as Base } from "./worker-harness.js";
export class SyntheticVault extends Base {
  snapshotSynthetic(accountId: string): string { return this.ctx.storage.sql.exec<{data: string}>("SELECT data FROM accounts WHERE id=?", accountId).toArray()[0]!.data; }
  replaceSynthetic(accountId: string, data: string): void { this.ctx.storage.sql.exec("UPDATE accounts SET data=? WHERE id=?", data, accountId); }
}
