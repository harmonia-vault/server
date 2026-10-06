// 仅测试：负例替换合成账号；生产 Worker 没有此 RPC。
export { default, InstanceRegistry } from "./worker-harness.js";
import { SyntheticVault as Base } from "./worker-harness.js";
export class SyntheticVault extends Base {
  snapshotSynthetic(accountId: string): string { return JSON.stringify(this.account(accountId)); }
  replaceSynthetic(accountId: string, data: string): void {
    const account = JSON.parse(data);
    if (account.id !== accountId) throw new Error('synthetic_account_mismatch');
    this.persistSynthetic(account, false);
  }
}
