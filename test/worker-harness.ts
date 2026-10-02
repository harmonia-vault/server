// 测试专用 RPC 建立合成状态；生产 Worker 不导出这个类或路由。
import { AccountVault } from "../src/worker.js";
import worker from "../src/worker.js";
import type { Account } from "../src/model.js";
export class SyntheticVault extends AccountVault {
  seed(account: Account): void {
    this.ctx.storage.sql.exec("INSERT INTO accounts(id,email,data) VALUES(?,?,?)", account.id, account.email, JSON.stringify(account));
  }
}
interface TestEnv { ACCOUNTS: DurableObjectNamespace<AccountVault>; FIXTURES: DurableObjectNamespace<SyntheticVault>; DIRECTORY: D1Database }
export default {
  async fetch(request: Request, env: TestEnv, ctx: ExecutionContext): Promise<Response> {
    if (new URL(request.url).pathname === "/test/seed") {
      const account = await request.json<Account>();
      await env.FIXTURES.getByName(account.id).seed(account);
      await env.DIRECTORY.prepare("CREATE TABLE IF NOT EXISTS account_directory (email TEXT PRIMARY KEY, account_id TEXT UNIQUE NOT NULL)").run();
      await env.DIRECTORY.prepare("INSERT INTO account_directory(email,account_id) VALUES(?,?)").bind(account.email, account.id).run();
      return Response.json({ seeded: true });
    }
    return worker.fetch(request, { ...env, ALLOW_REGISTRATION: "false", REQUIRE_EMAIL_VERIFICATION: "true" });
  },
};
