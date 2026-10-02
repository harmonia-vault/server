// 测试专用 RPC 建立合成状态；生产 Worker 不导出这个类或路由。
import { AccountVault } from "../src/worker.js";
import worker from "../src/worker.js";
import type { Email, EmailTransport } from "../src/email-transport.js";
import type { Account } from "../src/model.js";
export class SyntheticVault extends AccountVault {
  protected override mailTransport(): EmailTransport {
    return { send: async (message: Email) => {
      this.ctx.storage.sql.exec("CREATE TABLE IF NOT EXISTS synthetic_mail (message TEXT NOT NULL)");
      this.ctx.storage.sql.exec("INSERT INTO synthetic_mail(message) VALUES(?)", JSON.stringify(message));
    } };
  }
  mails(): Email[] {
    this.ctx.storage.sql.exec("CREATE TABLE IF NOT EXISTS synthetic_mail (message TEXT NOT NULL)");
    return this.ctx.storage.sql.exec<{ message: string }>("SELECT message FROM synthetic_mail").toArray().map(row => JSON.parse(row.message) as Email);
  }
  seed(account: Account): void {
    this.ctx.storage.sql.exec("INSERT INTO accounts(id,email,data) VALUES(?,?,?)", account.id, account.email, JSON.stringify(account));
  }
}
interface TestEnv { ACCOUNTS: DurableObjectNamespace<AccountVault>; FIXTURES: DurableObjectNamespace<SyntheticVault>; DIRECTORY: D1Database; ALLOW_REGISTRATION?: string; REQUIRE_EMAIL_VERIFICATION?: string; EMAIL_FROM?: string }
export default {
  async fetch(request: Request, env: TestEnv, ctx: ExecutionContext): Promise<Response> {
    if (new URL(request.url).pathname === "/test/seed") {
      const account = await request.json<Account>();
      await env.FIXTURES.getByName(account.id).seed(account);
      await env.DIRECTORY.prepare("CREATE TABLE IF NOT EXISTS account_directory (email TEXT PRIMARY KEY, account_id TEXT UNIQUE NOT NULL)").run();
      await env.DIRECTORY.prepare("INSERT INTO account_directory(email,account_id) VALUES(?,?)").bind(account.email, account.id).run();
      return Response.json({ seeded: true });
    }
    const mailbox = new URL(request.url).pathname.match(/^\/test\/mail\/([A-Za-z0-9._:-]+)$/);
    if (mailbox) return Response.json(await env.FIXTURES.getByName(mailbox[1]!).mails());
    return worker.fetch(request, { ...env, ALLOW_REGISTRATION: env.ALLOW_REGISTRATION ?? "false", REQUIRE_EMAIL_VERIFICATION: env.REQUIRE_EMAIL_VERIFICATION ?? "true", EMAIL_FROM: env.EMAIL_FROM ?? "",
      EMAIL: { send: async () => { throw new Error("synthetic edge must not send mail"); } } });
  },
};
