// 测试专用 RPC 建立合成状态；生产 Worker 不导出这个类或路由。
import { InstanceRegistry as Registry, AccountVault } from "../src/worker.js";
import { splitAccount, joinAccount } from '../src/account-temporary.js';
import worker from "../src/worker.js";
import type { Email, EmailTransport } from "../src/email-transport.js";
import type { Account } from "../src/model.js";
export class InstanceRegistry extends Registry {
  removeRoutingKey(): void { this.ctx.storage.sql.exec('DELETE FROM routing_key'); }
  async instanceProbe(): Promise<{ completed: number; keys: number }> {
    return { completed: this.ctx.storage.sql.exec<{ completed: number }>('SELECT completed FROM instance_registration').one().completed,
      keys: this.ctx.storage.sql.exec<{ keys: number }>('SELECT COUNT(*) AS keys FROM routing_key').one().keys };
  }
  async shortenLimits(seconds: number): Promise<void> {
    this.ctx.storage.sql.exec('UPDATE temporary_records SET expires_at=?', Math.floor(Date.now() / 1000) + seconds);
    await this.alarm();
  }
  temporaryCount(): number { return this.ctx.storage.sql.exec<{ count: number }>('SELECT COUNT(*) AS count FROM temporary_records').one().count; }
  async seedRoute(email: string, id: string): Promise<void> {
    this.ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS synthetic_routes (email TEXT PRIMARY KEY, id TEXT NOT NULL)');
    this.ctx.storage.sql.exec('INSERT INTO synthetic_routes(email,id) VALUES(?,?)', email, id);
  }
  override async resolveAccount(email: string): Promise<string> {
    this.ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS synthetic_routes (email TEXT PRIMARY KEY, id TEXT NOT NULL)');
    const row = this.ctx.storage.sql.exec<{ id: string }>('SELECT id FROM synthetic_routes WHERE email=?', email).toArray()[0];
    return row?.id ?? super.resolveAccount(email);
  }
}
export class SyntheticRegistry extends InstanceRegistry {
  arm(): void { this.ctx.storage.sql.exec("CREATE TRIGGER IF NOT EXISTS synthetic_registration_fault BEFORE UPDATE ON instance_registration WHEN NEW.completed=1 BEGIN SELECT RAISE(ABORT,'synthetic first decision failure'); END"); }
  disarm(): void { this.ctx.storage.sql.exec("DROP TRIGGER IF EXISTS synthetic_registration_fault"); }
}
export class SyntheticVault extends AccountVault {
  async shortenTemporary(seconds: number): Promise<void> {
    this.ctx.storage.sql.exec('UPDATE temporary_records SET expires_at=?', Math.floor(Date.now() / 1000) + seconds);
    await this.alarm();
  }
  async expiryProbe(): Promise<{ temporary: number; accounts: number; alarm: number | null }> {
    return {
      temporary: this.ctx.storage.sql.exec<{ count: number }>('SELECT COUNT(*) AS count FROM temporary_records').one().count,
      accounts: this.ctx.storage.sql.exec<{ count: number }>('SELECT COUNT(*) AS count FROM accounts').one().count,
      alarm: await this.ctx.storage.getAlarm(),
    };
  }
  protected override mailTransport(): EmailTransport {
    return { send: async (message: Email) => {
      this.ctx.storage.sql.exec("CREATE TABLE IF NOT EXISTS synthetic_mail (message TEXT NOT NULL)");
      this.ctx.storage.sql.exec("INSERT INTO synthetic_mail(message) VALUES(?)", JSON.stringify(message));
    } };
  }
  account(accountId:string): Account | null {
    const row = this.ctx.storage.sql.exec<{data:string}>('SELECT data FROM accounts WHERE id=?', accountId).toArray()[0];
    const data = row ? JSON.parse(row.data) as Account : this.store.temporary.get<Account>('registration', '', accountId);
    return data ? joinAccount(data, this.store.temporary.list(accountId)) : null;
  }
  activationFault(): void { this.ctx.storage.sql.exec("CREATE TRIGGER IF NOT EXISTS synthetic_activation_fault BEFORE UPDATE ON accounts WHEN json_extract(NEW.data,'$.registrationAdmission.state')='complete' BEGIN SELECT RAISE(ABORT,'synthetic activation failure'); END"); }
  clearFault(): void { this.ctx.storage.sql.exec("DROP TRIGGER IF EXISTS synthetic_activation_fault"); }
  removeAccount(accountId:string):void{this.ctx.storage.sql.exec("DELETE FROM accounts WHERE id=?",accountId);}
  mails(): Email[] {
    this.ctx.storage.sql.exec("CREATE TABLE IF NOT EXISTS synthetic_mail (message TEXT NOT NULL)");
    return this.ctx.storage.sql.exec<{ message: string }>("SELECT message FROM synthetic_mail").toArray().map(row => JSON.parse(row.message) as Email);
  }
  async notificationProbe(): Promise<{ now:number; scheduledAlarm:number|null; socketStates:number[] }> { return { now: Date.now(), scheduledAlarm: await this.ctx.storage.getAlarm(), socketStates: this.ctx.getWebSockets().map(ws=>ws.readyState) }; }
  resetGeneration(accountId: string): void {
    const row = this.ctx.storage.sql.exec<{data:string}>("SELECT data FROM accounts WHERE id=?", accountId).toArray()[0]!;
    const account = JSON.parse(row.data) as Account; account.generation = "2";
    this.ctx.storage.sql.exec("UPDATE accounts SET data=? WHERE id=?", JSON.stringify(account), accountId);
    // 测试专用触发 alarm，让正式通知内核重查修改后的权威状态。
    this.ctx.waitUntil(this.alarm());
  }
  seed(account: Account): void {
    this.persistSynthetic(account, true);
  }
  protected persistSynthetic(account: Account, insert: boolean): void {
    const { persistent, temporary } = splitAccount(account);
    this.ctx.storage.transactionSync(() => {
      if (insert) this.ctx.storage.sql.exec("INSERT INTO accounts(id,email,data) VALUES(?,?,?)", account.id, account.email, JSON.stringify(persistent));
      else this.ctx.storage.sql.exec('UPDATE accounts SET data=? WHERE id=?', JSON.stringify(persistent), account.id);
      this.store.temporary.removeOwner(account.id);
      for (const record of temporary) this.store.temporary.put(record);
    });
    this.store.temporary.changed();
  }
}
interface TestEnv { INSTANCES?: DurableObjectNamespace<Registry>; ACCOUNTS: DurableObjectNamespace<AccountVault>; FIXTURES: DurableObjectNamespace<SyntheticVault>; ALLOW_REGISTRATION?: string; REQUIRE_EMAIL_VERIFICATION?: string; EMAIL_FROM?: string }
export default {
  async fetch(request: Request, env: TestEnv, ctx: ExecutionContext): Promise<Response> {
    if (new URL(request.url).pathname === "/test/seed") {
      const account = await request.json<Account>();
      await env.FIXTURES.getByName(account.id).seed(account);
      await (env.INSTANCES?.getByName('harmonia-instance-v1') as DurableObjectStub<InstanceRegistry> | undefined)?.seedRoute(account.email, account.id);
      return Response.json({ seeded: true });
    }
    const probe = new URL(request.url).pathname.match(/^\/test\/notification-probe\/([A-Za-z0-9._:-]+)$/);
    if (probe) return Response.json(await env.FIXTURES.getByName(probe[1]!).notificationProbe());
    const reset = new URL(request.url).pathname.match(/^\/test\/reset-generation\/([A-Za-z0-9._:-]+)$/);
    if (reset) { await env.FIXTURES.getByName(reset[1]!).resetGeneration(reset[1]!); return Response.json({ reset: true }); }
    const mailbox = new URL(request.url).pathname.match(/^\/test\/mail\/([A-Za-z0-9._:-]+)$/);
    if (mailbox) return Response.json(await env.FIXTURES.getByName(mailbox[1]!).mails());
    return worker.fetch(request, { ...env, ALLOW_REGISTRATION: env.ALLOW_REGISTRATION ?? "false", REQUIRE_EMAIL_VERIFICATION: env.REQUIRE_EMAIL_VERIFICATION ?? "true", EMAIL_FROM: env.EMAIL_FROM ?? "",
      EMAIL: { send: async () => { throw new Error("synthetic edge must not send mail"); } } });
  },
};
