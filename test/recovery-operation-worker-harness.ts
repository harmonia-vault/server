// 仅实际本地workerd测试可见；生产worker不导出这几个原始SQL探针。
import worker, {InstanceRegistry} from '../src/worker.js';
import {SyntheticVault} from './worker-harness.js';
import type {Account} from '../src/model.js';
export {InstanceRegistry};
export class ClosureSyntheticVault extends SyntheticVault {
  replace(account: Account): void { this.ctx.storage.sql.exec('UPDATE accounts SET data=? WHERE id=?', JSON.stringify(account), account.id); }
  closureFault(on: boolean): void {
    this.ctx.storage.sql.exec('DROP TRIGGER IF EXISTS synthetic_closure_fault');
    if (on) this.ctx.storage.sql.exec("CREATE TRIGGER synthetic_closure_fault BEFORE UPDATE ON accounts WHEN json_extract(NEW.data,'$.recoveryOperationClosures') IS NOT NULL AND json_extract(OLD.data,'$.recoveryOperationClosures') IS NULL BEGIN SELECT RAISE(ABORT,'synthetic closure write failure'); END");
  }
}
interface Env {INSTANCES: DurableObjectNamespace<InstanceRegistry>; ACCOUNTS: DurableObjectNamespace<ClosureSyntheticVault>; FIXTURES: DurableObjectNamespace<ClosureSyntheticVault>; DIRECTORY: D1Database}
export default {async fetch(request: Request, env: Env): Promise<Response> {
  const u = new URL(request.url);
  if (u.pathname === '/test/seed') {
    const a = await request.json<Account>(); await env.FIXTURES.getByName(a.id).seed(a);
    await env.DIRECTORY.prepare('CREATE TABLE IF NOT EXISTS account_directory (email TEXT PRIMARY KEY, account_id TEXT UNIQUE NOT NULL)').run();
    await env.DIRECTORY.prepare('INSERT INTO account_directory(email,account_id) VALUES(?,?)').bind(a.email, a.id).run();
    return Response.json({seeded: true});
  }
  const m = u.pathname.match(/^\/test\/closure\/(state|replace|fault)\/([A-Za-z0-9._:-]+)$/);
  if (m) {
    const stub = env.FIXTURES.getByName(m[2]!);
    if (m[1] === 'state') return Response.json(await stub.account(m[2]!));
    if (m[1] === 'replace') await stub.replace(await request.json<Account>());
    else await stub.closureFault((await request.json<{on: boolean}>()).on);
    return Response.json({done: true});
  }
  return worker.fetch(request, {...env, ALLOW_REGISTRATION: 'false', REQUIRE_EMAIL_VERIFICATION: 'true', EMAIL_FROM: '', EMAIL: {send: async () => {throw Error('synthetic no mail');}}});
}};
