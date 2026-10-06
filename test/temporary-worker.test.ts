import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { setTimeout } from 'node:timers/promises';
import { build } from 'esbuild';
import { Miniflare } from 'miniflare';
import type { InstanceRegistry, SyntheticVault } from './worker-harness.js';
import { clientCredential } from './fixtures.js';
import { mailCode } from './email-proof.js';

test('workerd alarms delete pending registration and shared limits without account requests; routing survives restart', { timeout: 30000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'harmonia-temporary-worker-'));
  const bundle = await build({ entryPoints: ['test/worker-harness.ts'], bundle: true, write: false, format: 'esm', platform: 'browser', target: 'es2023', external: ['cloudflare:workers', 'node:*'], banner: { js: 'import { Buffer } from "node:buffer";' } });
  const options = { modules: true as const, script: bundle.outputFiles[0]!.text, compatibilityDate: '2026-07-30', compatibilityFlags: ['nodejs_compat'],
    durableObjects: { INSTANCES: { className: 'InstanceRegistry', useSQLite: true }, ACCOUNTS: { className: 'SyntheticVault', useSQLite: true }, FIXTURES: { className: 'SyntheticVault', useSQLite: true } },
    durableObjectsPersist: join(dir, 'objects'), bindings: { ALLOW_REGISTRATION: 'true', REQUIRE_EMAIL_VERIFICATION: 'true', EMAIL_FROM: 'noreply@example.invalid' } };
  let mf = new Miniflare(options);
  const post = (path: string, value: unknown) => mf.dispatchFetch(`https://synthetic.invalid${path}`, { method: 'POST', headers: { 'Harmonia-Protocol-Major': '2', 'content-type': 'application/json', 'cf-connecting-ip': '192.0.2.1' }, body: JSON.stringify(value) });
  const vault = async (id: string) => (await mf.getDurableObjectNamespace('FIXTURES')).getByName(id) as unknown as DurableObjectStub<SyntheticVault>;
  const registry = async () => (await mf.getDurableObjectNamespace('INSTANCES')).getByName('harmonia-instance-v1') as unknown as DurableObjectStub<InstanceRegistry>;
  try {
    const email = 'ttl@example.invalid';
    const response = await post('/v1/register', { email, credential: clientCredential });
    assert.equal(response.status, 200, await response.clone().text());
    const { accountId } = await response.json() as { accountId: string };
    const account = await vault(accountId), shared = await registry();
    const original = (await account.mails())[0]!;
    assert.equal((await account.expiryProbe()).accounts, 0);
    assert.ok((await account.expiryProbe()).alarm);
    assert.equal(await shared.resolveAccount(email.toUpperCase()), accountId);
    await account.shortenTemporary(2); await shared.shortenLimits(2);
    await setTimeout(2600);
    // 探针直接查 SQL，不通过会顺便清理的业务读取。
    assert.equal((await account.expiryProbe()).temporary, 0);
    assert.equal((await account.expiryProbe()).alarm, null);
    assert.equal(await shared.temporaryCount(), 0);
    const expired = await post(`/v1/accounts/${accountId}/email-verification/complete`, { accountGeneration: '1', code: mailCode(original) });
    assert.equal(expired.status, 401);
    assert.equal((await expired.json() as { error: string }).error, 'registration_expired');
    await mf.dispose(); mf = new Miniflare(options);
    assert.equal(await (await registry()).resolveAccount(email), accountId);
    const retry = await post('/v1/register', { email, credential: clientCredential });
    assert.equal(retry.status, 200, await retry.clone().text());
    assert.equal((await retry.json() as { accountId: string }).accountId, accountId);
    const fresh = await vault(accountId), code = mailCode((await fresh.mails()).at(-1)!);
    assert.equal((await post(`/v1/accounts/${accountId}/email-verification/complete`, { accountGeneration: '1', code: mailCode(original) })).status, 401);
    assert.equal((await post(`/v1/accounts/${accountId}/email-verification/complete`, { accountGeneration: '1', code })).status, 200);
    assert.equal((await fresh.expiryProbe()).accounts, 1);
    const login = await post('/v1/login', { email, credential: clientCredential });
    assert.equal(login.status, 200);
    await fresh.shortenTemporary(2);
    await mf.dispose(); mf = new Miniflare(options);
    await setTimeout(2600);
    const final = await (await vault(accountId)).expiryProbe();
    assert.equal(final.accounts, 1);
    assert.equal(final.temporary, 0);
    // 缺少当前格式的旧实例必须明确拒绝，不能静默创建另一份账号空间。
    await (await registry()).removeRoutingKey();
    await mf.dispose(); mf = new Miniflare(options);
    for (const path of ['/v1/login', '/v1/register']) {
      const result = await post(path, { email, credential: clientCredential });
      assert.equal(result.status, 409);
      assert.equal((await result.json() as { error: string }).error, 'account_format_unsupported');
    }
    const oldInstance = await (await registry()).instanceProbe();
    assert.equal(oldInstance.completed, 1);
    assert.equal(oldInstance.keys, 0);
  } finally { await mf.dispose(); rmSync(dir, { recursive: true, force: true }); }
});
