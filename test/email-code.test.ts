import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AccountLifecycle, type EmailProof } from '../src/account-lifecycle.js';
import { Fault } from '../src/model.js';
import { nodeStore } from '../src/node-store.js';
import { wasmPassword } from '../src/password.js';
import { VaultService } from '../src/service.js';
import { route } from '../src/http.js';
import type { Email } from '../src/email-transport.js';
import { mailCode } from './email-proof.js';
import { clientCredential } from './fixtures.js';

const email = 'code@example.invalid';
const denies = (code: string) => (e: unknown) => e instanceof Fault && e.code === code;
const wrong = (code: string) => code === 'A2BC3DE4' ? 'B2CD3EF4' : 'A2BC3DE4';
async function fixture(purpose: EmailProof['purpose'], run: (h: {
  life: AccountLifecycle; vault: VaultService; store: ReturnType<typeof nodeStore>['store'];
  code: string; id: string; mails: Email[]; advance: (seconds: number) => void;
  reopen: () => AccountLifecycle;
}) => Promise<void>) {
  const dir = mkdtempSync(join(tmpdir(), 'harmonia-email-code-'));
  const file = join(dir, 'account.sqlite');
  let now = 1800000000, db = nodeStore(file, () => now);
  const mails: Email[] = [], mail = { send: async (message: Email) => { mails.push(message); } };
  const life = new AccountLifecycle(db.store, wasmPassword, () => now, mail);
  const vault = new VaultService(db.store, { allowRegistration: true, requireEmailVerification: true }, () => now, wasmPassword, mail);
  try {
    const registration = await life.register(email, clientCredential, { allowRegistration: true, requireEmailVerification: purpose === 'verification' });
    if (purpose === 'reset') await life.requestProof(email, 'reset');
    await run({ life, vault, store: db.store, code: mailCode(mails.at(-1)!), id: registration.accountId, mails, advance: seconds => { now += seconds; },
      reopen: () => { db.sql.close(); db = nodeStore(file, () => now); return new AccountLifecycle(db.store, wasmPassword, () => now, mail); } });
  } finally { db.sql.close(); rmSync(dir, { recursive: true, force: true }); }
}
function checkCode(life: AccountLifecycle, id: string, code: string, purpose: EmailProof['purpose']): Promise<unknown> {
  return purpose === 'verification' ? life.verifyEmail(id, { accountGeneration: '1', code }) : life.resolveCode(email, code);
}
for (const purpose of ['verification', 'reset'] as const) {
  test(`${purpose}: four wrong guesses followed by the correct fifth code succeed`, async () => fixture(purpose, async h => {
    for (let i = 0; i < 4; i++) await assert.rejects(checkCode(h.life, h.id, wrong(h.code), purpose), denies('email_code_invalid'));
    assert.equal(h.store.read(h.id)!.emailProofs![0]!.code!.failedAttempts, 4);
    await checkCode(h.life, h.id, h.code, purpose);
  }));
  test(`${purpose}: concurrent guesses stop at five and the lock survives SQLite reopen`, async () => fixture(purpose, async h => {
    const attempts = await Promise.allSettled(Array.from({ length: 12 }, () => checkCode(h.life, h.id, wrong(h.code), purpose)));
    assert.equal(attempts.filter(r => r.status === 'rejected' && r.reason.code === 'email_code_invalid').length, 4);
    assert.equal(attempts.filter(r => r.status === 'rejected' && r.reason.code === 'email_code_attempts_exhausted').length, 8);
    assert.equal(h.store.read(h.id)!.emailProofs![0]!.code!.failedAttempts, 5);
    const reopened = h.reopen();
    await assert.rejects(checkCode(reopened, h.id, h.code, purpose), denies('email_code_attempts_exhausted'));
    h.advance(60);
    await reopened.requestProof(email, purpose);
    await checkCode(reopened, h.id, mailCode(h.mails.at(-1)!), purpose);
  }));
  for (const elapsed of [899, 900]) test(`${purpose}: validity at ${elapsed} seconds`, async () => fixture(purpose, async h => {
    h.advance(elapsed);
    if (elapsed === 899) await checkCode(h.life, h.id, h.code, purpose);
    else await assert.rejects(checkCode(h.life, h.id, h.code, purpose), denies(purpose === 'verification' ? 'registration_expired' : 'email_code_invalid'));
  }));
  test(`${purpose}: resending replaces the challenge and resets the budget`, async () => fixture(purpose, async h => {
    const original = h.store.read(h.id)!.emailProofs![0]!;
    await assert.rejects(checkCode(h.life, h.id, wrong(h.code), purpose), denies('email_code_invalid'));
    await assert.rejects(h.life.requestProof(email, purpose), denies('email_request_limited'));
    h.advance(60); await h.life.requestProof(email, purpose);
    const replacement = h.store.read(h.id)!.emailProofs![0]!;
    assert.notEqual(replacement.id, original.id);
    assert.equal(replacement.code!.failedAttempts, 0);
    assert.equal(h.store.read(h.id)!.emailProofs!.length, 1);
    await checkCode(h.life, h.id, mailCode(h.mails.at(-1)!), purpose);
  }));
}
test('reset: cold queries reuse the original receipt without extending the email-code deadline', async () => fixture('reset', async h => {
  const proof = await h.life.resolveCode(email, h.code);
  h.advance(850);
  await h.life.reset(h.id, { ...proof, newCredential: 'ab'.repeat(32), confirmation: 'DELETE_OLD_VAULT' });
  const resumed = await h.life.resolveCode(email, h.code);
  assert.deepEqual(resumed, proof);
  assert.equal((await h.life.resetStatus(h.id, resumed)).state, 'complete');
  h.advance(50);
  await assert.rejects(h.life.resolveCode(email, h.code), denies('email_code_expired'));
}));
test('HTTP: code is the only verification input; legacy fields and routes are rejected', async () => fixture('verification', async h => {
  const post = (path: string, value: unknown) => route(new Request(`https://synthetic.invalid${path}`, { method: 'POST', headers: {"Harmonia-Protocol-Major":"2", 'content-type': 'application/json' }, body: JSON.stringify(value) }), h.vault);
  const path = `/v1/accounts/${h.id}/email-verification/complete`;
  assert.equal((await post('/v1/account-reset/resolve', { email, code: h.code })).status, 401);
  assert.equal((await post('/v1/email-verification/resolve', { email, code: h.code })).status, 404);
  assert.equal((await post(`/v1/accounts/${h.id}/email-verification/code`, { accountGeneration: '1', code: h.code })).status, 404);
  assert.equal((await post(path, { accountGeneration: '1', challengeId: 'email-code', token: h.code })).status, 400);
  assert.equal((await post(path, { accountGeneration: '1', code: h.code, token: h.code })).status, 400);
  assert.equal((await post(path, { accountGeneration: '1', code: Number(h.code) })).status, 400);
  for (let n = 0; n < 4; n++) assert.equal((await post(path, { accountGeneration: '1', code: wrong(h.code) })).status, 401);
  const response = await post(path, { accountGeneration: '1', code: h.code.toLowerCase() });
  assert.equal(response.status, 200); assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.deepEqual(await response.json(), { verified: true });
  assert.equal((await post(path, { accountGeneration: '1', code: h.code })).status, 401);
}));

test('optional verification consumes the code even when registration is already complete', async () => fixture('reset', async h => {
  h.advance(31);
  await h.life.requestProof(email, 'verification');
  const input = { accountGeneration: '1', code: mailCode(h.mails.at(-1)!) };
  await h.life.verifyEmail(h.id, input);
  assert.equal(h.store.read(h.id)!.verified, true);
  await assert.rejects(h.life.verifyEmail(h.id, input), denies('email_code_invalid'));
  assert.equal(h.store.read(h.id)!.emailProofs!.every(proof => proof.purpose === 'reset'), true);
}));

test('registration resend keeps the original deadline and expiry allows a fresh registration', async () => fixture('verification', async h => {
  const deadline = h.store.read(h.id)!.registrationAdmission!.expiresAt;
  h.advance(870);
  await h.life.requestProof(email, 'verification');
  const resent = mailCode(h.mails.at(-1)!);
  const account = h.store.read(h.id)!;
  assert.equal(account.registrationAdmission!.expiresAt, deadline);
  assert.equal(account.emailProofs![0]!.expiresAt, deadline);
  assert.equal(account.emailProofs![0]!.code.expiresAt, deadline);
  assert.match(h.mails.at(-1)!.text, /^1 分钟内有效/m);
  h.advance(30);
  const sent = h.mails.length;
  await h.life.requestProof(email, 'verification');
  await assert.rejects(checkCode(h.life, h.id, resent, 'verification'), denies('registration_expired'));
  assert.equal(h.mails.length, sent);
  h.advance(30);
  const replacement = await h.life.register(email, clientCredential, { allowRegistration: true, requireEmailVerification: true });
  assert.notEqual(replacement.accountId, h.id);
  assert.equal(replacement.accountGeneration, '1');
  assert.equal(h.store.read(replacement.accountId)!.registrationAdmission!.expiresAt, deadline + 930);
  await assert.rejects(h.life.verifyEmail(h.id, { accountGeneration: '1', code: resent }));
  await h.life.verifyEmail(replacement.accountId, { accountGeneration: '1', code: mailCode(h.mails.at(-1)!).toLowerCase() });
  assert.equal(h.store.read(replacement.accountId)!.registrationAdmission!.state, 'complete');
}));

test('resending immediately before registration expiry leaves only the remaining lifetime', async () => fixture('verification', async h => {
  h.advance(899);
  await h.life.requestProof(email, 'verification');
  const code = mailCode(h.mails.at(-1)!);
  h.advance(1);
  await assert.rejects(checkCode(h.life, h.id, code, 'verification'), denies('registration_expired'));
}));

for (const purpose of ['verification', 'reset'] as const) test(`${purpose}: malformed codes never consume a guess; ASCII lowercase works`, async () => fixture(purpose, async h => {
  for (const code of ['123456', '23456789', 'ABCDEFGH', 'A2BC3D4', 'A2BC3DE45', 'A2BC3DE0', 'A2BC3DE1', 'A2BC3DEI', 'A2BC3DEO', 'ß2BC3DE', 'Ａ2BC3DE4', 'A2BC3DE4\n']) {
    await assert.rejects(checkCode(h.life, h.id, code, purpose), denies('email_code_invalid'));
  }
  assert.equal(h.store.read(h.id)!.emailProofs![0]!.code.failedAttempts, 0);
  assert.match(h.code, /^[2-9A-HJ-NP-Z]{8}$/);
  assert.match(h.code, /[2-9]/);
  assert.match(h.code, /[A-Z]/);
  await checkCode(h.life, h.id, h.code.toLowerCase(), purpose);
}));
