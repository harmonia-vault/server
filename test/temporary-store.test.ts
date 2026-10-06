import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { nodeStore } from '../src/node-store.js';
import { AccountLifecycle } from '../src/account-lifecycle.js';
import { VaultService } from '../src/service.js';
import { fixtureAccount, now, auth, clientCredential } from './fixtures.js';
import { mailCode } from './email-proof.js';
import type { Email } from '../src/email-transport.js';
import type { RecoveryDAGAccount } from '../src/recovery-dag-account.js';
import { Fault } from '../src/model.js';

const passwords = { hash: async (value: string) => `synthetic:${value}`, verify: async (value: string, verifier: string) => verifier === `synthetic:${value}` };
const policy = { allowRegistration: true, requireEmailVerification: true };
const rejects = (code: string) => (error: unknown) => error instanceof Fault && error.code === code;

test('unverified registration is temporary; expiry releases the email and leaves IP limits intact', async () => {
  let clock = now;
  const db = nodeStore(':memory:', () => clock), mails: Email[] = [];
  const life = new AccountLifecycle(db.store, passwords, () => clock, { send: async message => { mails.push(message); } });
  try {
    const first = await life.register('pending@example.invalid', clientCredential, policy, undefined, '192.0.2.1');
    assert.equal(db.sql.rows('SELECT id FROM accounts').length, 0);
    assert.equal(db.store.byEmail('pending@example.invalid'), first.accountId);
    clock += 900;
    assert.equal(db.store.read(first.accountId), undefined);
    assert.equal(db.store.byEmail('pending@example.invalid'), undefined);
    db.store.temporary.sweep();
    assert.equal(db.sql.rows("SELECT key FROM temporary_records WHERE namespace<>'email-limit'").length, 0);
    assert.equal(db.sql.rows("SELECT key FROM temporary_records WHERE namespace='email-limit'").length, 1);
    await assert.rejects(life.verifyEmail(first.accountId, { accountGeneration: '1', code: mailCode(mails[0]!) }), rejects('registration_expired'));
    const fresh = await life.register('pending@example.invalid', clientCredential, policy);
    assert.notEqual(fresh.accountId, first.accountId);
    await life.verifyEmail(fresh.accountId, { accountGeneration: '1', code: mailCode(mails.at(-1)!) });
    assert.equal(db.sql.rows('SELECT id FROM accounts').length, 1);
    assert.equal(db.store.read(fresh.accountId)!.registrationAdmission.state, 'complete');
  } finally { db.sql.close(); }
});

test('promotion failure rolls back the account and code consumption together', async () => {
  const db = nodeStore(':memory:', () => now), mails: Email[] = [];
  const life = new AccountLifecycle(db.store, passwords, () => now, { send: async message => { mails.push(message); } });
  try {
    const first = await life.register('atomic@example.invalid', clientCredential, policy);
    const input = { accountGeneration: '1', code: mailCode(mails[0]!) };
    db.sql.execute("CREATE TRIGGER fail_promotion BEFORE INSERT ON accounts BEGIN SELECT RAISE(ABORT,'synthetic promotion failure'); END");
    await assert.rejects(life.verifyEmail(first.accountId, input), /synthetic promotion failure/);
    assert.equal(db.store.read(first.accountId)!.verified, false);
    assert.equal(db.sql.rows('SELECT id FROM accounts').length, 0);
    assert.equal((await db.store.registrationAuthority.info()).firstCompleted, false);
    db.sql.execute('DROP TRIGGER fail_promotion');
    await life.verifyEmail(first.accountId, input);
    assert.equal(db.store.read(first.accountId)!.registrationAdmission.state, 'complete');
  } finally { db.sql.close(); }
});

test('failed mail leaves only a temporary application, which is physically removed', async () => {
  let clock = now;
  const db = nodeStore(':memory:', () => clock);
  const life = new AccountLifecycle(db.store, passwords, () => clock, { send: async () => { throw new Error('synthetic delivery failure'); } });
  try {
    await assert.rejects(life.register('failed@example.invalid', clientCredential, policy), rejects('email_delivery_failed'));
    assert.equal(db.sql.rows('SELECT id FROM accounts').length, 0);
    clock += 900; db.store.temporary.sweep();
    assert.equal(db.sql.rows('SELECT key FROM temporary_records').length, 0);
  } finally { db.sql.close(); }
});

test('all transient account fields expire while signed initialization and approved pairing remain', async () => {
  let clock = now;
  const db = nodeStore(':memory:', () => clock), account = await fixtureAccount();
  const expiresAt = now + 1;
  account.sessions.forEach(s => { s.expiresAt = expiresAt; });
  account.deviceChallenges = [{ id: 'challenge', deviceId: 'admin', sessionHash: 'hash', nonce: 'nonce', generation: '1', expiresAt }];
  account.bootChallenges = [{ id: 'boot', deviceId: 'admin', generation: '1', signingPublicKey: 'key', receivingPublicKey: 'key', nonce: 'nonce', expiresAt }];
  account.recoveryChallenges = [{ id: 'recovery', generation: '1', recoveryGeneration: '1', signingPublicKey: 'key', nonce: 'nonce', expiresAt }];
  const code = { salt: 'salt', failedAttempts: 0, expiresAt };
  account.emailProofs = [{ id: 'proof', purpose: 'reset', generation: '1', tokenHash: 'hash', verifierHash: 'hash', expiresAt, code }];
  account.resetReceipt = { id: 'reset', oldGeneration: '1', generation: '2', tokenHash: 'hash', contentHash: 'hash', expiresAt, code };
  account.notificationTickets = [{ ticketHash: 'ticket', sessionHash: 'hash', accountGeneration: '1', deviceId: 'admin', expiresAt }];
  const complete = Object.values(account.vaultInitializations!)[0]!;
  const pending = structuredClone(complete); delete pending.complete; pending.expiresAt = expiresAt;
  account.vaultInitializations!.pending = pending;
  const approval = account.dagDeviceEnrollments!.writer!;
  const pairing = { idempotencyKey: 'pair', initiatorSessionHash: 'hash', context: { ...approval.context, expiresAt: String(expiresAt) }, certificateVersion: '5' as const, messages: {}, confirmations: {} };
  account.dagPairingSessions = { pending: pairing, complete: { ...pairing, approval, sequence: 3 } };
  try {
    db.store.create(account);
    const persisted = JSON.parse(String(db.sql.rows('SELECT data FROM accounts')[0]!.data)) as Record<string, unknown>;
    assert.equal('sessions' in persisted, false);
    assert.equal('resetReceipt' in persisted, false);
    clock += 1;
    const current = db.store.read(account.id) as RecoveryDAGAccount;
    for (const key of ['sessions', 'deviceChallenges', 'emailProofs', 'bootChallenges', 'recoveryChallenges', 'notificationTickets'] as const) assert.deepEqual(current[key], []);
    assert.equal(current.resetReceipt, undefined);
    assert.equal(current.vaultInitializations!.pending, undefined);
    assert.equal(current.dagPairingSessions!.pending, undefined);
    assert.deepEqual(Object.values(current.vaultInitializations!), [complete]);
    assert.deepEqual(current.dagPairingSessions!.complete!.approval, approval);
    await assert.rejects(new VaultService(db.store, policy, () => clock).pull(account.id, auth('writer'), 0), rejects('unauthorized'));
    db.store.temporary.sweep();
    assert.equal(db.sql.rows('SELECT key FROM temporary_records').length, 0);
  } finally { db.sql.close(); }
});

test('Node timer clears multiple batches without reads; reopening resumes a persisted deadline', t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: now * 1000 });
  const dir = mkdtempSync(join(tmpdir(), 'harmonia-ttl-')), path = join(dir, 'synthetic.sqlite');
  let db = nodeStore(path);
  try {
    for (let n = 0; n < 300; n++) db.store.temporary.put({ namespace: 'probe', owner: '', key: String(n), value: n, expiresAt: now + 1 });
    db.store.temporary.changed(); db.sql.close();
    db = nodeStore(path);
    t.mock.timers.tick(1000);
    t.mock.timers.tick(1);
    assert.equal(db.sql.rows('SELECT key FROM temporary_records').length, 0);
    db.store.temporary.put({ namespace: 'probe', owner: '', key: 'offline', value: true, expiresAt: now + 2 });
    db.store.temporary.changed(); db.sql.close();
    t.mock.timers.tick(2000); db = nodeStore(path);
    assert.equal(db.sql.rows('SELECT key FROM temporary_records').length, 0);
  } finally { db.sql.close(); t.mock.timers.reset(); rmSync(dir, { recursive: true, force: true }); }
});
