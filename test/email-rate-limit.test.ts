import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { IncomingMessage } from "node:http";
import { Socket } from "node:net";
import { nodeStore } from "../src/node-store.js";
import { VaultService } from "../src/service.js";
import { Fault } from "../src/model.js";
import { canonicalClientIP } from "../src/email-rate-limit.js";
import { incomingClientIP } from "../src/node-runtime.js";
import { route } from "../src/http.js";
import type { Email } from "../src/email-transport.js";
import { mailCode } from "./email-proof.js";

const credential = "ab".repeat(32), ipA = "192.0.2.1", ipB = "192.0.2.2";
function fixture() {
  const dir = mkdtempSync(join(tmpdir(), "harmonia-email-limits-")), path = join(dir, "db.sqlite");
  let db = nodeStore(path), now = 1800000000, failing = false;
  const mails: Email[] = [];
  const passwords = { hash: async (value: string) => `synthetic:${value}`, verify: async () => true };
  const mail = { send: async (message: Email) => { if (failing) throw new Error("synthetic mail failure"); mails.push(message); } };
  const service = () => new VaultService(db.store, { allowRegistration: true, requireEmailVerification: true }, () => now, passwords, mail);
  const send = (email: string, ip = ipA, purpose = "email-verification") => route(new Request(`https://service.example.invalid/v1/${purpose}/request`, {
    method: "POST", headers: {"Harmonia-Protocol-Major":"2", "content-type": "application/json", "x-forwarded-for": crypto.randomUUID() }, body: JSON.stringify({ email }),
  }), service(), ip);
  return { mails, service, send, get store() { return db.store; },
    register: (email: string, ip = ipA) => service().register(email, credential, undefined, ip),
    advance: (seconds: number) => { now += seconds; },
    failMail: (value: boolean) => { failing = value; },
    reopen: () => { db.sql.close(); db = nodeStore(path); },
    close: () => { db.sql.close(); rmSync(dir, { recursive: true, force: true }); },
  };
}
async function limited(response: Response, seconds: number, code = "email_request_limited") {
  assert.equal(response.status, 429);
  assert.equal(response.headers.get("retry-after"), String(seconds));
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.deepEqual(await response.json(), { error: code, retryAfterSeconds: seconds });
}

test("registration and resend share independent email/IP cooldowns; 30 seconds is accepted", async () => {
  const h = fixture();
  try {
    await h.register("target@example.invalid");
    await limited(await h.send("TARGET@example.invalid", ipB), 30);
    await limited(await h.send("other@example.invalid", ipA), 30);
    await assert.rejects(h.register("blocked@example.invalid", ipA), (error: unknown) => error instanceof Fault && error.retryAfterSeconds === 30);
    assert.equal(h.store.byEmail("blocked@example.invalid"), undefined);
    h.advance(13);
    await limited(await h.send("target@example.invalid", ipB), 17);
    h.advance(17);
    assert.equal((await h.send("target@example.invalid", ipB)).status, 200);
    assert.equal(h.mails.length, 2);
    await limited(await h.send("target@example.invalid", ipA, "account-reset"), 30);
  } finally { h.close(); }
});

test("parallel requests admit one email and cooldown survives SQLite reopen", async () => {
  const h = fixture();
  try {
    await h.register("concurrent@example.invalid"); h.advance(30);
    const replies = await Promise.all(Array.from({ length: 12 }, (_, i) => h.send("concurrent@example.invalid", `192.0.2.${i + 10}`)));
    assert.equal(replies.filter(reply => reply.status === 200).length, 1);
    assert.equal(replies.filter(reply => reply.status === 429).length, 11);
    assert.equal(h.mails.length, 2);
    h.reopen(); h.advance(7);
    await limited(await h.send("concurrent@example.invalid", ipB), 23);
    h.advance(23);
    assert.equal((await h.send("concurrent@example.invalid", ipB)).status, 200);
  } finally { h.close(); }
});

test("IP rolling burst quota persists a 15 minute ban; denied calls neither count nor extend it", async () => {
  const h = fixture();
  try {
    for (let i = 0; i < 5; i++) {
      assert.equal((await h.send(`burst-${i}@example.invalid`)).status, 200);
      for (let j = 0; j < 6; j++) await limited(await h.send(`denied-${i}-${j}@example.invalid`), 30);
      h.advance(30);
    }
    await limited(await h.send("sixth@example.invalid"), 900, "email_ip_blocked");
    h.reopen(); h.advance(120);
    await limited(await h.send("seventh@example.invalid"), 780, "email_ip_blocked");
    assert.equal((await h.send("sixth@example.invalid", ipB)).status, 200);
    h.advance(780);
    assert.equal((await h.send("after-ban@example.invalid")).status, 200);
  } finally { h.close(); }
});

test("IP hourly quota spans multiple ten-minute windows and bans for one hour", async () => {
  const h = fixture();
  try {
    for (let batch = 0; batch < 4; batch++) {
      for (let i = 0; i < 5; i++) {
        assert.equal((await h.send(`hour-${batch}-${i}@example.invalid`)).status, 200);
        h.advance(30);
      }
      h.advance(451);
    }
    await limited(await h.send("hour-over@example.invalid"), 3600, "email_ip_blocked");
    h.reopen(); h.advance(3599);
    await limited(await h.send("hour-over@example.invalid"), 1, "email_ip_blocked");
    h.advance(1);
    assert.equal((await h.send("hour-over@example.invalid")).status, 200);
  } finally { h.close(); }
});

test("mail failures retain quota; resending before the fixed deadline can finish registration", async () => {
  const h = fixture();
  try {
    const registered = await h.register("expired@example.invalid");
    h.advance(60); h.failMail(true);
    assert.equal((await h.send("expired@example.invalid")).status, 503);
    h.failMail(false);
    await limited(await h.send("expired@example.invalid", ipB), 30);
    h.advance(30);
    assert.equal((await h.send("expired@example.invalid", ipB)).status, 200);
    const verified = await route(new Request(`https://service.example.invalid/v1/accounts/${registered.accountId}/email-verification/complete`, {
      method: "POST", headers: {"Harmonia-Protocol-Major":"2", "content-type": "application/json" },
      body: JSON.stringify({ accountGeneration: registered.accountGeneration, code: mailCode(h.mails.at(-1)!) }),
    }), h.service(), ipB);
    assert.equal(verified.status, 200);
    assert.equal(h.store.read(registered.accountId)!.registrationAdmission!.state, "complete");
    await limited(await h.send("expired@example.invalid", ipA), 30);
  } finally { h.close(); }
});

test("IP normalization and explicit proxy trust prevent spoofed forwarded headers", () => {
  const socket = new Socket();
  Object.defineProperty(socket, "remoteAddress", { value: "::ffff:192.0.2.1" });
  const incoming = new IncomingMessage(socket);
  incoming.headers = { "x-real-ip": ipB, "x-forwarded-for": "192.0.2.3", "cf-connecting-ip": "192.0.2.4" };
  assert.equal(incomingClientIP(incoming), ipA);
  assert.equal(incomingClientIP(incoming, [ipA]), ipB);
  incoming.headers["x-real-ip"] = "192.0.2.2, 192.0.2.3";
  assert.equal(incomingClientIP(incoming, [ipA]), "unknown");
  assert.equal(canonicalClientIP("2001:0db8:0:0:0:0:0:1"), canonicalClientIP("2001:db8::1"));
  assert.equal(canonicalClientIP("::ffff:c000:201"), ipA);
});

test('IPv6 /64 shares cooldown and persistent bans across changing host addresses', async () => {
  const h = fixture();
  try {
    assert.equal((await h.send('v6-first@example.invalid', '2001:db8:abcd:1234::1')).status, 200);
    await limited(await h.send('v6-other@example.invalid', '2001:0db8:abcd:1234:ffff:ffff:ffff:ffff'), 30);
    assert.equal((await h.send('v6-next-subnet@example.invalid', '2001:db8:abcd:1235::1')).status, 200);
    for (let i = 1; i < 5; i++) {
      h.advance(30);
      assert.equal((await h.send(`v6-${i}@example.invalid`, `2001:db8:abcd:1234::${i + 1}`)).status, 200);
    }
    h.advance(30);
    await limited(await h.send('v6-over@example.invalid', '2001:db8:abcd:1234::abcd'), 900, 'email_ip_blocked');
    h.reopen(); h.advance(120);
    await limited(await h.send('v6-restarted@example.invalid', '2001:db8:abcd:1234:9876::1'), 780, 'email_ip_blocked');
    h.advance(780);
    assert.equal((await h.send('v6-after@example.invalid', '2001:db8:abcd:1234::8')).status, 200);
  } finally { h.close(); }
});

test('compressed IPv6 prefixes and IPv4-mapped addresses cannot split mail quotas', async () => {
  const h = fixture();
  try {
    assert.equal((await h.send('compressed@example.invalid', '2001:db8::1')).status, 200);
    await limited(await h.send('expanded@example.invalid', '2001:0db8:0000:0000:abcd:0:0:2'), 30);
    assert.equal((await h.send('mapped@example.invalid', '::ffff:192.0.2.1')).status, 200);
    await limited(await h.send('plain@example.invalid', '192.0.2.1'), 30);
    assert.equal((await h.send('different-v4@example.invalid', '192.0.2.2')).status, 200);
    const socket = new Socket();
    Object.defineProperty(socket, 'remoteAddress', { value: '2001:db8::2' });
    const incoming = new IncomingMessage(socket);
    incoming.headers = { 'x-real-ip': '192.0.2.9' };
    assert.equal(incomingClientIP(incoming, ['2001:db8::1']), '2001:db8::2');
  } finally { h.close(); }
});
