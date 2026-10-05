import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build } from "esbuild";
import { Miniflare } from "miniflare";
import { emptyAccount } from "../src/account-lifecycle.js";
import type { InstanceRegistry } from "../src/worker.js";

test("workerd shares email/IP admission across account DOs and preserves bans after restart", { timeout: 120000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "harmonia-worker-mail-limits-"));
  const bundle = await build({ entryPoints: ["test/worker-harness.ts"], bundle: true, write: false,
    format: "esm", platform: "browser", target: "es2023", external: ["cloudflare:workers", "node:*"],
    banner: { js: 'import { Buffer } from "node:buffer";' } });
  const options = { modules: true as const, script: bundle.outputFiles[0]!.text,
    compatibilityDate: "2026-07-30", compatibilityFlags: ["nodejs_compat"],
    durableObjects: { INSTANCES: { className: "InstanceRegistry", useSQLite: true }, ACCOUNTS: { className: "SyntheticVault", useSQLite: true }, FIXTURES: { className: "SyntheticVault", useSQLite: true } },
    d1Databases: { DIRECTORY: "directory" }, durableObjectsPersist: join(dir, "objects"), d1Persist: join(dir, "d1"),
    bindings: { ALLOW_REGISTRATION: "true", REQUIRE_EMAIL_VERIFICATION: "true", EMAIL_FROM: "noreply@example.invalid" },
  };
  let mf = new Miniflare(options);
  const post = (path: string, body: unknown, ip: string) => mf.dispatchFetch(`https://selfhost.example.invalid${path}`, {
    method: "POST", headers: {"Harmonia-Protocol-Major":"2", "content-type": "application/json", "cf-connecting-ip": ip }, body: JSON.stringify(body),
  });
  const request = (email: string, ip: string, purpose = "email-verification") => post(`/v1/${purpose}/request`, { email }, ip);
  const registry = async () => (await mf.getDurableObjectNamespace("INSTANCES")).getByName("harmonia-instance-v1") as unknown as DurableObjectStub<InstanceRegistry>;
  try {
    for (const id of ["mail-a", "mail-b"]) {
      assert.equal((await post("/test/seed", emptyAccount(id, `${id}@example.invalid`, "1", "synthetic-verifier", { verificationRequiredAtRegistration: false, registrationAdmission: { id: `registration-${id}`, mode: "open", state: "complete", readyAt: 1, expiresAt: 900 } }), "192.0.2.1")).status, 200);
    }
    assert.equal((await request("mail-a@example.invalid", "192.0.2.1")).status, 200);
    const byIP = await request("mail-b@example.invalid", "192.0.2.1");
    assert.equal(byIP.status, 429);
    assert.ok(Number(byIP.headers.get("retry-after")) > 0);
    assert.equal((await request("MAIL-A@example.invalid", "192.0.2.2")).status, 429);
    assert.equal((await request("mail-b@example.invalid", "192.0.2.2")).status, 200);
    assert.equal((await request("absent@example.invalid", "192.0.2.3")).status, 200);
    assert.equal((await request("absent@example.invalid", "192.0.2.4", "account-reset")).status, 429);
    assert.equal((await request("ipv6-first@example.invalid", "2001:db8:ab:cd::1")).status, 200);
    assert.equal((await request("ipv6-second@example.invalid", "2001:0db8:ab:cd:ffff::2")).status, 429);
    assert.equal((await request("ipv6-subnet@example.invalid", "2001:db8:ab:ce::1")).status, 200);
    const key = (kind: string, value: string) => `${kind}:${createHash("sha256").update(value).digest("hex")}`;
    const now = Math.floor(Date.now() / 1000), ipKey = key("ip", "192.0.2.99");
    const limits = await registry();
    for (let i = 0; i < 5; i++) {
      assert.equal((await limits.reserveEmail(key("email", `worker-${i}@example.invalid`), ipKey, now - 150 + i * 30)).retryAfterSeconds, 0);
    }
    const ban = await request("worker-sixth@example.invalid", "192.0.2.99");
    assert.equal(ban.status, 429);
    assert.equal((await ban.json() as { error: string }).error, "email_ip_blocked");
    await mf.dispose(); mf = new Miniflare(options);
    const persisted = await request("after-restart@example.invalid", "192.0.2.99");
    assert.equal(persisted.status, 429);
    const body = await persisted.json() as { error: string; retryAfterSeconds: number };
    assert.equal(body.error, "email_ip_blocked");
    assert.ok(body.retryAfterSeconds > 850 && body.retryAfterSeconds <= 900);
  } finally { await mf.dispose(); rmSync(dir, { recursive: true, force: true }); }
});
