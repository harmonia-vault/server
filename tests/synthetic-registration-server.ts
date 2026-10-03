// 仅测试：全新空账号库，正式注册/初始化机制；不编译到dist、不种可信身份。
import { chmodSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { nodeStore } from "../src/node-store.js";
import { VaultService } from "../src/service.js";
import { nodeServer } from "../src/node-runtime.js";
import type { Email, EmailTransport } from "../src/email-transport.js";
const flags = new Set(process.argv.slice(2));
if ([...flags].some(flag => !["--allow-registration", "--require-email-verification", "--capture-email"].includes(flag))) throw new Error("synthetic_fixture_argument_invalid");
process.umask(0o077);
const dir = mkdtempSync(join(tmpdir(), "harmonia-registration-fixture-")); chmodSync(dir, 0o700);
const path = join(dir, "synthetic.sqlite"), { store, sql } = nodeStore(path); chmodSync(path, 0o600);
const emails: Email[] = [], capture = flags.has("--capture-email");
const mail: EmailTransport | undefined = capture ? { send: async message => { if (!message.to.endsWith(".invalid")) throw new Error("synthetic_recipient_required"); emails.push(message); } } : undefined;
const service = new VaultService(store, { allowRegistration: flags.has("--allow-registration"), requireEmailVerification: flags.has("--require-email-verification") }, undefined, undefined, mail);
const { server, closeNotifications } = nodeServer(service, async request => {
  const url = new URL(request.url);
  if (capture && url.pathname === "/test/emails") {
    if (request.method !== "GET" || url.search) return Response.json({ error: "synthetic_mail_request_invalid" }, { status: 400, headers: { "cache-control": "no-store" } });
    return Response.json(emails, { headers: { "cache-control": "no-store" } });
  }
  if (request.method === "POST" && ["/v1/register", "/v1/login", "/v1/email-verification/request", "/v1/account-reset/request"].includes(url.pathname)) {
    let input: unknown; try { input = await request.clone().json(); } catch { return undefined; }
    if (input && typeof input === "object" && "email" in input && typeof input.email === "string" && !input.email.endsWith(".invalid")) return Response.json({ error: "synthetic_recipient_required" }, { status: 400, headers: { "cache-control": "no-store" } });
  }
  return undefined;
});
server.listen(0, "127.0.0.1", () => {
  const address = server.address(); if (!address || typeof address === "string") throw new Error("synthetic_bind_invalid");
  // 只输出端口/合成邮箱捕获句柄；没有账号、凭据、token或钥匙。
  console.log(JSON.stringify({ port: address.port, mailboxPath: capture ? "/test/emails" : null }));
});
let stopping = false;
function stop(): void { if (stopping) return; stopping = true; closeNotifications(); server.closeAllConnections(); server.close(() => { sql.close(); rmSync(dir, { recursive: true, force: true }); process.exit(0); }); }
process.on("SIGTERM", stop); process.on("SIGINT", stop);
