// 仅测试夹具：合成账号/设备密钥，绝不编译到生产 dist，不提供设备信任绕过路由。
import type { Email, EmailTransport } from "../src/email-transport.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { canonical, trustRootPayload, type TrustRoot } from "../src/lifecycle-wire.js";
import { createServer } from "node:http";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { nodeStore } from "../src/node-store.js";
import { VaultService } from "../src/service.js";
import { route } from "../src/http.js";
import { fixtureAccount, seeds, email, clientCredential, recoverySeed, recoveryKeys } from "../test/fixtures.js";
const dir = mkdtempSync(join(tmpdir(), "harmonia-synthetic-http-"));
const { store, sql } = nodeStore(join(dir, "synthetic.sqlite"));
const a = await fixtureAccount(); a.sessions = [];
const fixtureArg = process.argv.indexOf("--recovery-envelopes");
if (fixtureArg >= 0) {
  const entries = JSON.parse(readFileSync(process.argv[fixtureArg + 1]!, "utf8")) as { environmentId: string; envelope: string }[];
  for (const e of entries) { if (!Object.hasOwn(a.environments, e.environmentId)) throw new Error("unknown synthetic environment"); a.environments[e.environmentId]!.recoveryEnvelope = e.envelope; }
}
if (process.argv.includes("--with-trust-root")) {
  const rec = recoveryKeys(recoverySeed, a.id), root: TrustRoot = { rootDeviceId: "admin", rootSigningPublicKey: a.devices.admin!.signingPublicKey,
    rootReceivingPublicKey: a.devices.admin!.receivingPublicKey, recoveryGeneration: a.recoveryGeneration,
    recoverySigningPublicKey: rec.signingPublicKey, recoveryReceivingPublicKey: rec.receivingPublicKey, signature: "" };
  root.signature = Buffer.from(ed25519.sign(canonical(trustRootPayload(a.id, a.generation, root)), rec.signingSeed)).toString("base64url"); a.trustRoot = root;
}
if (process.argv.includes("--empty-vault")) {
  // 测试首次管理手机初始化：保留合成登录账户，不能沿用任何夹具设备权限。
  a.devices = {}; a.environments = {}; a.grants = {}; a.grantHistory = []; a.events = []; a.sequence = 0;
  a.recoveryGeneration = "0"; a.recoverySigningPublicKey = null; delete a.recoveryReceivingPublicKey; delete a.trustRoot;
}
store.create(a);
const capturedEmails: Email[] = [], capture = process.argv.includes("--capture-email");
const mail: EmailTransport | undefined = capture ? { send: async message => { if (!message.to.endsWith(".invalid")) throw new Error("only synthetic recipient allowed"); capturedEmails.push(message); } } : undefined;
const service = new VaultService(store, { allowRegistration: capture, requireEmailVerification: true }, undefined, undefined, mail);
const server = createServer(async (incoming, outgoing) => {
  const chunks: Buffer[] = []; let size = 0;
  for await (const chunk of incoming) { size += Buffer.byteLength(chunk); if (size > 100_000) { outgoing.writeHead(413); outgoing.end(); return; } chunks.push(Buffer.from(chunk)); }
  const headers = new Headers();
  for (const [key, value] of Object.entries(incoming.headers)) if (value) headers.set(key, Array.isArray(value) ? value.join(", ") : value);
  const request = new Request(`http://127.0.0.1${incoming.url ?? "/"}`, { method: incoming.method ?? "GET", headers,
    ...(["GET", "HEAD"].includes(incoming.method ?? "GET") ? {} : { body: Buffer.concat(chunks) }) });
  const response = capture && incoming.method === "GET" && incoming.url === "/test/emails" ? Response.json(capturedEmails, { headers: { "cache-control": "no-store" } }) : await route(request, service); outgoing.writeHead(response.status, Object.fromEntries(response.headers)); outgoing.end(Buffer.from(await response.arrayBuffer()));
});
server.listen(0, "127.0.0.1", () => {
  const addr = server.address(); if (!addr || typeof addr === "string") throw new Error("invalid test bind");
  console.log(JSON.stringify({ endpoint: `http://127.0.0.1:${addr.port}`, accountId: a.id, accountGeneration: a.generation,
    email, credential: clientCredential, environmentId: "dev", keyVersion: "1", grantGeneration: "1",
    syntheticSigningSeeds: Object.fromEntries(Object.entries(seeds).map(([id, key]) => [id, Buffer.from(key).toString("base64url")])),
    devices: a.devices, grants: Object.values(a.grants), recoveryGeneration: a.recoveryGeneration,
    recoverySigningPublicKey: a.recoverySigningPublicKey, recoveryReceivingPublicKey: a.recoveryReceivingPublicKey,
    trustRoot: a.trustRoot ?? null, emailCapture: capture, syntheticRecoverySeed: Buffer.from(recoverySeed).toString("base64url") }));
});
function stop(): void { server.close(() => { sql.close(); rmSync(dir, { recursive: true, force: true }); process.exit(0); }); }
process.on("SIGTERM", stop); process.on("SIGINT", stop);
