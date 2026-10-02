// 仅测试夹具：合成账号/设备密钥，绝不编译到生产 dist，不提供设备信任绕过路由。
import { createServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { nodeStore } from "../src/node-store.js";
import { VaultService } from "../src/service.js";
import { route } from "../src/http.js";
import { fixtureAccount, seeds, email, clientCredential } from "../test/fixtures.js";
const dir = mkdtempSync(join(tmpdir(), "harmonia-synthetic-http-"));
const { store, sql } = nodeStore(join(dir, "synthetic.sqlite"));
const a = await fixtureAccount(); a.sessions = []; store.create(a);
const service = new VaultService(store, { allowRegistration: false, requireEmailVerification: true });
const server = createServer(async (incoming, outgoing) => {
  const chunks: Buffer[] = []; let size = 0;
  for await (const chunk of incoming) { size += Buffer.byteLength(chunk); if (size > 100_000) { outgoing.writeHead(413); outgoing.end(); return; } chunks.push(Buffer.from(chunk)); }
  const headers = new Headers();
  for (const [key, value] of Object.entries(incoming.headers)) if (value) headers.set(key, Array.isArray(value) ? value.join(", ") : value);
  const request = new Request(`http://127.0.0.1${incoming.url ?? "/"}`, { method: incoming.method ?? "GET", headers,
    ...(["GET", "HEAD"].includes(incoming.method ?? "GET") ? {} : { body: Buffer.concat(chunks) }) });
  const response = await route(request, service); outgoing.writeHead(response.status, Object.fromEntries(response.headers)); outgoing.end(Buffer.from(await response.arrayBuffer()));
});
server.listen(0, "127.0.0.1", () => {
  const addr = server.address(); if (!addr || typeof addr === "string") throw new Error("invalid test bind");
  console.log(JSON.stringify({ endpoint: `http://127.0.0.1:${addr.port}`, accountId: a.id, accountGeneration: a.generation,
    email, credential: clientCredential, environmentId: "dev", keyVersion: "1", grantGeneration: "1",
    syntheticSigningSeeds: Object.fromEntries(Object.entries(seeds).map(([id, key]) => [id, Buffer.from(key).toString("base64url")])),
    devices: a.devices, grants: Object.values(a.grants) }));
});
function stop(): void { server.close(() => { sql.close(); rmSync(dir, { recursive: true, force: true }); process.exit(0); }); }
process.on("SIGTERM", stop); process.on("SIGINT", stop);
