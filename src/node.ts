import { createServer } from "node:http";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { nodeStore } from "./node-store.js";
import { VaultService } from "./service.js";
import { route } from "./http.js";
const path = process.env.HARMONIA_DATABASE ?? "/data/harmonia.sqlite";
mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
const { store, sql } = nodeStore(path);
const service = new VaultService(store, {
  allowRegistration: process.env.HARMONIA_ALLOW_REGISTRATION === "true",
  requireEmailVerification: process.env.HARMONIA_REQUIRE_EMAIL_VERIFICATION !== "false",
});
// Bind loopback only; a TLS-terminating reverse proxy is required for remote access.
const server = createServer(async (incoming, outgoing) => {
 try {
  const chunks: Buffer[] = []; let size = 0;
  for await (const chunk of incoming) {
    size += Buffer.byteLength(chunk);
    if (size > 100_000) { outgoing.writeHead(413); outgoing.end(); incoming.destroy(); return; }
    chunks.push(Buffer.from(chunk));
  }
  const headers = new Headers();
  for (const [key, value] of Object.entries(incoming.headers)) if (value) headers.set(key, Array.isArray(value) ? value.join(", ") : value);
  const request = new Request(`http://127.0.0.1${incoming.url ?? "/"}`, { method: incoming.method ?? "GET", headers,
    ...(["GET", "HEAD"].includes(incoming.method ?? "GET") ? {} : { body: Buffer.concat(chunks) }) });
  const response = await route(request, service);
  outgoing.writeHead(response.status, Object.fromEntries(response.headers)); outgoing.end(Buffer.from(await response.arrayBuffer()));
 } catch { if (!outgoing.headersSent) outgoing.writeHead(400); outgoing.end(); }
});
if (process.env.HARMONIA_BIND && process.env.HARMONIA_BIND !== "127.0.0.1") throw new Error("remote_plain_http_binding_disabled");
server.listen(Number(process.env.HARMONIA_PORT ?? "8787"), "127.0.0.1");
function stop(): void { server.close(() => { sql.close(); process.exit(0); }); }
process.on("SIGTERM", stop); process.on("SIGINT", stop);
