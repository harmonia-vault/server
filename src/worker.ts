import { DurableObject } from "cloudflare:workers";
import { SqlStore, type Sql } from "./store.js";
import { VaultService, normalizeEmail } from "./service.js";
import { route } from "./http.js";
import { Fault } from "./model.js";
import { workerPassword } from "./worker-password.js";
import { credential, DUMMY_VERIFIER } from "./password.js";
type Env = Cloudflare.Env;
class DurableSql implements Sql {
  constructor(private readonly storage: DurableObjectStorage) {}
  execute(query: string, params: (string | number | null)[] = []): void { this.storage.sql.exec(query, ...params).toArray(); }
  rows(query: string, params: (string | number | null)[] = []): Record<string, unknown>[] { return this.storage.sql.exec(query, ...params).toArray(); }
  transaction<T>(operation: () => T): T { return this.storage.transactionSync(operation); }
}
export class AccountVault extends DurableObject<Env> {
  private readonly service: VaultService;
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    const store = new SqlStore(new DurableSql(ctx.storage));
    this.service = new VaultService(store, { allowRegistration: false, requireEmailVerification: env.REQUIRE_EMAIL_VERIFICATION !== "false" }, undefined, workerPassword);
  }
  // RPC carries request primitives. Security is rechecked inside the account-local transaction.
  async handle(accountId: string, method: string, url: string, headers: [string, string][], payload: string | null): Promise<{ status: number; headers: Record<string, string>; body: string }> {
    const parsed = new URL(url);
    const routed = parsed.pathname.match(/^\/v1\/accounts\/([^/]+)\//)?.[1];
    if (routed && routed !== accountId) return { status: 403, headers: {}, body: '{"error":"account_binding_invalid"}' };
    if (!this.service.store.read(accountId)) return { status: 401, headers: {}, body: '{"error":"unauthorized"}' };
    const request = new Request(url, { method, headers, ...(payload === null ? {} : { body: payload }) });
    const response = await route(request, this.service);
    return { status: response.status, headers: Object.fromEntries(response.headers), body: await response.text() };
  }
  // No enrollment, trusted-device seed or reset RPC is exposed.
}
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const url = new URL(request.url);
      if (url.protocol !== "https:" && !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)) throw new Fault(400, "https_required");
      if (url.pathname === "/health") return Response.json({ status: "experimental", trustedEnrollment: false, registration: false }, { headers: { "cache-control": "no-store" } });
      if (url.pathname === "/v1/register") throw new Fault(env.ALLOW_REGISTRATION === "true" ? 503 : 403, env.ALLOW_REGISTRATION === "true" ? "worker_registration_unavailable" : "registration_disabled");
      let payload: string | null = null;
      if (request.body) {
        // Shared route enforces decoded body limits; this edge guard prevents pre-routing buffering.
        const reader = request.body.getReader(); const chunks: Uint8Array[] = []; let length = 0;
        try { while (true) { const p = await reader.read(); if (p.done) break; length += p.value.length;
          if (length > 100000) { await reader.cancel(); throw new Fault(413, "body_too_large"); } chunks.push(p.value); } }
        finally { reader.releaseLock(); }
        payload = Buffer.concat(chunks).toString("utf8");
      }
      let accountId = url.pathname.match(/^\/v1\/accounts\/([A-Za-z0-9._:-]+)\/(pull|mutations|grants|device-challenges|device-sessions)$/)?.[1];
      if (url.pathname === "/v1/login" && request.method === "POST") {
        if (!request.headers.get("content-type")?.startsWith("application/json")) throw new Fault(415, "json_required");
        let b: unknown; try { b = JSON.parse(payload ?? "null"); } catch { throw new Fault(400, "json_invalid"); }
        if (!b || typeof b !== "object" || !("email" in b) || typeof b.email !== "string" || !("credential" in b) || typeof b.credential !== "string") throw new Fault(400, "login_input_invalid");
        credential(b.credential);
        // D1 only maps email to account. Verifiers, generations, grants and tokens live exclusively in the DO.
        const row = await env.DIRECTORY.prepare("SELECT account_id FROM account_directory WHERE email=?").bind(normalizeEmail(b.email)).first<{ account_id: string }>();
        accountId = row?.account_id;
        if (!accountId) { await workerPassword.verify(b.credential, DUMMY_VERIFIER); throw new Fault(401, "unauthorized"); }
      }
      if (!accountId) throw new Fault(404, "not_found");
      const reply = await env.ACCOUNTS.getByName(accountId).handle(accountId, request.method, request.url, Array.from(request.headers), payload);
      return new Response(reply.body, { status: reply.status, headers: reply.headers });
    } catch (error) {
      const fault = error instanceof Fault ? error : new Fault(500, "internal_error");
      return Response.json({ error: fault.code }, { status: fault.status, headers: { "cache-control": "no-store" } });
    }
  },
} satisfies ExportedHandler<Env>;
