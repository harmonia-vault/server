import { DurableObject } from "cloudflare:workers";
import { SqlStore, type Sql } from "./store.js";
import { VaultService, normalizeEmail } from "./service.js";
import { bodyLimit, requestAuth, route } from "./http.js";
import { NotificationAuthority, notificationPath, type NotificationState } from "./notifications.js";
import { cloudflareEmail, type EmailTransport } from "./email-transport.js";
import { Fault } from "./model.js";
import { workerPassword } from "./worker-password.js";
import { credential, DUMMY_VERIFIER } from "./password.js";
type Env = Omit<Cloudflare.Env, "EMAIL"> & { EMAIL?: SendEmail };
class DurableSql implements Sql {
  constructor(private readonly storage: DurableObjectStorage) {}
  execute(query: string, params: (string | number | null)[] = []): void { this.storage.sql.exec(query, ...params).toArray(); }
  rows(query: string, params: (string | number | null)[] = []): Record<string, unknown>[] { return this.storage.sql.exec(query, ...params).toArray(); }
  transaction<T>(operation: () => T): T { return this.storage.transactionSync(operation); }
}
export class AccountVault extends DurableObject<Env> {
  private readonly service: VaultService;
  private readonly notifications: NotificationAuthority;
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    const store = new SqlStore(new DurableSql(ctx.storage));
    this.notifications = new NotificationAuthority(store);
    store.onCommit(() => this.ctx.waitUntil(this.refreshNotifications()));
    this.service = new VaultService(store, { allowRegistration: env.ALLOW_REGISTRATION === "true", requireEmailVerification: env.REQUIRE_EMAIL_VERIFICATION !== "false" }, undefined, workerPassword, this.mailTransport(env));
  }
  private async refreshNotifications(): Promise<void> {
    let deadline = Infinity;
    for (const ws of this.ctx.getWebSockets()) {
      if (ws.readyState !== 1) continue;
      const state = ws.deserializeAttachment() as NotificationState | null;
      if (!state) { ws.close(4003, "authorization_required"); continue; }
      const next = this.notifications.deliver(state, ws);
      if (next) { ws.serializeAttachment(next.state); deadline = Math.min(deadline, next.expiresAt); }
    }
    // 使用存储 alarm，不用常驻 interval 阻止 DO 休眠。alarm 仅调度，权限始终重读账号。
    await (Number.isFinite(deadline) ? this.ctx.storage.setAlarm(deadline * 1000) : this.ctx.storage.deleteAlarm());
  }
  async fetch(request: Request): Promise<Response> {
    try {
      const accountId = notificationPath(request), credentials = requestAuth(request), sockets = this.ctx.getWebSockets().filter(ws => ws.readyState === 1);
      if (sockets.length >= 256 || sockets.filter(ws => (ws.deserializeAttachment() as NotificationState | null)?.deviceId === credentials.deviceId).length >= 4) throw new Fault(429, "notification_capacity_reached");
      const state = await this.notifications.consume(accountId, credentials);
      const active = this.ctx.getWebSockets().filter(ws => ws.readyState === 1);
      if (active.length >= 256 || active.filter(ws => (ws.deserializeAttachment() as NotificationState | null)?.deviceId === credentials.deviceId).length >= 4) throw new Fault(429, "notification_capacity_reached");
      const pair = new WebSocketPair();
      this.ctx.acceptWebSocket(pair[1]); pair[1].serializeAttachment(state); await this.refreshNotifications();
      return new Response(null, { status: 101, webSocket: pair[0], headers: { "cache-control": "no-store" } });
    } catch (error) { const f = error instanceof Fault ? error : new Fault(500, "internal_error"); return Response.json({ error: f.code }, { status: f.status, headers: { "cache-control": "no-store" } }); }
  }
  async alarm(): Promise<void> { await this.refreshNotifications(); }
  webSocketMessage(ws: WebSocket): void {
    const state = ws.deserializeAttachment() as NotificationState | null;
    if (state) this.notifications.deliver(state, ws);
    ws.close(1008, "notifications_only");
  }
  webSocketClose(ws: WebSocket, code: number): void { try { ws.close(code === 4003 ? 4003 : 1000, "closed"); } catch { /* 已关闭 */ } this.ctx.waitUntil(this.refreshNotifications()); }
  webSocketError(ws: WebSocket): void { try { ws.close(1011, "reconnect_required"); } catch { /* 已关闭 */ } this.ctx.waitUntil(this.refreshNotifications()); }
  protected mailTransport(env: Env): EmailTransport | undefined { return cloudflareEmail(env.EMAIL, env.EMAIL_FROM); }
  async register(accountId: string, email: string, value: string): Promise<{ status: number; headers: Record<string, string>; body: string }> {
    try { return { status: 200, headers: { "content-type": "application/json", "cache-control": "no-store" }, body: JSON.stringify(await this.service.register(email, value, accountId)) }; }
    catch (error) { const fault = error instanceof Fault ? error : new Fault(500, "internal_error"); return { status: fault.status, headers: { "content-type": "application/json", "cache-control": "no-store" }, body: JSON.stringify({ error: fault.code }) }; }
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
  // 没有直接种入可信设备或绕过邮件证明的重置 RPC；全部业务经统一路由校验。
}
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const url = new URL(request.url);
      if (url.protocol !== "https:" && !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)) throw new Fault(400, "https_required");
      if (url.pathname === "/health") return Response.json({ status: "experimental", trustedEnrollment: false, registration: env.ALLOW_REGISTRATION === "true" }, { headers: { "cache-control": "no-store" } });
      const subscription = url.pathname.match(/^\/v1\/accounts\/([A-Za-z0-9._:-]+)\/notifications$/);
      if (subscription) { notificationPath(request); return env.ACCOUNTS.getByName(subscription[1]!).fetch(request); }
      let payload: string | null = null;
      if (request.body) {
        // Shared route enforces decoded body limits; this edge guard prevents pre-routing buffering.
        const reader = request.body.getReader(); const chunks: Uint8Array[] = []; let length = 0;
        try { while (true) { const p = await reader.read(); if (p.done) break; length += p.value.length;
          if (length > bodyLimit(request.method, url.pathname)) { await reader.cancel(); throw new Fault(413, "body_too_large"); } chunks.push(p.value); } }
        finally { reader.releaseLock(); }
        payload = Buffer.concat(chunks).toString("utf8");
      }
      if (url.pathname === "/v1/register" && request.method === "POST") {
        if (env.ALLOW_REGISTRATION !== "true") throw new Fault(403, "registration_disabled");
        if (env.REQUIRE_EMAIL_VERIFICATION !== "false" && !cloudflareEmail(env.EMAIL, env.EMAIL_FROM)) throw new Fault(503, "email_verification_unavailable");
        if (!request.headers.get("content-type")?.startsWith("application/json")) throw new Fault(415, "json_required");
        let b: unknown; try { b = JSON.parse(payload ?? "null"); } catch { throw new Fault(400, "json_invalid"); }
        if (!b || typeof b !== "object" || !("email" in b) || typeof b.email !== "string" || !("credential" in b) || typeof b.credential !== "string") throw new Fault(400, "login_input_invalid");
        credential(b.credential); const email = normalizeEmail(b.email), candidate = crypto.randomUUID();
        await env.DIRECTORY.prepare("CREATE TABLE IF NOT EXISTS account_directory (email TEXT PRIMARY KEY, account_id TEXT UNIQUE NOT NULL)").run();
        // D1 reserves only the routing identity. No credential, generation, permission or proof is duplicated here.
        await env.DIRECTORY.prepare("INSERT INTO account_directory(email,account_id) VALUES(?,?) ON CONFLICT(email) DO NOTHING").bind(email, candidate).run();
        const reserved = await env.DIRECTORY.prepare("SELECT account_id FROM account_directory WHERE email=?").bind(email).first<{ account_id: string }>();
        if (!reserved) throw new Fault(503, "directory_unavailable");
        const reply = await env.ACCOUNTS.getByName(reserved.account_id).register(reserved.account_id, email, b.credential);
        return new Response(reply.body, { status: reply.status, headers: reply.headers });
      }
      let accountId = url.pathname.match(/^\/v1\/accounts\/([A-Za-z0-9._:-]+)\//)?.[1];
      if (["/v1/email-verification/request", "/v1/account-reset/request"].includes(url.pathname) && request.method === "POST") {
        if (!cloudflareEmail(env.EMAIL, env.EMAIL_FROM)) throw new Fault(503, "email_verification_unavailable");
        if (!request.headers.get("content-type")?.startsWith("application/json")) throw new Fault(415, "json_required");
        let b: unknown; try { b = JSON.parse(payload ?? "null"); } catch { throw new Fault(400, "json_invalid"); }
        if (!b || typeof b !== "object" || !("email" in b) || typeof b.email !== "string" || Object.keys(b).join("|") !== "email") throw new Fault(400, "fields_invalid");
        const row = await env.DIRECTORY.prepare("SELECT account_id FROM account_directory WHERE email=?").bind(normalizeEmail(b.email)).first<{ account_id: string }>();
        accountId = row?.account_id;
        if (!accountId) return Response.json({ accepted: true }, { headers: { "cache-control": "no-store" } });
      }
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
