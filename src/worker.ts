import { protocolInfoResponse, requestProtocolMajor, withProtocolMajor, protocolMajorHeader } from './protocol-info.js';
import { SqlRegistrationAuthority, instanceInfo, type RegistrationAuthority, type RegistrationAdmission, type RegistrationState } from "./registration.js";
import { DurableObject } from "cloudflare:workers";
import { SqlStore, type Sql } from "./store.js";
import { VaultService, normalizeEmail } from "./service.js";
import { bodyLimit, faultResponse, requestAuth, route } from "./http.js";
import { canonicalClientIP, SqlEmailRateLimit, type EmailRateLimit, type EmailLimitDecision } from "./email-rate-limit.js";
import { NotificationAuthority, notificationPath, type NotificationState } from "./notifications.js";
import { cloudflareEmail, type EmailTransport } from "./email-transport.js";
import { normalizeEmailCode } from "./email-code.js";
import { Fault } from "./model.js";
import { workerPassword } from "./worker-password.js";
import { credential } from "./password.js";
import { createHmac, randomBytes } from 'node:crypto';
import { TemporaryStore } from './temporary-store.js';
type Env = Omit<Cloudflare.Env, "EMAIL" | "INSTANCES"> & { EMAIL?: SendEmail; INSTANCES?: DurableObjectNamespace<InstanceRegistry> };
class DurableSql implements Sql {
  constructor(private readonly storage: DurableObjectStorage) {}
  execute(query: string, params: (string | number | null)[] = []): void { this.storage.sql.exec(query, ...params).toArray(); }
  rows(query: string, params: (string | number | null)[] = []): Record<string, unknown>[] { return this.storage.sql.exec(query, ...params).toArray(); }
  transaction<T>(operation: () => T): T { return this.storage.transactionSync(operation); }
}
// 跨账号的注册决定与邮件额度独立于账号；邮件额度只存哈希键和时间。
export class InstanceRegistry extends DurableObject<Env> {
  private readonly authority: SqlRegistrationAuthority;
  private readonly emailLimits: SqlEmailRateLimit;
  private readonly temporary: TemporaryStore;
  private readonly routingKey: string | undefined;
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    const sql = new DurableSql(ctx.storage);
    const state = sql.transaction(() => {
      const existing = sql.rows("SELECT name FROM sqlite_master WHERE type='table' AND name='instance_registration'").length > 0;
      const authority = new SqlRegistrationAuthority(sql), temporary = new TemporaryStore(sql);
      // 实例创建与路由密钥原子提交；旧实例不能被解释成新的账号空间。
      sql.execute('CREATE TABLE IF NOT EXISTS routing_key (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL)');
      if (!existing) sql.execute('INSERT INTO routing_key(id,value) VALUES(1,?)', [Buffer.from(randomBytes(32)).toString('hex')]);
      const routingKey = sql.rows('SELECT value FROM routing_key WHERE id=1')[0]?.value as string | undefined;
      return { authority, temporary, routingKey };
    });
    this.authority = state.authority;
    this.temporary = state.temporary;
    this.routingKey = state.routingKey;
    this.emailLimits = new SqlEmailRateLimit(sql, this.temporary);
    this.temporary.onChange(() => this.ctx.waitUntil(this.scheduleExpiry()));
    this.ctx.blockConcurrencyWhile(async () => {
      if (await this.ctx.storage.getAlarm() === null) { this.temporary.sweep(); await this.scheduleExpiry(); }
    });
  }
  async supportsFormat(): Promise<boolean> { return this.routingKey !== undefined; }
  private requireFormat(): string { if (!this.routingKey) throw new Fault(409, 'account_format_unsupported'); return this.routingKey; }
  async resolveAccount(email: string): Promise<string> { return createHmac('sha256', Buffer.from(this.requireFormat(), 'hex')).update(normalizeEmail(email)).digest('hex'); }
  private async scheduleExpiry(): Promise<void> {
    const deadline = this.temporary.nextExpiry();
    if (deadline === undefined) await this.ctx.storage.deleteAlarm();
    else await this.ctx.storage.setAlarm(Math.max(Date.now() + 1, deadline * 1000));
  }
  async alarm(): Promise<void> { this.temporary.sweep(); await this.scheduleExpiry(); }
  reserveEmail(emailKey: string, ipKey: string | undefined, now: number): Promise<EmailLimitDecision> {
    this.requireFormat();
    return this.emailLimits.reserve(emailKey, ipKey, now);
  }
  async info(): Promise<RegistrationState> { this.requireFormat(); return this.authority.info(); }
  async complete(accountId: string, admissionId: string, mode: RegistrationAdmission["mode"]): Promise<{ accepted: boolean }> { this.requireFormat(); return this.authority.complete(accountId, admissionId, mode); }
}
function instanceRegistry(env: Env): DurableObjectStub<InstanceRegistry> {
  if (!env.INSTANCES) throw new Fault(503, "instance_unavailable");
  return env.INSTANCES.getByName("harmonia-instance-v1");
}
function registrationAuthority(env: Env): RegistrationAuthority { return instanceRegistry(env); }
function emailRateLimit(env: Env): EmailRateLimit {
  if (!env.INSTANCES) throw new Fault(503, "instance_unavailable");
  const registry = env.INSTANCES.getByName("harmonia-instance-v1");
  return { reserve: (email, ip, now) => registry.reserveEmail(email, ip, now) };
}
export class AccountVault extends DurableObject<Env> {
  private readonly service: VaultService;
  private readonly notifications: NotificationAuthority;
  protected readonly store: SqlStore;
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    const store = new SqlStore(new DurableSql(ctx.storage), { info: () => registrationAuthority(env).info(), complete: (id, admission, mode) => registrationAuthority(env).complete(id, admission, mode) }, { reserve: (email, ip, now) => emailRateLimit(env).reserve(email, ip, now) });
    this.store = store;
    this.notifications = new NotificationAuthority(store);
    store.temporary.onChange(() => this.ctx.waitUntil(this.refreshNotifications()));
    this.service = new VaultService(store, { allowRegistration: env.ALLOW_REGISTRATION === "true", requireEmailVerification: env.REQUIRE_EMAIL_VERIFICATION !== "false" }, undefined, workerPassword, this.mailTransport(env));
    this.ctx.blockConcurrencyWhile(async () => {
      if (await this.ctx.storage.getAlarm() === null) { store.temporary.sweep(); await this.refreshNotifications(); }
    });
  }
  private async refreshNotifications(): Promise<void> {
    let deadline = this.store.temporary.nextExpiry() ?? Infinity;
    for (const ws of this.ctx.getWebSockets()) {
      if (ws.readyState !== 1) continue;
      const state = ws.deserializeAttachment() as NotificationState | null;
      if (!state) { ws.close(4003, "authorization_required"); continue; }
      const next = this.notifications.deliver(state, ws);
      if (next) { ws.serializeAttachment(next.state); deadline = Math.min(deadline, next.expiresAt); }
    }
    // 使用存储 alarm，不用常驻 interval 阻止 DO 休眠。alarm 仅调度，权限始终重读账号。
    await (Number.isFinite(deadline) ? this.ctx.storage.setAlarm(Math.max(Date.now() + 1, deadline * 1000)) : this.ctx.storage.deleteAlarm());
  }
  async fetch(request: Request): Promise<Response> {
    try {
      const accountId = notificationPath(request), credentials = requestAuth(request);
      const state = await this.notifications.consume(accountId, credentials);
      const active = this.ctx.getWebSockets().filter(ws => ws.readyState === 1);
      if (active.length >= 256 || active.filter(ws => (ws.deserializeAttachment() as NotificationState | null)?.deviceId === credentials.deviceId).length >= 4) throw new Fault(429, "notification_capacity_reached");
      const pair = new WebSocketPair();
      this.ctx.acceptWebSocket(pair[1]); pair[1].serializeAttachment(state); await this.refreshNotifications();
      return new Response(null, { status: 101, webSocket: pair[0], headers: { "cache-control": "no-store" } });
    } catch (error) { const f = error instanceof Fault ? error : new Fault(500, "internal_error"); return Response.json({ error: f.code }, { status: f.status, headers: { "cache-control": "no-store" } }); }
  }
  async alarm(): Promise<void> { this.store.temporary.sweep(); await this.refreshNotifications(); }
  webSocketMessage(ws: WebSocket): void {
    const state = ws.deserializeAttachment() as NotificationState | null;
    if (state) this.notifications.deliver(state, ws);
    ws.close(1008, "notifications_only");
  }
  webSocketClose(ws: WebSocket, code: number): void { try { ws.close(code === 4003 ? 4003 : 1000, "closed"); } catch { /* 已关闭 */ } this.ctx.waitUntil(this.refreshNotifications()); }
  webSocketError(ws: WebSocket): void { try { ws.close(1011, "reconnect_required"); } catch { /* 已关闭 */ } this.ctx.waitUntil(this.refreshNotifications()); }
  protected mailTransport(env: Env): EmailTransport | undefined { return cloudflareEmail(env.EMAIL, env.EMAIL_FROM); }
  async register(accountId: string, email: string, value: string, clientIP = "unknown"): Promise<{ status: number; headers: Record<string, string>; body: string }> {
    try { return { status: 200, headers: { "content-type": "application/json", "cache-control": "no-store" }, body: JSON.stringify(await this.service.register(email, value, accountId, clientIP)) }; }
    catch (error) {
      const response = faultResponse(error instanceof Fault ? error : new Fault(500, "internal_error"));
      return { status: response.status, headers: Object.fromEntries(response.headers), body: await response.text() };
    }
  }
  // RPC carries request primitives. Security is rechecked inside the account-local transaction.
  async handle(accountId: string, method: string, url: string, headers: [string, string][], payload: string | null, clientIP = "unknown"): Promise<{ status: number; headers: Record<string, string>; body: string }> {
    const parsed = new URL(url);
    const routed = parsed.pathname.match(/^\/v1\/accounts\/([^/]+)\//)?.[1];
    if (routed && routed !== accountId) return { status: 403, headers: {}, body: '{"error":"account_binding_invalid"}' };
    try {
      if (routed && !this.service.store.read(accountId)) {
        const error = parsed.pathname.endsWith('/email-verification/complete') ? 'registration_expired' : 'unauthorized';
        return { status: 401, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' }, body: JSON.stringify({ error }) };
      }
    } catch (error) {
      // 在 DO 内转成固定错误响应；RPC 序列化不会保留自定义 Fault 类型。
      const fault = error instanceof Fault ? error : new Fault(500, "internal_error");
      return { status: fault.status, headers: { "content-type": "application/json", "cache-control": "no-store" }, body: JSON.stringify({ error: fault.code }) };
    }
    const request = new Request(url, { method, headers, ...(payload === null ? {} : { body: payload }) });
    const response = await route(request, this.service, clientIP);
    return { status: response.status, headers: Object.fromEntries(response.headers), body: await response.text() };
  }
  // 没有直接种入可信设备或绕过邮件证明的重置 RPC；全部业务经统一路由校验。
}
async function workerFetch(request: Request, env: Env): Promise<Response> {
    try {
      const url = new URL(request.url);
      const clientIP = canonicalClientIP(request.headers.get("cf-connecting-ip"));
      if (url.protocol !== "https:" && !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)) throw new Fault(400, "https_required");
      if(url.pathname==="/protocol-info")return protocolInfoResponse(request);
      // 在 RPC 边界外返回固定错误，避免错误类型在序列化时丢失。
      if (['/instance-info', '/v1/register', '/v1/login', '/v1/email-verification/request', '/v1/account-reset/request', '/v1/account-reset/resolve'].includes(url.pathname)
        && !await instanceRegistry(env).supportsFormat()) throw new Fault(409, 'account_format_unsupported');
      if (url.pathname === "/instance-info") {
        if (request.method !== "GET") throw new Fault(405, "method_not_allowed");
        if (url.search) throw new Fault(400, "query_forbidden");
        return Response.json(await instanceInfo(registrationAuthority(env), { allowRegistration: env.ALLOW_REGISTRATION === "true", requireEmailVerification: env.REQUIRE_EMAIL_VERIFICATION !== "false" }), { headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" } });
      }
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
        const raw=Buffer.concat(chunks);
        if(/^\/v1\/accounts\/[^/]+\/(recovery-operation-resolutions-v1|recovery-authority-|recovered-|pairings-v[45])/.test(url.pathname)){
          try{payload=new TextDecoder("utf-8",{fatal:true}).decode(raw);}catch{throw new Fault(400,"json_invalid");}
        }else payload=raw.toString("utf8");
      }
      if (url.pathname === "/v1/register" && request.method === "POST") {
        const instance = await registrationAuthority(env).info();
        if (env.ALLOW_REGISTRATION !== "true" && instance.firstCompleted) throw new Fault(403, "registration_disabled");
        if (env.REQUIRE_EMAIL_VERIFICATION !== "false" && !cloudflareEmail(env.EMAIL, env.EMAIL_FROM)) throw new Fault(503, "email_verification_unavailable");
        if (!request.headers.get("content-type")?.startsWith("application/json")) throw new Fault(415, "json_required");
        let b: unknown; try { b = JSON.parse(payload ?? "null"); } catch { throw new Fault(400, "json_invalid"); }
        if (!b || typeof b !== "object" || !("email" in b) || typeof b.email !== "string" || !("credential" in b) || typeof b.credential !== "string") throw new Fault(400, "login_input_invalid");
        credential(b.credential); const email = normalizeEmail(b.email);
        const accountId = await instanceRegistry(env).resolveAccount(email);
        const reply = await env.ACCOUNTS.getByName(accountId).register(accountId, email, b.credential, clientIP);
        return new Response(reply.body, { status: reply.status, headers: reply.headers });
      }
      let accountId = url.pathname.match(/^\/v1\/accounts\/([A-Za-z0-9._:-]+)\//)?.[1];
      if (/^\/v1\/(?:email-verification\/request|account-reset\/(?:request|resolve))$/.test(url.pathname) && request.method === "POST") {
        const resolving = url.pathname.endsWith("/resolve");
        if (!resolving && !cloudflareEmail(env.EMAIL, env.EMAIL_FROM)) throw new Fault(503, "email_verification_unavailable");
        if (!request.headers.get("content-type")?.startsWith("application/json")) throw new Fault(415, "json_required");
        let b: unknown; try { b = JSON.parse(payload ?? "null"); } catch { throw new Fault(400, "json_invalid"); }
        if (!b || typeof b !== "object" || !("email" in b) || typeof b.email !== "string" || Object.keys(b).sort().join("|") !== (resolving ? "code|email" : "email")) throw new Fault(400, "fields_invalid");
        if (resolving && (!("code" in b) || typeof b.code !== "string" || !normalizeEmailCode(b.code))) throw new Fault(400, "email_code_invalid");
        accountId = await instanceRegistry(env).resolveAccount(normalizeEmail(b.email));
      }
      if (url.pathname === "/v1/login" && request.method === "POST") {
        if (!request.headers.get("content-type")?.startsWith("application/json")) throw new Fault(415, "json_required");
        let b: unknown; try { b = JSON.parse(payload ?? "null"); } catch { throw new Fault(400, "json_invalid"); }
        if (!b || typeof b !== "object" || !("email" in b) || typeof b.email !== "string" || !("credential" in b) || typeof b.credential !== "string") throw new Fault(400, "login_input_invalid");
        credential(b.credential);
        accountId = await instanceRegistry(env).resolveAccount(normalizeEmail(b.email));
      }
      if (!accountId) throw new Fault(404, "not_found");
      const reply = await env.ACCOUNTS.getByName(accountId).handle(accountId, request.method, request.url, Array.from(request.headers), payload, clientIP);
      return new Response(reply.body, { status: reply.status, headers: reply.headers });
    } catch (error) {
      const fault = error instanceof Fault ? error : new Fault(500, "internal_error");
      return faultResponse(fault);
    }
}
export default { async fetch(request:Request,env:Env):Promise<Response>{
 try{if (!["/protocol-info", "/health"].includes(new URL(request.url).pathname)) requestProtocolMajor(request);const response=await workerFetch(request,env);
 if(response.status===101){const headers=new Headers(response.headers);headers.set(protocolMajorHeader,"2");return new Response(null,{status:101,headers,webSocket:response.webSocket!});}
 return withProtocolMajor(response);
 }catch(error){const f=error instanceof Fault?error:new Fault(500,"internal_error");return withProtocolMajor(Response.json({error:f.code},{status:f.status,headers:{"cache-control":"no-store"}}));}
} } satisfies ExportedHandler<Env>;
