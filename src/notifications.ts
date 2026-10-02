import { Fault, type Account, type Auth } from "./model.js";
import { bytes, generation, identifier } from "./protocol.js";
import { device, permission, randomToken, sameAccount, session, tokenHash } from "./service.js";
import type { Store } from "./store.js";
export interface NotificationTicket { ticketHash: string; sessionHash: string; accountGeneration: string; deviceId: string; expiresAt: number }
export interface NotificationIdentity { accountId: string; accountGeneration: string; deviceId: string; sessionHash: string }
export interface NotificationState extends NotificationIdentity { lastSequence: number }
export interface SequenceHint { accountId: string; accountGeneration: string; sequence: number }
export interface NotificationPeer { send(data: string): void; close(code: number, reason: string): void }
export const unix = (): number => Math.floor(Date.now() / 1000);
export function notificationPath(request: Request): string {
  const u = new URL(request.url);
  if (u.protocol !== "https:" && !(u.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname))) throw new Fault(400, "https_required");
  const m = u.pathname.match(/^\/v1\/accounts\/([A-Za-z0-9._:-]+)\/notifications$/);
  if (!m) throw new Fault(404, "not_found");
  if (u.search) throw new Fault(400, "query_forbidden");
  if (request.method !== "GET") throw new Fault(405, "method_not_allowed");
  if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") throw new Fault(426, "upgrade_required");
  return m[1]!;
}
export class NotificationAuthority {
  constructor(readonly store: Store, private readonly clock: () => number = unix) {}
  private current(a: Account, identity: NotificationIdentity): { hint: SequenceHint; expiresAt: number } {
    const now = this.clock(); sameAccount(a, identity.accountGeneration); device(a, identity.deviceId);
    const s = session(a, identity.sessionHash, now);
    if (s.deviceId !== identity.deviceId) throw new Fault(403, "device_proof_required");
    let latestGrantExpiry = 0;
    for (const env of Object.keys(a.environments)) {
      try { const g = permission(a, identity.deviceId, env, now); latestGrantExpiry = Math.max(latestGrantExpiry, g.expiresAt === "0" ? s.expiresAt : Math.min(s.expiresAt, Number(g.expiresAt))); }
      catch { /* 当前不可读环境不给通知订阅权 */ }
    }
    if (latestGrantExpiry <= now) throw new Fault(403, "environment_forbidden");
    return { hint: { accountId: a.id, accountGeneration: a.generation, sequence: a.sequence }, expiresAt: Math.min(s.expiresAt, latestGrantExpiry) };
  }
  check(identity: NotificationIdentity): { hint: SequenceHint; expiresAt: number } {
    const a = this.store.read(identity.accountId); if (!a) throw new Fault(401, "unauthorized");
    return this.current(a, identity);
  }
  async issue(accountId: string, auth: Auth): Promise<{ ticket: string; expiresAt: number; sequence: number }> {
    identifier(accountId); identifier(auth.deviceId); generation(auth.accountGeneration); bytes(auth.token, 32);
    const identity = { accountId, accountGeneration: auth.accountGeneration, deviceId: auth.deviceId, sessionHash: await tokenHash(auth.token) };
    const ticket = randomToken(), ticketHash = await tokenHash(ticket), now = this.clock();
    return this.store.transaction(accountId, a => {
      const current = this.current(a, identity), expiresAt = Math.min(now + 30, current.expiresAt);
      a.notificationTickets = (a.notificationTickets ?? []).filter(t => t.expiresAt > now);
      if (a.notificationTickets.length >= 32 || a.notificationTickets.filter(t => t.deviceId === auth.deviceId).length >= 4) throw new Fault(429, "notification_capacity_reached");
      a.notificationTickets.push({ ticketHash, sessionHash: identity.sessionHash, accountGeneration: a.generation, deviceId: auth.deviceId, expiresAt });
      return { ticket, expiresAt, sequence: a.sequence };
    });
  }
  async consume(accountId: string, auth: Auth): Promise<NotificationState> {
    identifier(accountId); identifier(auth.deviceId); generation(auth.accountGeneration); bytes(auth.token, 32);
    const hash = await tokenHash(auth.token);
    return this.store.transaction(accountId, a => {
      sameAccount(a, auth.accountGeneration);
      const t = a.notificationTickets?.find(t => t.ticketHash === hash && t.deviceId === auth.deviceId && t.accountGeneration === a.generation && t.expiresAt > this.clock());
      if (!t) throw new Fault(401, "notification_ticket_invalid");
      const state = { accountId, accountGeneration: a.generation, deviceId: auth.deviceId, sessionHash: t.sessionHash, lastSequence: -1 };
      this.current(a, state);
      a.notificationTickets = a.notificationTickets!.filter(other => other.ticketHash !== hash);
      return state;
    });
  }
  deliver(state: NotificationState, peer: NotificationPeer): { state: NotificationState; expiresAt: number } | undefined {
    try {
      // 无 await：读取同一权威状态后立即发送，不能在检查与发送间接受撤销。
      const current = this.check(state);
      if (current.hint.sequence !== state.lastSequence) peer.send(JSON.stringify(current.hint));
      return { state: { ...state, lastSequence: current.hint.sequence }, expiresAt: current.expiresAt };
    } catch { try { peer.close(4003, "authorization_required"); } catch { /* 已断线 */ } return; }
  }
}
