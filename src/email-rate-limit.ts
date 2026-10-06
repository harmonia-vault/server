import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { Fault } from "./model.js";
import type { Sql } from "./store.js";
import { TemporaryStore } from './temporary-store.js';

export const emailSendCooldown = 30;
export interface EmailLimitDecision { retryAfterSeconds: number; blocked: boolean }
export interface EmailRateLimit {
  reserve(emailKey: string, ipKey: string | undefined, now: number): Promise<EmailLimitDecision>;
}

// 仅由运行时传入可信 IP；不读取用户可以任意设置的转发头。
export function canonicalClientIP(value: string | null | undefined): string {
  if (!value || !isIP(value)) return "unknown";
  if (isIP(value) === 4) return value;
  const canonical = new URL(`http://[${value}]/`).hostname.slice(1, -1);
  const mapped = canonical.match(/^::ffff:([a-f0-9]+):([a-f0-9]+)$/);
  if (!mapped) return canonical;
  const high = parseInt(mapped[1]!, 16), low = parseInt(mapped[2]!, 16);
  return [high >> 8, high & 255, low >> 8, low & 255].join(".");
}

function limitKey(kind: string, value: string): string {
  return `${kind}:${createHash("sha256").update(value).digest("hex")}`;
}

// Keep proxy trust checks address-specific; only the mail limiter aggregates IPv6.
function emailIPScope(value: string): string {
  const address = canonicalClientIP(value);
  if (isIP(address) !== 6) return address;
  const [left, right] = address.split("::");
  const head = left ? left.split(":") : [];
  const tail = right ? right.split(":") : [];
  const groups = right === undefined
    ? head
    : [...head, ...Array<string>(8 - head.length - tail.length).fill("0"), ...tail];
  return `${groups.slice(0, 4).join(":")}::/64`;
}

export async function reserveEmailSend(limits: EmailRateLimit, email: string, ip: string | undefined, now: number): Promise<void> {
  const decision = await limits.reserve(limitKey("email", email), ip === undefined ? undefined : limitKey("ip", emailIPScope(ip)), now);
  if (decision.retryAfterSeconds > 0) {
    throw new Fault(429, decision.blocked ? "email_ip_blocked" : "email_request_limited", decision.retryAfterSeconds);
  }
}

interface LimitState { nextAt: number; blockedUntil: number; history: number[] }
export class SqlEmailRateLimit implements EmailRateLimit {
  constructor(private readonly sql: Sql, private readonly temporary: TemporaryStore) {}
  private read(key: string, now: number): LimitState {
    return this.temporary.get<LimitState>('email-limit', '', key, now) ?? { nextAt: 0, blockedUntil: 0, history: [] };
  }
  private write(key: string, state: LimitState, expiresAt: number): void {
    this.temporary.put({ namespace: 'email-limit', owner: '', key, value: state, expiresAt });
  }
  async reserve(emailKey: string, ipKey: string | undefined, now: number): Promise<EmailLimitDecision> {
    const decision = this.sql.transaction(() => {
      const email = this.read(emailKey, now), ip = ipKey ? this.read(ipKey, now) : undefined;
      const wait = Math.max(email.nextAt, ip?.nextAt ?? 0, ip?.blockedUntil ?? 0) - now;
      if (wait > 0) return { retryAfterSeconds: Math.ceil(wait), blocked: (ip?.blockedUntil ?? 0) > now };
      if (ip && ipKey) {
        ip.history = ip.history.filter(time => time > now - 3600);
        let blockSeconds = 0;
        if (ip.history.length >= 20) blockSeconds = 3600;
        else if (ip.history.filter(time => time > now - 600).length >= 5) blockSeconds = 900;
        if (blockSeconds) {
          ip.blockedUntil = now + blockSeconds;
          this.write(ipKey, ip, Math.max(ip.blockedUntil, (ip.history.at(-1) ?? now) + 3600));
          // 不在事务中抛错，否则刚写入的封禁会回滚。
          return { retryAfterSeconds: blockSeconds, blocked: true };
        }
        ip.nextAt = now + emailSendCooldown;
        ip.history.push(now);
        this.write(ipKey, ip, now + 3600);
      }
      this.write(emailKey, { nextAt: now + emailSendCooldown, blockedUntil: 0, history: [] }, now + emailSendCooldown);
      return { retryAfterSeconds: 0, blocked: false };
    });
    this.temporary.changed();
    return decision;
  }
}
