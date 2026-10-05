import type { Auth } from "./model.js";
import { Fault } from "./model.js";
import type { Store } from "./store.js";
import { bytes, generation, identifier } from "./protocol.js";
import { device, permission, sameAccount, session, tokenHash } from "./service.js";
import { stillCurrent } from './dag-enrollment.js';
import type { RecoveryDAGAccount } from './recovery-dag-account.js';
import { recoveryDAGCapability } from './recovery-dag-wire.js';
export interface PendingPairingMetadata { idempotencyKey: string; initiatorDeviceId: string; state: "pending" | "approved"; expiresAt: string }
export interface PendingPairings { accountGeneration: string; certificateVersion: "5"; capabilities: string[]; requests: PendingPairingMetadata[] }
/** 只读提示投影；没有独立的批准状态或可信身份来源。 */
export class PendingPairingService {
  constructor(readonly store: Store, private readonly clock = () => Math.floor(Date.now() / 1000)) {}
  async list(accountId: string, auth: Auth): Promise<PendingPairings> {
    identifier(accountId); identifier(auth.deviceId); generation(auth.accountGeneration); bytes(auth.token, 32);
    const hash = await tokenHash(auth.token);
    return this.store.transaction(accountId, raw => {
      const a = raw as RecoveryDAGAccount, now = this.clock(); sameAccount(a, auth.accountGeneration);
      const current = session(a, hash, now); device(a, auth.deviceId);
      if (current.deviceId !== auth.deviceId) throw new Fault(403, "device_proof_required");
      if (!Object.keys(a.environments).some(id => { try { return permission(a, auth.deviceId, id, now).role === "admin"; } catch (error) { if (error instanceof Fault) return false; throw error; } })) throw new Fault(403, "admin_required");
      const approver = a.devices[auth.deviceId]!, requests: PendingPairingMetadata[] = [];
      for (const [key, record] of Object.entries(a.dagPairingSessions ?? {})) {
        const c = record.context;
        if (record.certificateVersion !== "5" || record.sequence !== undefined || key !== record.idempotencyKey ||
          c.accountId !== a.id || c.accountGeneration !== a.generation || c.approverDeviceId !== auth.deviceId ||
          c.approverSigningPublicKey !== approver.signingPublicKey || c.approverReceivingPublicKey !== approver.receivingPublicKey ||
          BigInt(c.expiresAt) <= BigInt(now)) continue;
        const initiator = a.sessions.find(s => s.tokenHash === record.initiatorSessionHash && s.generation === a.generation && s.kind === "login" && s.expiresAt > now);
        if (!initiator || (initiator.deviceId && (!a.devices[initiator.deviceId] || a.devices[initiator.deviceId]!.revoked))) continue;
        if (record.approval) {
          try {
            stillCurrent(a, record, record.approval, now);
          } catch (error) { if (error instanceof Fault) continue; throw error; }
        }
        requests.push({ idempotencyKey: key, initiatorDeviceId: c.initiatorDeviceId, state: record.approval ? "approved" : "pending", expiresAt: c.expiresAt });
      }
      requests.sort((left, right) => BigInt(left.expiresAt) < BigInt(right.expiresAt) ? -1 : BigInt(left.expiresAt) > BigInt(right.expiresAt) ? 1 : left.idempotencyKey < right.idempotencyKey ? -1 : left.idempotencyKey > right.idempotencyKey ? 1 : 0);
      return { accountGeneration: a.generation, certificateVersion: "5", capabilities: [recoveryDAGCapability], requests: requests.slice(0, 64) };
    });
  }
}
