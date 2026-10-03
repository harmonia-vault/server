import { buildIssuerRecoveryEvidence, verifyIssuerRecoveryGraph, type IssuerRecoveryProof } from "./issuer-recovery.js";
import type { RecoveryAuthorityAccount } from "./recovery-authority.js";
import { buildIssuerEvidence, verifyIssuerOriginGraph, type IssuerOriginProof } from "./issuer-origin.js";
import { deviceRevocationBytes } from "./environments.js";
import { own, type EnrollmentAccount } from "./enrollment-wire.js";
import { issuerAuthorityHash } from "./issuer-proof.js";
import { Fault, grantKey, type Auth, type SignedGrant } from "./model.js";
import { bytes, generation, grantBytes, identifier, verify } from "./protocol.js";
import { device, permission, sameAccount, session, tokenHash } from "./service.js";
import type { Store } from "./store.js";

export interface OperationReceipt { idempotencyKey: string; accepted: boolean; sequence?: number; contentHash?: string }
export interface ManagementSubject {
  deviceId: string; signingPublicKey: string; receivingPublicKey: string;
  currentGrant: SignedGrant | null; highestGrantGeneration: string;
}
export interface ManagementControl {
  accountId: string; accountGeneration: string; environmentId: string; sequence: number; keyVersion: string;
  subjects: ManagementSubject[]; issuerEvidence: IssuerOriginProof;
}
export interface ManagementControlRecovery extends Omit<ManagementControl, "issuerEvidence"> {
  issuerEvidence: IssuerRecoveryProof;
}
/** 仅提供已接受授权的管理投影与本人操作回执，不建立新设备信任。 */
export class GrantManagementService {
  constructor(readonly store: Store, private readonly clock = () => Math.floor(Date.now() / 1000)) {}
  private async authenticated<T>(accountId: string, auth: Auth, operation: (account: EnrollmentAccount, now: number) => T): Promise<T> {
    identifier(accountId); identifier(auth.deviceId); generation(auth.accountGeneration); bytes(auth.token, 32);
    const hash = await tokenHash(auth.token);
    return this.store.transaction(accountId, raw => {
      const account = raw as EnrollmentAccount, now = this.clock(); sameAccount(account, auth.accountGeneration);
      const currentSession = session(account, hash, now); device(account, auth.deviceId);
      if (currentSession.deviceId !== auth.deviceId) throw new Fault(403, "device_proof_required");
      return operation(account, now);
    });
  }
  async status(accountId: string, auth: Auth, idempotencyKey: string): Promise<OperationReceipt> {
    identifier(idempotencyKey);
    const accepted = await this.authenticated(accountId, auth, account => own(account.idempotency, `grant/${auth.deviceId}/${idempotencyKey}`));
    if (!accepted) return { idempotencyKey, accepted: false };
    return { idempotencyKey, accepted: true, sequence: accepted.sequence, contentHash: await tokenHash(accepted.content) };
  }
  async revocationStatus(accountId: string, auth: Auth, idempotencyKey: string): Promise<OperationReceipt> {
    identifier(idempotencyKey);
    const record = await this.authenticated(accountId, auth, account => {
      const found = own(account.deviceRevocations, `${auth.deviceId}/${idempotencyKey}`);
      if (!found?.signature) return undefined;
      const r = found.revocation;
      if (r.accountId !== accountId || r.accountGeneration !== account.generation || r.deviceId !== auth.deviceId || !Number.isSafeInteger(found.sequence) || found.sequence! < 1) throw new Fault(403, "binding_invalid");
      return { sequence: found.sequence!, content: Buffer.from(deviceRevocationBytes(r)).toString("base64url") + "." + found.signature };
    });
    if (!record) return { idempotencyKey, accepted: false };
    return { idempotencyKey, accepted: true, sequence: record.sequence, contentHash: await tokenHash(record.content) };
  }
  async control(accountId: string, auth: Auth, environmentId: string): Promise<ManagementControl> {
    return this.controlWithProfile(accountId, auth, environmentId, "origin") as Promise<ManagementControl>;
  }
  async controlRecovery(accountId: string, auth: Auth, environmentId: string): Promise<ManagementControlRecovery> {
    return this.controlWithProfile(accountId, auth, environmentId, "recovery") as Promise<ManagementControlRecovery>;
  }
  private async controlWithProfile(accountId: string, auth: Auth, environmentId: string, profile: "origin" | "recovery") {
    identifier(environmentId);
    return this.authenticated(accountId, auth, (account, now) => {
      if (permission(account, auth.deviceId, environmentId, now).role !== "admin") throw new Fault(403, "admin_required");
      const devices = Object.values(account.devices).filter(device => !device.revoked).sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
      if (devices.length > 256) throw new Fault(413, "issuer_origin_too_large");
      const current = own(account.grants, grantKey(environmentId, auth.deviceId))!;
      const sources: SignedGrant[] = [current];
      const subjects: ManagementSubject[] = devices.map(subject => {
        identifier(subject.id);
        const history = (account.grantHistory ?? []).filter(event => event.grant.grant.environmentId === environmentId && event.grant.grant.subjectDeviceId === subject.id);
        let highest = 0n, highestHash = "";
        for (const event of history) {
          const g = event.grant.grant; grantBytes(g);
          if (g.accountId !== accountId || g.accountGeneration !== account.generation || g.subjectSigningPublicKey !== subject.signingPublicKey || g.subjectReceivingPublicKey !== subject.receivingPublicKey) throw new Fault(403, "issuer_archive_mismatch");
          const gg = BigInt(g.grantGeneration), h = issuerAuthorityHash(event.grant);
          if (gg === highest && highestHash !== h) throw new Fault(403, "issuer_authority_parent_mismatch");
          if (gg > highest) { highest = gg; highestHash = h; }
        }
        const grant = own(account.grants, grantKey(environmentId, subject.id));
        if (grant ? issuerAuthorityHash(grant) !== highestHash : highest !== 0n) throw new Fault(403, "issuer_authority_unaccepted");
        if (grant) {
          const accepted = history.find(event => issuerAuthorityHash(event.grant) === highestHash)!;
          if (grant.grant.role === "none") {
            // 撤销记录不是可授予权限的图节点；仅保留其冻结管理来源和独立签名。
            if (!accepted.authorization || accepted.originHash) throw new Fault(403, "issuer_authority_parent_mismatch");
            const parent = accepted.authorization.grant, g = grant.grant;
            if (parent.role !== "admin" || parent.accountId !== accountId || parent.accountGeneration !== account.generation || parent.subjectDeviceId !== g.issuerDeviceId || parent.environmentId !== environmentId || parent.keyVersion !== g.keyVersion) throw new Fault(403, "issuer_authority_parent_mismatch");
            sources.push(accepted.authorization);
          } else sources.push(grant);
        }
        return { deviceId: subject.id, signingPublicKey: subject.signingPublicKey, receivingPublicKey: subject.receivingPublicKey,
          currentGrant: grant ? structuredClone(grant) : null, highestGrantGeneration: String(highest) };
      });
      const identityIds = subjects.map(subject => subject.deviceId);
      const issuerEvidence = profile === "recovery"
        ? buildIssuerRecoveryEvidence(account as RecoveryAuthorityAccount, auth.deviceId, sources, [current], identityIds)
        : buildIssuerEvidence(account, auth.deviceId, sources, [current], identityIds);
      if (!issuerEvidence) throw new Fault(403, "issuer_origin_invalid");
      const graph = profile === "recovery" ? verifyIssuerRecoveryGraph(issuerEvidence as IssuerRecoveryProof) : verifyIssuerOriginGraph(issuerEvidence as IssuerOriginProof);
      for (const subject of subjects) {
        const identity = graph.identities.get(subject.deviceId);
        if (!identity || identity.signing !== subject.signingPublicKey || identity.receiving !== subject.receivingPublicKey) throw new Fault(403, "issuer_archive_mismatch");
        if (subject.currentGrant) {
          const issuer = graph.identities.get(subject.currentGrant.grant.issuerDeviceId);
          if (!issuer) throw new Fault(403, "issuer_archive_mismatch");
          verify(issuer.signing, grantBytes(subject.currentGrant.grant), subject.currentGrant.signature);
        }
      }
      return structuredClone({ accountId, accountGeneration: account.generation, environmentId, sequence: account.sequence,
        keyVersion: account.environments[environmentId]!.keyVersion, subjects, issuerEvidence });
    });
  }
}
