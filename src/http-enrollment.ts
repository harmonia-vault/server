import { Fault, type Auth, type SignedGrant } from "./model.js";
import { strictRecoveryBody } from "./strict-recovery-body.js";
import { body } from "./http.js";
import type { VaultService } from "./service.js";
import { EnrollmentService, type LoginAuth, type PairingProposal, type ApprovalRequestV2, type ApprovalRequestV3, type ApprovalRequestV4, type Relay } from "./enrollment.js";
import { exact, type InitializationProposal } from "./enrollment-wire.js";
function text(value: unknown): string { if (typeof value !== "string") throw new Fault(400, "string_required"); return value; }
function auth(request: Request): LoginAuth & { deviceId?: string } {
  const token = request.headers.get("authorization")?.match(/^Bearer ([A-Za-z0-9_-]+)$/)?.[1];
  const accountGeneration = request.headers.get("x-harmonia-account-generation"), deviceId = request.headers.get("x-harmonia-device-id");
  if (!token || !accountGeneration) throw new Fault(401, "unauthorized");
  return { token, accountGeneration, ...(deviceId ? { deviceId } : {}) };
}
export async function enrollmentRoute(request: Request, vault: VaultService): Promise<{ handled: boolean; result?: unknown }> {
  const url = new URL(request.url);
  const m = url.pathname.match(/^\/v1\/accounts\/([A-Za-z0-9._:-]+)\/(vault-initializations|pairings|pairings-v2|pairings-v3|pairings-v4)(?:\/([A-Za-z0-9._:-]+)(?:\/(relay|approve|complete))?)?$/);
  if (!m) return { handled: false };
  const accountId = m[1]!, op = m[2]!, key = m[3], step = m[4];
  const version = op === "pairings-v4" ? "4" : op === "pairings-v3" ? "3" : op === "pairings-v2" ? "2" : "1";
  if (version !== "1" && url.search) throw new Fault(400, "query_forbidden");
  const service = new EnrollmentService(vault.store), credentials = auth(request);
  let result: unknown;
  if (op === "vault-initializations") {
    if (request.method === "POST" && !key) result = await service.initialize(accountId, credentials, await body(request) as unknown as InitializationProposal);
    else if (request.method === "GET" && key && !step) result = await service.initializationStatus(accountId, credentials, key);
    else if (request.method === "POST" && key && step === "complete") {
      const b = await body(request); exact(b, ["challengeId", "deviceSignature", "recoverySignature"]);
      result = await service.completeInitialization(accountId, credentials, key, text(b.challengeId), text(b.deviceSignature), text(b.recoverySignature));
    } else throw new Fault(405, "method_not_allowed");
  } else {
    if (request.method === "POST" && !key) result = await service.beginPairing(accountId, credentials, await body(request) as unknown as PairingProposal, version);
    else if (request.method === "GET" && key && !step) result = await service.pairingStatus(accountId, credentials, key, version);
    else if (request.method === "POST" && key && step === "relay") result = await service.relay(accountId, credentials, key, await body(request) as unknown as Relay, version);
    else if (request.method === "POST" && key && step === "approve") {
      if (!credentials.deviceId) throw new Fault(403, "device_proof_required");
      const b = version === "4" ? await strictRecoveryBody(request) : await body(request, version === "3" ? 1_000_000 : version === "2" ? 262144 : 100000);
      if(version==="4")result=await service.approveV4(accountId,credentials as Auth,key,b as unknown as ApprovalRequestV4);
      else if (version === "3") result = await service.approveV3(accountId, credentials as Auth, key, b as unknown as ApprovalRequestV3);
      else if (version === "2") result = await service.approveV2(accountId, credentials as Auth, key, b as unknown as ApprovalRequestV2);
      else { exact(b, ["grants", "transcriptHash", "signature"]); result = await service.approve(accountId, credentials as Auth, key, { grants: b.grants as SignedGrant[], transcriptHash: text(b.transcriptHash), signature: text(b.signature) }); }
    } else if (request.method === "POST" && key && step === "complete") {
      const b = await body(request); exact(b, ["signature"]); result = await service.completePairing(accountId, credentials, key, text(b.signature), version);
    } else throw new Fault(405, "method_not_allowed");
  }
  return { handled: true, result };
}
