import { Fault, type Auth, type SignedGrant } from "./model.js";
import { body } from "./http.js";
import type { VaultService } from "./service.js";
import { EnrollmentService, type LoginAuth, type PairingProposal, type Relay } from "./enrollment.js";
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
  const m = url.pathname.match(/^\/v1\/accounts\/([A-Za-z0-9._:-]+)\/(vault-initializations|pairings)(?:\/([A-Za-z0-9._:-]+)(?:\/(relay|approve|complete))?)?$/);
  if (!m) return { handled: false };
  const accountId = m[1]!, op = m[2]!, key = m[3], step = m[4];
  const service = new EnrollmentService(vault.store, vault.policy.requireEmailVerification), credentials = auth(request);
  let result: unknown;
  if (op === "vault-initializations") {
    if (request.method === "POST" && !key) result = await service.initialize(accountId, credentials, await body(request) as unknown as InitializationProposal);
    else if (request.method === "GET" && key && !step) result = await service.initializationStatus(accountId, credentials, key);
    else if (request.method === "POST" && key && step === "complete") {
      const b = await body(request); exact(b, ["challengeId", "deviceSignature", "recoverySignature"]);
      result = await service.completeInitialization(accountId, credentials, key, text(b.challengeId), text(b.deviceSignature), text(b.recoverySignature));
    } else throw new Fault(405, "method_not_allowed");
  } else {
    if (request.method === "POST" && !key) result = await service.beginPairing(accountId, credentials, await body(request) as unknown as PairingProposal);
    else if (request.method === "GET" && key && !step) result = await service.pairingStatus(accountId, credentials, key);
    else if (request.method === "POST" && key && step === "relay") result = await service.relay(accountId, credentials, key, await body(request) as unknown as Relay);
    else if (request.method === "POST" && key && step === "approve") {
      if (!credentials.deviceId) throw new Fault(403, "device_proof_required");
      const b = await body(request); exact(b, ["grants", "transcriptHash", "signature"]);
      result = await service.approve(accountId, credentials as Auth, key, { grants: b.grants as SignedGrant[], transcriptHash: text(b.transcriptHash), signature: text(b.signature) });
    } else if (request.method === "POST" && key && step === "complete") {
      const b = await body(request); exact(b, ["signature"]); result = await service.completePairing(accountId, credentials, key, text(b.signature));
    } else throw new Fault(405, "method_not_allowed");
  }
  return { handled: true, result };
}
