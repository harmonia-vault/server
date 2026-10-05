import { Fault } from "./model.js";
import { body } from "./http.js";
import { LifecycleService } from "./lifecycle.js";
import type { RecoveryAuth } from "./lifecycle-wire.js";
import type { Store } from "./store.js";
function exact(value: Record<string, unknown>, names: string[]): void {
  if (Object.keys(value).sort().join("|") !== names.sort().join("|")) throw new Fault(400, "fields_invalid");
}
function text(value: unknown): string { if (typeof value !== "string") throw new Fault(400, "string_required"); return value; }
function auth(request: Request): RecoveryAuth {
  const token = request.headers.get("authorization")?.match(/^Bearer ([A-Za-z0-9_-]+)$/)?.[1];
  const accountGeneration = request.headers.get("x-harmonia-account-generation");
  const deviceId = request.headers.get("x-harmonia-device-id");
  if (!token || !accountGeneration) throw new Fault(401, "unauthorized");
  return { token, accountGeneration, ...(deviceId ? { deviceId } : {}) };
}
export async function lifecycleRoute(request: Request, store: Store): Promise<{ handled: boolean; result?: unknown }> {
  const url = new URL(request.url);
  const m = url.pathname.match(/^\/v1\/accounts\/([A-Za-z0-9._:-]+)\/(boot-challenges|boot-sessions|recovery-challenges|recovery-sessions)(?:\/([A-Za-z0-9._:-]+)(?:\/(complete))?)?$/);
  if (!m) return { handled: false };
  const accountId = m[1]!, op = m[2]!, operationId = m[3], completion = m[4]; const service = new LifecycleService(store);
  let result: unknown;
  if (request.method === "POST" && !operationId && op === "boot-challenges") {
    const b = await body(request); exact(b, ["deviceId", "accountGeneration"]);
    result = service.bootChallenge(accountId, text(b.deviceId), text(b.accountGeneration));
  } else if (request.method === "POST" && !operationId && op === "boot-sessions") {
    const b = await body(request); exact(b, ["deviceId", "accountGeneration", "challengeId", "signature"]);
    result = await service.bootSession(accountId, text(b.deviceId), text(b.accountGeneration), text(b.challengeId), text(b.signature));
  } else if (request.method === "POST" && !operationId && op === "recovery-challenges") {
    const b = await body(request); exact(b, ["accountGeneration"]); result = service.recoveryChallenge(accountId, text(b.accountGeneration));
  } else if (request.method === "POST" && !operationId && op === "recovery-sessions") {
    const b = await body(request); exact(b, ["accountGeneration", "challengeId", "signature"]);
    result = await service.recoverySession(accountId, text(b.accountGeneration), text(b.challengeId), text(b.signature));
  } else throw new Fault(405, "method_not_allowed");
  return { handled: true, result };
}
