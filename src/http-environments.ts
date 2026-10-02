import { Fault, type Auth } from "./model.js";
import { body } from "./http.js";
import { EnvironmentService, type SignedEnvironmentChange, type SignedDeviceRevocation } from "./environments.js";
import type { Store } from "./store.js";
function auth(request: Request): Auth {
  const token = request.headers.get("authorization")?.match(/^Bearer ([A-Za-z0-9_-]+)$/)?.[1];
  const deviceId = request.headers.get("x-harmonia-device-id"), accountGeneration = request.headers.get("x-harmonia-account-generation");
  if (!token || !deviceId || !accountGeneration) throw new Fault(401, "unauthorized");
  return { token, deviceId, accountGeneration };
}
export async function environmentRoute(request: Request, store: Store): Promise<{ handled: boolean; result?: unknown }> {
  const m = new URL(request.url).pathname.match(/^\/v1\/accounts\/([A-Za-z0-9._:-]+)\/(environments|environment-changes|device-revocations)(?:\/([A-Za-z0-9._:-]+))?$/);
  if (!m) return { handled: false };
  const service = new EnvironmentService(store), accountId = m[1]!, op = m[2]!, key = m[3], credentials = auth(request);
  let result: unknown;
  if (request.method === "GET" && op === "environments" && !key) result = await service.list(accountId, credentials);
  else if (request.method === "POST" && op === "environment-changes" && !key) result = await service.change(accountId, credentials, await body(request, 1_000_000) as unknown as SignedEnvironmentChange);
  else if (request.method === "GET" && op === "environment-changes" && key) result = await service.changeStatus(accountId, credentials, key);
  else if (request.method === "GET" && op === "device-revocations" && key) result = await service.revocationStatus(accountId, credentials, key);
  else if (request.method === "POST" && op === "device-revocations" && !key) {
    const b = await body(request);
    if (Object.keys(b).sort().join("|") !== "idempotencyKey|subjectDeviceId" || typeof b.idempotencyKey !== "string" || typeof b.subjectDeviceId !== "string") throw new Fault(400, "fields_invalid");
    result = await service.revocationChallenge(accountId, credentials, b.subjectDeviceId, b.idempotencyKey);
  } else if (request.method === "POST" && op === "device-revocations" && key === "complete") result = await service.revokeDevice(accountId, credentials, await body(request) as unknown as SignedDeviceRevocation);
  else throw new Fault(405, "method_not_allowed");
  return { handled: true, result };
}
