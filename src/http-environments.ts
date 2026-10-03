import { Fault, type Auth } from "./model.js";
import { body } from "./http.js";
import { EnvironmentService, type SignedEnvironmentChange, type SignedEnvironmentChangeV2, type SignedDeviceRevocation } from "./environments.js";
import type { Store } from "./store.js";
function auth(request: Request): Auth {
  const token = request.headers.get("authorization")?.match(/^Bearer ([A-Za-z0-9_-]+)$/)?.[1];
  const deviceId = request.headers.get("x-harmonia-device-id"), accountGeneration = request.headers.get("x-harmonia-account-generation");
  if (!token || !deviceId || !accountGeneration) throw new Fault(401, "unauthorized");
  return { token, deviceId, accountGeneration };
}
export async function environmentRoute(request: Request, store: Store): Promise<{ handled: boolean; result?: unknown }> {
  const url = new URL(request.url);
  const m = url.pathname.match(/^\/v1\/accounts\/([A-Za-z0-9._:-]+)\/(environments|issuer-evidence|environment-changes|environment-changes-v2|environment-changes-v3|device-revocations)(?:\/([A-Za-z0-9._:-]+))?$/);
  if (!m) return { handled: false };
  if ((m[2] === "environment-changes-v2" || m[2] === "environment-changes-v3") && url.search) throw new Fault(400, "query_forbidden");
  const service = new EnvironmentService(store), accountId = m[1]!, op = m[2]!, key = m[3], credentials = auth(request);
  let result: unknown;
  if (op === "issuer-evidence") {
    const environmentId = url.searchParams.get("environmentId");
    if (request.method !== "GET" || key) throw new Fault(405, "method_not_allowed");
    if (!environmentId || url.searchParams.getAll("environmentId").length !== 1 || url.searchParams.getAll("capability").length !== 1 || !["issuer-origin-v1", "issuer-recovery-v1"].includes(url.searchParams.get("capability") ?? "") || [...url.searchParams.keys()].some(name => name !== "environmentId" && name !== "capability")) throw new Fault(400, "issuer_origin_capability_required");
    return { handled: true, result: await (url.searchParams.get("capability") === "issuer-recovery-v1" ? service.controlRecovery(accountId, credentials, environmentId) : service.control(accountId, credentials, environmentId)) };
  }
  if (request.method === "GET" && op === "environments" && !key) result = await service.list(accountId, credentials);
  else if (request.method === "POST" && op === "environment-changes" && !key) result = await service.change(accountId, credentials, await body(request, 1_000_000) as unknown as SignedEnvironmentChange);
  else if (request.method === "POST" && op === "environment-changes-v2" && !key) result = await service.changeV2(accountId, credentials, await body(request, 1_000_000) as unknown as SignedEnvironmentChangeV2);
  else if (request.method === "POST" && op === "environment-changes-v3" && !key) result = await service.changeV3(accountId, credentials, await body(request, 1_000_000) as unknown as SignedEnvironmentChangeV2);
  else if (request.method === "GET" && (op === "environment-changes" || op === "environment-changes-v2" || op === "environment-changes-v3") && key) result = await service.changeStatus(accountId, credentials, key, op === "environment-changes" ? "1" : "2");
  else if (request.method === "GET" && op === "device-revocations" && key) result = await service.revocationStatus(accountId, credentials, key);
  else if (request.method === "POST" && op === "device-revocations" && !key) {
    const b = await body(request);
    if (Object.keys(b).sort().join("|") !== "idempotencyKey|subjectDeviceId" || typeof b.idempotencyKey !== "string" || typeof b.subjectDeviceId !== "string") throw new Fault(400, "fields_invalid");
    result = await service.revocationChallenge(accountId, credentials, b.subjectDeviceId, b.idempotencyKey);
  } else if (request.method === "POST" && op === "device-revocations" && key === "complete") result = await service.revokeDevice(accountId, credentials, await body(request) as unknown as SignedDeviceRevocation);
  else throw new Fault(405, "method_not_allowed");
  return { handled: true, result };
}
