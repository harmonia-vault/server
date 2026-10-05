import { Fault } from "./model.js";
import { requestAuth } from "./http.js";
import { GrantManagementService } from "./grant-management.js";
import type { Store } from "./store.js";
export async function grantManagementRoute(request: Request, store: Store): Promise<{ handled: boolean; result?: unknown }> {
  const url = new URL(request.url), match = url.pathname.match(/^\/v1\/accounts\/([A-Za-z0-9._:-]+)\/(grant-status|device-revocation-status|grant-management)$/);
  if (!match) return { handled: false };
  if (request.method !== "GET") throw new Fault(405, "method_not_allowed");
  const service = new GrantManagementService(store), credentials = requestAuth(request), accountId = match[1]!;
  if (match[2] === "grant-status" || match[2] === "device-revocation-status") {
    if ([...url.searchParams.keys()].join("|") !== "idempotencyKey") throw new Fault(400, "query_invalid");
    return { handled: true, result: await (match[2] === "grant-status" ? service.status(accountId, credentials, url.searchParams.get("idempotencyKey")!) : service.revocationStatus(accountId, credentials, url.searchParams.get("idempotencyKey")!)) };
  }
  const env = url.searchParams.get("environmentId");
  if (!env || url.searchParams.getAll("environmentId").length !== 1 || url.searchParams.getAll("capability").length !== 1 || url.searchParams.get("capability") !== "issuer-recovery-dag-v1" || [...url.searchParams.keys()].some(name => name !== "environmentId" && name !== "capability")) throw new Fault(400, "issuer_origin_capability_required");
  return { handled: true, result: await service.controlDAG(accountId, credentials, env) };
}
