import { Fault, type Auth, type SignedGrant, type SignedMutation } from "./model.js";
import type { VaultService } from "./service.js";
import { accountRoute } from "./http-account.js";
import { lifecycleRoute } from "./http-lifecycle.js";
import { enrollmentRoute } from "./http-enrollment.js";
import { NotificationAuthority } from "./notifications.js";
import { environmentRoute } from "./http-environments.js";
export function bodyLimit(method: string, pathname: string): number {
  return method === "POST" && /^\/v1\/accounts\/[A-Za-z0-9._:-]+\/environment-changes$/.test(pathname) ? 1_000_000 : 100_000;
}
export async function body(request: Request, maxBody = 100_000): Promise<Record<string, unknown>> {
  if (!Number.isSafeInteger(maxBody) || maxBody <= 0 || maxBody > 1_000_000) throw new Fault(500, "body_limit_invalid");
  if (!request.headers.get("content-type")?.startsWith("application/json")) throw new Fault(415, "json_required");
  const reader = request.body?.getReader(); if (!reader) throw new Fault(400, "body_required");
  const chunks: Uint8Array[] = []; let size = 0;
  try { while (true) { const part = await reader.read(); if (part.done) break; size += part.value.length;
    if (size > maxBody) { await reader.cancel(); throw new Fault(413, "body_too_large"); } chunks.push(part.value); } }
  finally { reader.releaseLock(); }
  try {
    const result: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (!result || typeof result !== "object" || Array.isArray(result)) throw new Error();
    return result as Record<string, unknown>;
  } catch { throw new Fault(400, "json_invalid"); }
}
export function requestAuth(request: Request): Auth {
  const token = request.headers.get("authorization")?.match(/^Bearer ([A-Za-z0-9_-]+)$/)?.[1];
  const deviceId = request.headers.get("x-harmonia-device-id");
  const accountGeneration = request.headers.get("x-harmonia-account-generation");
  if (!token || !deviceId || !accountGeneration) throw new Fault(401, "unauthorized");
  return { token, deviceId, accountGeneration };
}
function objectMember(value: unknown): void { if (!value || typeof value !== "object" || Array.isArray(value)) throw new Fault(400, "object_required"); }
export async function route(request: Request, service: VaultService): Promise<Response> {
  try {
    const url = new URL(request.url);
    if (url.protocol !== "https:" && !(url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname))) throw new Fault(400, "https_required");
    let result: unknown;
    if (request.method === "GET" && url.pathname === "/health") result = { status: "experimental", trustedEnrollment: false };
    else if (request.method === "POST" && ["/v1/register", "/v1/login"].includes(url.pathname)) {
      const b = await body(request);
      if (typeof b.email !== "string" || typeof b.credential !== "string") throw new Fault(400, "login_input_invalid");
      result = url.pathname.endsWith("register") ? await service.register(b.email, b.credential) : await service.login(b.email, b.credential);
    } else {
      const account = await accountRoute(request, service.accountLifecycle());
      if (account.handled) return Response.json(account.result, { headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" } });
      const enrollment = await enrollmentRoute(request, service);
      if (enrollment.handled) return Response.json(enrollment.result, { headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" } });
      const environment = await environmentRoute(request, service.store);
      if (environment.handled) return Response.json(environment.result, { headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" } });
      const lifecycle = await lifecycleRoute(request, service.store);
      if (lifecycle.handled) return Response.json(lifecycle.result, { headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" } });
      const match = url.pathname.match(/^\/v1\/accounts\/([A-Za-z0-9._:-]+)\/(pull|mutations|mutation-status|grants|device-challenges|device-sessions|notification-tickets)$/);
      if (!match) throw new Fault(404, "not_found");
      const accountId = match[1]!; const operation = match[2]!; const credentials = requestAuth(request);
      if (request.method === "POST" && operation === "notification-tickets") {
        if (url.search) throw new Fault(400, "query_forbidden");
        const b = await body(request); if (Object.keys(b).length) throw new Fault(400, "fields_invalid");
        result = await new NotificationAuthority(service.store).issue(accountId, credentials);
      } else if (request.method === "GET" && operation === "mutation-status") {
        if (Array.from(url.searchParams.keys()).join("|") !== "idempotencyKey") throw new Fault(400, "query_invalid");
        result = await service.mutationStatus(accountId, credentials, url.searchParams.get("idempotencyKey")!);
      } else if (request.method === "POST" && operation === "device-challenges") {
        await body(request); result = await service.deviceChallenge(accountId, credentials);
      } else if (request.method === "POST" && operation === "device-sessions") {
        const b = await body(request);
        if (typeof b.challengeId !== "string" || typeof b.signature !== "string") throw new Fault(400, "challenge_input_invalid");
        result = await service.deviceSession(accountId, credentials, b.challengeId, b.signature);
      } else if (request.method === "GET" && operation === "pull") {
        const after = url.searchParams.get("after");
        if (after === null || !/^(0|[1-9][0-9]*)$/.test(after)) throw new Fault(400, "checkpoint_invalid");
        const scope = url.searchParams.get("scope");
        if (scope !== null && (scope !== "authorizations" || url.searchParams.getAll("scope").length !== 1)) throw new Fault(400, "scope_invalid");
        result = await service.pull(accountId, credentials, Number(after), scope ?? undefined);
      } else if (request.method === "POST" && operation === "mutations") {
        const b = await body(request); objectMember(b.mutation);
        if (Object.keys(b).sort().join("|") !== "mutation|signature") throw new Fault(400, "fields_invalid");
        if (typeof b.signature !== "string") throw new Fault(400, "signature_required");
        result = await service.mutate(accountId, credentials, b as unknown as SignedMutation);
      } else if (request.method === "POST" && operation === "grants") {
        const b = await body(request); objectMember(b.grant);
        if (Object.keys(b).sort().join("|") !== "grant|signature") throw new Fault(400, "fields_invalid");
        if (typeof b.signature !== "string") throw new Fault(400, "signature_required");
        result = await service.changeGrant(accountId, credentials, b as unknown as SignedGrant);
      } else throw new Fault(405, "method_not_allowed");
    }
    return Response.json(result, { headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" } });
  } catch (error) {
    const fault = error instanceof Fault ? error : new Fault(500, "internal_error");
    // No request, token, password-equivalent credential or ciphertext is logged.
    return Response.json({ error: fault.code }, { status: fault.status, headers: { "cache-control": "no-store" } });
  }
}
