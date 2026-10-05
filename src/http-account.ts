import { Fault } from "./model.js";
import { body } from "./http.js";
import { AccountLifecycle, type ProofInput, type ResetInput, type VerificationInput } from "./account-lifecycle.js";
function fields(value: Record<string, unknown>, expected: string[]): void {
  if (Object.keys(value).sort().join("|") !== expected.sort().join("|")) throw new Fault(400, "fields_invalid");
  for (const v of Object.values(value)) if (typeof v !== "string") throw new Fault(400, "string_required");
}
export async function accountRoute(request: Request, lifecycle: AccountLifecycle, clientIP: string): Promise<{ handled: boolean; result?: unknown }> {
  const path = new URL(request.url).pathname;
  if (path === "/v1/account-reset/resolve") {
    if (request.method !== "POST") throw new Fault(405, "method_not_allowed");
    const b = await body(request); fields(b, ["email", "code"]);
    return { handled: true, result: await lifecycle.resolveCode(b.email as string, b.code as string) };
  }
  if (["/v1/email-verification/request", "/v1/account-reset/request"].includes(path)) {
    if (request.method !== "POST") throw new Fault(405, "method_not_allowed");
    const b = await body(request); fields(b, ["email"]);
    return { handled: true, result: await lifecycle.requestProof(b.email as string, path.includes("account-reset") ? "reset" : "verification", clientIP) };
  }
  const m = path.match(/^\/v1\/accounts\/([A-Za-z0-9._:-]+)\/(email-verification|account-reset)\/(complete|status)$/);
  if (!m) return { handled: false };
  if (request.method !== "POST" || (m[2] === "email-verification" && m[3] !== "complete")) throw new Fault(405, "method_not_allowed");
  const b = await body(request);
  if (m[2] === "email-verification") {
    fields(b, ["accountGeneration", "code"]);
    return { handled: true, result: await lifecycle.verifyEmail(m[1]!, b as unknown as VerificationInput) };
  }
  fields(b, m[3] === "complete" ? ["accountGeneration", "challengeId", "token", "newCredential", "confirmation"] : ["accountGeneration", "challengeId", "token"]);
  const result = m[3] === "status" ? await lifecycle.resetStatus(m[1]!, b as unknown as ProofInput) : await lifecycle.reset(m[1]!, b as unknown as ResetInput);
  return { handled: true, result };
}
