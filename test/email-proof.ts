import assert from "node:assert/strict";
import type { AccountLifecycle, ProofInput, VerificationInput } from "../src/account-lifecycle.js";
import type { Email } from "../src/email-transport.js";

export type ResolvedEmailProof = ProofInput & { accountId: string };
export function mailCode(mail: Email): string {
  assert.equal(mail.text.includes('{'), false, 'mail must not contain a JSON credential');
  const match = mail.text.match(/^验证码：([2-9A-HJ-NP-Z]{8})$/m);
  assert.ok(match, 'mail must contain eight unambiguous letters and digits');
  return match[1]!;
}
export type EmailVerification = VerificationInput & { accountId: string };
export function verificationCode(mail: Email, accountId: string, accountGeneration = "1"): EmailVerification {
  return { accountId, accountGeneration, code: mailCode(mail) };
}
export function emailVerification(lifecycle: AccountLifecycle, mail: Email): EmailVerification {
  const id = lifecycle.store.byEmail(mail.to)!;
  return verificationCode(mail, id, lifecycle.store.read(id)!.generation);
}
export function resetProof(lifecycle: AccountLifecycle, mail: Email): Promise<ResolvedEmailProof> {
  return lifecycle.resolveCode(mail.to, mailCode(mail));
}
export async function httpResetProof(post: (path: string, body: unknown) => Promise<{ status: number; json(): Promise<unknown> }>, mail: Email): Promise<ResolvedEmailProof> {
  const response = await post('/v1/account-reset/resolve', { email: mail.to, code: mailCode(mail) });
  assert.equal(response.status, 200);
  return await response.json() as ResolvedEmailProof;
}

// Account-flow tests honor the production mail cooldown; limit tests exercise 429 directly.
export async function afterEmailCooldown<T extends { status: number; clone(): { json(): Promise<unknown> } }>(send: () => Promise<T>): Promise<T> {
  const response = await send();
  if (response.status !== 429) return response;
  const fault = await response.clone().json() as { error?: string; retryAfterSeconds?: number };
  if (fault.error !== 'email_request_limited' || !fault.retryAfterSeconds || fault.retryAfterSeconds > 30) return response;
  await new Promise(resolve => setTimeout(resolve, (fault.retryAfterSeconds! + 1) * 1000));
  return send();
}
