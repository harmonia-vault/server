import { tokenHash } from "./service.js";

export const emailCodeLifetime = 15 * 60;
export const emailCodeAttempts = 5;
export interface EmailCodeState { salt: string; failedAttempts: number; expiresAt: number }

const alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
export function normalizeEmailCode(value: unknown): string | undefined {
  // Check ASCII before case folding: Unicode expansions must not become valid codes.
  if (typeof value !== "string" || value.length !== 8 || !/^[2-9A-HJ-NP-Za-hj-np-z]{8}$/.test(value)) return undefined;
  const code = value.toUpperCase();
  return /[2-9]/.test(code) && /[A-Z]/.test(code) ? code : undefined;
}

export function randomEmailCode(): string {
  const values = new Uint8Array(8);
  let code: string;
  // 256 is divisible by the 32-character alphabet; reject unmixed whole codes.
  do {
    crypto.getRandomValues(values);
    code = Array.from(values, value => alphabet[value & 31]).join("");
  } while (!normalizeEmailCode(code));
  return code;
}

// The random, server-only salt keeps the internal bearer proof unguessable.
// Neither the short code nor the derived bearer token is persisted.
export async function emailCodeToken(salt: string, code: string): Promise<string> {
  const hash = await tokenHash(JSON.stringify(["harmonia/email-code/v2", salt, code]));
  return Buffer.from(hash, "hex").toString("base64url");
}
