import { argon2id, argon2Verify } from "hash-wasm";
import { Fault } from "./model.js";
export const ARGON2 = Object.freeze({ memorySize: 65536, iterations: 3, parallelism: 1, hashLength: 32 });
export function credential(value: string): Uint8Array {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) throw new Fault(400, "credential_invalid");
  return Buffer.from(value, "hex");
}
export async function hashCredential(value: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return argon2id({ password: credential(value), salt, ...ARGON2, outputType: "encoded" });
}
export async function verifyCredential(value: string, verifier: string): Promise<boolean> {
  return argon2Verify({ password: credential(value), hash: verifier });
}

export interface PasswordHasher { hash(value: string): Promise<string>; verify(value: string, verifier: string): Promise<boolean> }
export const wasmPassword: PasswordHasher = { hash: hashCredential, verify: verifyCredential };

// 仅未知账号等成本验证的公开合成值；真实账号仍独立随机盐。
export const DUMMY_VERIFIER = "$argon2id$v=19$m=65536,t=3,p=1$U1NTU1NTU1NTU1NTU1NTUw$/boP/ZGPFKRT9+2nP3GdOynnKAkRhTQI85HFc/VXfbg";
