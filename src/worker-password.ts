import { argon2idAsync } from "@noble/hashes/argon2.js";
import { ARGON2, credential, type PasswordHasher } from "./password.js";
import { Fault } from "./model.js";
const base64 = (value: Uint8Array): string => Buffer.from(value).toString("base64").replace(/=+$/g, "");
// 资源准入计数不保存请求或账号数据：每 isolate 只允许一次 64 MiB 派生。
let deriving = false;
async function derive(value: string, salt: Uint8Array): Promise<Uint8Array> {
  const password = credential(value);
  if (deriving) throw new Fault(429, "password_capacity_reached");
  deriving = true;
  try { return await argon2idAsync(password, salt, { t: ARGON2.iterations, m: ARGON2.memorySize, p: ARGON2.parallelism, dkLen: ARGON2.hashLength }); }
  finally { deriving = false; }
}
// Pure-JS mature implementation avoids Workers' runtime WebAssembly compilation restriction.
// Parameters are identical to Node. Production CPU/memory quotas still require measurement.
export const workerPassword: PasswordHasher = {
  async hash(value: string): Promise<string> {
    const salt = crypto.getRandomValues(new Uint8Array(16)); const hash = await derive(value, salt);
    return `$argon2id$v=19$m=65536,t=3,p=1$${base64(salt)}$${base64(hash)}`;
  },
  async verify(value: string, verifier: string): Promise<boolean> {
    const match = verifier.match(/^\$argon2id\$v=19\$m=65536,t=3,p=1\$([A-Za-z0-9+/]{22})\$([A-Za-z0-9+/]{43})$/);
    if (!match) throw new Fault(503, "password_parameters_invalid");
    const salt = Buffer.from(match[1]!, "base64"); const expected = Buffer.from(match[2]!, "base64");
    if (base64(salt) !== match[1] || base64(expected) !== match[2]) throw new Fault(503, "password_parameters_invalid");
    const actual = await derive(value, salt);
    let mismatch = actual.length ^ expected.length;
    for (let i = 0; i < actual.length; i++) mismatch |= actual[i]! ^ expected[i]!;
    return mismatch === 0;
  },
};
