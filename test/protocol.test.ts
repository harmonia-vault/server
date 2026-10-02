import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { mutationBytes, grantBytes, verify } from "../src/protocol.js";
import type { Mutation, Grant } from "../src/model.js";
import { tokenHash } from "../src/service.js";
interface Vectors { grant: Grant & { signature: string }; mutation: Mutation & { signature: string }; grantSigningHex: string; mutationSigningHex: string; signingPublicKey: string }
const vectors = JSON.parse(readFileSync(new URL("./vectors/signatures-v1.json", import.meta.url), "utf8")) as Vectors;
test("server validates Go-generated mutation and management signatures using identical deterministic bytes", () => {
  const { signature: ms, ...m } = vectors.mutation;
  const { signature: gs, ...g } = vectors.grant;
  assert.equal(Buffer.from(mutationBytes(m)).toString("hex"), vectors.mutationSigningHex);
  assert.equal(Buffer.from(grantBytes(g)).toString("hex"), vectors.grantSigningHex);
  verify(vectors.signingPublicKey, mutationBytes(m), ms);
  verify(vectors.signingPublicKey, grantBytes(g), gs);
  assert.throws(() => verify(vectors.signingPublicKey, mutationBytes({ ...m, accountGeneration: "2" }), ms));
});
test("server accepts full protocol packet limit and rejects malformed encodings and extra signed fields", () => {
  const { signature: _, ...m } = vectors.mutation;
  assert.doesNotThrow(() => mutationBytes({ ...m, payload: Buffer.alloc(65576).toString("base64url") }));
  assert.throws(() => mutationBytes({ ...m, payload: Buffer.alloc(65577).toString("base64url") }));
  assert.throws(() => mutationBytes({ ...m, payload: m.payload + "=" }));
  assert.throws(() => mutationBytes({ ...m, accountGeneration: "01" }));
  assert.throws(() => mutationBytes({ ...m, accountGeneration: "18446744073709551616" }));
  assert.throws(() => mutationBytes({ ...m, extraPlaintext: "synthetic-unexpected-field" } as Mutation));
});
test("device session proof uses fixed purpose and UTF8 login-token hash agreed with Go", async () => {
  const v = JSON.parse(readFileSync(new URL("./vectors/device-session-v1.json", import.meta.url), "utf8")) as {
    proof: { accountId: string; accountGeneration: string; deviceId: string; loginTokenHash: string; challengeId: string; nonce: string; expiresAt: string };
    syntheticLoginToken: string; signature: string; signingPublicKey: string; signingHex: string;
  };
  const p = v.proof;
  assert.equal(await tokenHash(v.syntheticLoginToken), p.loginTokenHash);
  const message = new TextEncoder().encode(JSON.stringify(["harmonia/device-session/v1", p.accountId, p.accountGeneration, p.deviceId, p.loginTokenHash, p.challengeId, p.nonce, p.expiresAt]));
  assert.equal(Buffer.from(message).toString("hex"), v.signingHex);
  verify(v.signingPublicKey, message, v.signature);
});
