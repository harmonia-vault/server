import { sha256 } from "@noble/hashes/sha2.js";
import { Fault } from "./model.js";
import { bytes, generation, identifier, verify } from "./protocol.js";
export interface TrustRoot {
  rootDeviceId: string; rootSigningPublicKey: string; rootReceivingPublicKey: string;
  recoveryGeneration: string; recoverySigningPublicKey: string; recoveryReceivingPublicKey: string; signature: string;
}
export function trustRootPayload(accountId: string, accountGeneration: string, root: TrustRoot): string[] {
  identifier(accountId); generation(accountGeneration); identifier(root.rootDeviceId); generation(root.recoveryGeneration);
  for (const key of [root.rootSigningPublicKey, root.rootReceivingPublicKey, root.recoverySigningPublicKey, root.recoveryReceivingPublicKey]) bytes(key, 32);
  if (root.rootSigningPublicKey === root.rootReceivingPublicKey || root.recoverySigningPublicKey === root.recoveryReceivingPublicKey || root.rootSigningPublicKey === root.recoverySigningPublicKey) throw new Fault(400, "key_purpose_invalid");
  return ["harmonia/trust-root/v1", accountId, accountGeneration, root.rootDeviceId, root.rootSigningPublicKey, root.rootReceivingPublicKey,
    root.recoveryGeneration, root.recoverySigningPublicKey, root.recoveryReceivingPublicKey];
}
export function validateTrustRoot(accountId: string, accountGeneration: string, root: TrustRoot): void {
  if (!root || Object.keys(root).sort().join("|") !== "recoveryGeneration|recoveryReceivingPublicKey|recoverySigningPublicKey|rootDeviceId|rootReceivingPublicKey|rootSigningPublicKey|signature") throw new Fault(400, "trust_root_fields_invalid");
  const fields = trustRootPayload(accountId, accountGeneration, root);
  verify(root.recoverySigningPublicKey, new TextEncoder().encode(JSON.stringify(fields)), root.signature);
}
export function trustRootHash(accountId: string, accountGeneration: string, root: TrustRoot): string {
  validateTrustRoot(accountId, accountGeneration, root);
  return Buffer.from(sha256(new TextEncoder().encode(JSON.stringify([...trustRootPayload(accountId, accountGeneration, root), root.signature])))).toString("hex");
}
